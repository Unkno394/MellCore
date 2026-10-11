use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::{
    api::AppState,
    auth::Principal,
    errors::AppError,
    telemetry::{AttackEvent, IncomingEvent, SCHEMA_VERSION, TelemetryBatch, ValidationCode},
};

#[derive(Serialize, ToSchema)]
pub struct IngestResponse {
    pub batch_id: Uuid,
    pub accepted_events: usize,
    pub duplicate_events: usize,
}

#[derive(Default, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct EventQuery {
    pub after: Option<Uuid>,
    pub limit: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct AttackEventPage {
    pub items: Vec<AttackEvent>,
    pub next_cursor: Option<Uuid>,
}

#[derive(FromRow)]
struct StoredAttackEvent {
    agent_id: Uuid,
    server_id: Uuid,
    event_id: Uuid,
    trap_id: Uuid,
    session_id: Option<String>,
    sequence_no: Option<i64>,
    event_type: String,
    occurred_at: chrono::DateTime<Utc>,
    received_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
    source_ip: Option<String>,
    source_port: Option<i32>,
    destination_port: Option<i32>,
    protocol: String,
    service_type: String,
    payload: serde_json::Value,
    metadata: serde_json::Value,
}

#[utoipa::path(get,path="/api/v1/traps/{trap_id}/events",tag="telemetry",security(("bearer"=[])),params(("trap_id"=Uuid,Path),EventQuery),responses((status=200,body=AttackEventPage),(status=401,body=crate::errors::ErrorResponse),(status=404,description="Trap missing or owned by another user",body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn list(
    State(state): State<AppState>,
    principal: Principal,
    Path(trap_id): Path<Uuid>,
    Query(query): Query<EventQuery>,
) -> Result<Json<AttackEventPage>, AppError> {
    let limit = match query.limit.unwrap_or(50) {
        value @ 1..=100 => value as usize,
        _ => return Err(AppError::invalid("Limit must be between 1 and 100")),
    };
    let pool = state.pool()?;
    crate::resources::traps::get(pool, &principal, trap_id).await?;
    let stored: Vec<StoredAttackEvent> = sqlx::query_as(
        "SELECT ae.agent_id,ae.server_id,ae.event_id,ae.trap_id,ae.session_id,ae.sequence_no,ae.event_type,ae.occurred_at,ae.received_at,ae.expires_at,ae.source_ip,ae.source_port,ae.destination_port,ae.protocol,ae.service_type,ae.payload,ae.metadata FROM attack_events ae WHERE ae.trap_id=$1 AND ($2::uuid IS NULL OR ae.event_id>$2) ORDER BY ae.event_id LIMIT $3",
    )
    .bind(trap_id)
    .bind(query.after)
    .bind(i64::try_from(limit + 1).map_err(|_| AppError::internal())?)
    .fetch_all(pool)
    .await?;
    let mut items = stored
        .into_iter()
        .map(AttackEvent::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|event| event.event.event_id)
    } else {
        None
    };
    Ok(Json(AttackEventPage { items, next_cursor }))
}

impl TryFrom<StoredAttackEvent> for AttackEvent {
    type Error = AppError;

    fn try_from(value: StoredAttackEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            agent_id: value.agent_id,
            server_id: value.server_id,
            event: IncomingEvent {
                event_id: value.event_id,
                trap_id: value.trap_id,
                session_id: value.session_id,
                sequence_no: value
                    .sequence_no
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| AppError::internal())?,
                event_type: value.event_type,
                occurred_at: value.occurred_at,
                source_ip: value
                    .source_ip
                    .map(|ip| ip.parse())
                    .transpose()
                    .map_err(|_| AppError::internal())?,
                source_port: value
                    .source_port
                    .map(u16::try_from)
                    .transpose()
                    .map_err(|_| AppError::internal())?,
                destination_port: value
                    .destination_port
                    .map(u16::try_from)
                    .transpose()
                    .map_err(|_| AppError::internal())?,
                protocol: value.protocol,
                service_type: value.service_type,
                payload: value.payload,
                metadata: value.metadata,
            },
            received_at: value.received_at,
            expires_at: value.expires_at,
        })
    }
}

/// Internal agent endpoint. The bearer token is independent from user JWTs.
#[utoipa::path(post,path="/internal/v1/telemetry/batches",tag="telemetry",security(("telemetry_bearer"=[])),request_body=TelemetryBatch,responses((status=202,body=IngestResponse),(status=401,body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(batch): Json<TelemetryBatch>,
) -> Result<(StatusCode, Json<IngestResponse>), AppError> {
    authorize(&state, &headers)?;
    batch
        .validate(&state.config.telemetry, Utc::now())
        .map_err(validation_error)?;
    let pool = state.pool()?;
    let body = serde_json::to_vec(&batch).map_err(|_| AppError::invalid("Invalid telemetry"))?;
    let batch_hash = Sha256::digest(body).to_vec();
    let mut tx = pool.begin().await?;

    if let Some(existing) = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT batch_hash FROM telemetry_batches WHERE batch_id=$1 FOR SHARE",
    )
    .bind(batch.batch_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        if existing != batch_hash {
            return Err(AppError::conflict("Conflicting telemetry batch ID"));
        }
        tx.commit().await?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(IngestResponse {
                batch_id: batch.batch_id,
                accepted_events: 0,
                duplicate_events: batch.events.len(),
            }),
        ));
    }

    let server_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM servers WHERE server_id=$1)")
            .bind(batch.server_id)
            .fetch_one(&mut *tx)
            .await?;
    if !server_exists {
        return Err(AppError::not_found());
    }
    for event in &batch.events {
        let authorized: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM traps WHERE trap_id=$1 AND server_id=$2)",
        )
        .bind(event.trap_id)
        .bind(batch.server_id)
        .fetch_one(&mut *tx)
        .await?;
        if !authorized {
            return Err(AppError::forbidden());
        }
    }

    sqlx::query("INSERT INTO telemetry_batches(batch_id,agent_id,server_id,batch_hash,event_count) VALUES($1,$2,$3,$4,$5)")
        .bind(batch.batch_id)
        .bind(batch.agent_id)
        .bind(batch.server_id)
        .bind(&batch_hash)
        .bind(i32::try_from(batch.events.len()).map_err(|_| AppError::invalid("Too many telemetry events"))?)
        .execute(&mut *tx)
        .await?;

    let mut accepted_events = 0_usize;
    let mut duplicate_events = 0_usize;
    let received_at = Utc::now();
    let expires_at = received_at + Duration::days(state.config.telemetry.retention_days);
    for event in &batch.events {
        let mut hasher = Sha256::new();
        hasher.update(batch.agent_id.as_bytes());
        hasher.update(batch.server_id.as_bytes());
        hasher.update(
            serde_json::to_vec(event).map_err(|_| AppError::invalid("Invalid telemetry event"))?,
        );
        let hash = hasher.finalize().to_vec();
        if let Some(existing) = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT event_hash FROM attack_events WHERE event_id=$1 FOR SHARE",
        )
        .bind(event.event_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            if existing != hash {
                return Err(AppError::conflict("Conflicting telemetry event ID"));
            }
            duplicate_events += 1;
            continue;
        }
        insert_event(&mut tx, &batch, event, &hash, received_at, expires_at).await?;
        accepted_events += 1;
    }
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(IngestResponse {
            batch_id: batch.batch_id,
            accepted_events,
            duplicate_events,
        }),
    ))
}

async fn insert_event(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    batch: &TelemetryBatch,
    event: &IncomingEvent,
    event_hash: &[u8],
    received_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
) -> Result<(), AppError> {
    let sequence_no = event
        .sequence_no
        .map(i64::try_from)
        .transpose()
        .map_err(|_| AppError::invalid("sequence_no exceeds PostgreSQL bigint"))?;
    sqlx::query("INSERT INTO attack_events(event_id,batch_id,agent_id,server_id,trap_id,session_id,sequence_no,event_type,occurred_at,received_at,expires_at,source_ip,source_port,destination_port,protocol,service_type,payload,metadata,event_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)")
        .bind(event.event_id)
        .bind(batch.batch_id)
        .bind(batch.agent_id)
        .bind(batch.server_id)
        .bind(event.trap_id)
        .bind(&event.session_id)
        .bind(sequence_no)
        .bind(&event.event_type)
        .bind(event.occurred_at)
        .bind(received_at)
        .bind(expires_at)
        .bind(event.source_ip.map(|ip| ip.to_string()))
        .bind(event.source_port.map(i32::from))
        .bind(event.destination_port.map(i32::from))
        .bind(&event.protocol)
        .bind(&event.service_type)
        .bind(&event.payload)
        .bind(&event.metadata)
        .bind(event_hash)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let expected = state
        .config
        .telemetry_ingest_token
        .as_ref()
        .ok_or_else(AppError::unauthorized)?
        .expose()
        .as_bytes();
    let supplied = telemetry_bearer(headers).unwrap_or_default();
    if !constant_time_eq(expected, supplied) {
        return Err(AppError::unauthorized());
    }
    Ok(())
}

fn telemetry_bearer(headers: &HeaderMap) -> Option<&[u8]> {
    if headers.get_all(AUTHORIZATION).iter().count() != 1 {
        return None;
    }
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > 4096
        || token.chars().any(char::is_whitespace)
    {
        return None;
    }
    Some(token.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let longest = left.len().max(right.len());
    for index in 0..longest {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn validation_error(error: crate::telemetry::ValidationError) -> AppError {
    match error.code {
        ValidationCode::ConflictingEventId => AppError::conflict("Conflicting event ID in batch"),
        _ => AppError::invalid("Invalid telemetry batch"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn telemetry_bearer_requires_one_well_formed_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("bearer opaque-token"),
        );
        assert_eq!(telemetry_bearer(&headers), Some(&b"opaque-token"[..]));

        headers.append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer second-token"),
        );
        assert_eq!(telemetry_bearer(&headers), None);

        let mut malformed = HeaderMap::new();
        malformed.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer token with spaces"),
        );
        assert_eq!(telemetry_bearer(&malformed), None);
    }
}
