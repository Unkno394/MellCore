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

#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CenterEventInput {
    pub agent_id: Uuid,
    pub event: IncomingEvent,
}

#[derive(Default, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct EventQuery {
    pub after: Option<Uuid>,
    pub limit: Option<u32>,
    pub q: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AttackEventPage {
    pub items: Vec<AttackEvent>,
    pub next_cursor: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct AttackGraphMatch {
    pub scenario_id: Uuid,
    pub trap_id: Uuid,
    pub session_key: String,
    pub evidence_domain: String,
    pub technique_key: String,
    pub technique_name: String,
    pub status: String,
    pub similarity: f32,
    pub coverage: f32,
    pub evidence_event_ids: Vec<Uuid>,
    pub matched_event_ids: Vec<Uuid>,
    pub nodes: Vec<AttackGraphNode>,
    pub edges: Vec<AttackGraphEdge>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct AttackGraphNode {
    pub node_id: Uuid,
    pub node_key: String,
    pub action_kind: String,
    pub process_class: String,
    pub resource_class: String,
    pub status: String,
    pub matched_event_ids: Vec<Uuid>,
    pub observed_outcome: Option<String>,
    pub expected_outcome: String,
}

#[derive(Serialize, ToSchema)]
pub struct AttackGraphEdge {
    pub from_node: Uuid,
    pub to_node: Uuid,
    pub status: String,
    pub matched_event_ids: Vec<Uuid>,
    pub observed_outcome: Option<String>,
    pub expected_outcome: String,
    pub time_delta_ms: Option<i64>,
}

#[derive(Clone, Deserialize)]
struct NodeEvidence {
    event_id: Uuid,
    observed_outcome: String,
    occurred_at: chrono::DateTime<Utc>,
    from_node: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct BaitEngagement {
    pub bait_id: Uuid,
    pub opens: i64,
    pub sessions: i64,
    pub last_opened_at: chrono::DateTime<Utc>,
}

#[derive(FromRow)]
struct BaitEngagementRow {
    bait_id: String,
    opens: i64,
    sessions: i64,
    last_opened_at: chrono::DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct AttackGraphProposal {
    pub proposal_id: Uuid,
    pub action_kind: String,
    pub process_class: String,
    pub resource_class: String,
    pub outcome: String,
    pub sample_event_id: Option<Uuid>,
    pub evidence_count: i64,
    pub suggested_technique: Option<Uuid>,
    pub first_seen: chrono::DateTime<Utc>,
    pub last_seen: chrono::DateTime<Utc>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewGraphProposal {
    pub decision: String,
    pub technique_id: Option<Uuid>,
    pub predecessor_node_id: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct ReviewGraphResult {
    pub proposal_id: Uuid,
    pub status: String,
    pub node_id: Option<Uuid>,
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
    principal.require("telemetry.view")?;
    let limit = match query.limit.unwrap_or(50) {
        value @ 1..=100 => value as usize,
        _ => return Err(AppError::invalid("Limit must be between 1 and 100")),
    };
    let search = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if search.is_some_and(|value| value.chars().count() > 200) {
        return Err(AppError::invalid(
            "Search query must be at most 200 characters",
        ));
    }
    let pool = state.pool()?;
    crate::resources::traps::get(pool, &principal, trap_id).await?;
    let stored: Vec<StoredAttackEvent> = sqlx::query_as(
        "SELECT ae.agent_id,ae.server_id,ae.event_id,ae.trap_id,ae.session_id,ae.sequence_no,ae.event_type,ae.occurred_at,ae.received_at,ae.expires_at,ae.source_ip,ae.source_port,ae.destination_port,ae.protocol,ae.service_type,ae.payload,ae.metadata FROM attack_events ae WHERE ae.trap_id=$1 AND ($2::uuid IS NULL OR (ae.occurred_at,ae.event_id) < (SELECT cursor.occurred_at,cursor.event_id FROM attack_events cursor WHERE cursor.trap_id=$1 AND cursor.event_id=$2)) AND ($3::text IS NULL OR strpos(lower(concat_ws(' ',ae.event_type,ae.service_type,ae.protocol,ae.source_ip,ae.payload::text,ae.metadata::text)),lower($3))>0) ORDER BY ae.occurred_at DESC,ae.event_id DESC LIMIT $4",
    )
    .bind(trap_id)
    .bind(query.after)
    .bind(search)
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

#[utoipa::path(get,path="/api/v1/traps/{trap_id}/events/{event_id}",tag="telemetry",security(("bearer"=[])),params(("trap_id"=Uuid,Path),("event_id"=Uuid,Path)),responses((status=200,body=AttackEvent),(status=404,body=crate::errors::ErrorResponse)))]
pub async fn get_event(
    State(state): State<AppState>,
    principal: Principal,
    Path((trap_id, event_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<AttackEvent>, AppError> {
    let pool = state.pool()?;
    crate::resources::traps::get(pool, &principal, trap_id).await?;
    let stored: StoredAttackEvent = sqlx::query_as("SELECT agent_id,server_id,event_id,trap_id,session_id,sequence_no,event_type,occurred_at,received_at,expires_at,source_ip,source_port,destination_port,protocol,service_type,payload,metadata FROM attack_events WHERE trap_id=$1 AND event_id=$2")
        .bind(trap_id).bind(event_id).fetch_optional(pool).await?.ok_or_else(AppError::not_found)?;
    Ok(Json(AttackEvent::try_from(stored)?))
}

#[utoipa::path(get,path="/api/v1/traps/{trap_id}/bait-engagement",tag="telemetry",security(("bearer"=[])),params(("trap_id"=Uuid,Path)),responses((status=200,body=[BaitEngagement]),(status=401,body=crate::errors::ErrorResponse),(status=404,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn list_bait_engagement(
    State(state): State<AppState>,
    principal: Principal,
    Path(trap_id): Path<Uuid>,
) -> Result<Json<Vec<BaitEngagement>>, AppError> {
    let pool = state.pool()?;
    let trap = crate::resources::traps::get(pool, &principal, trap_id).await?;
    if trap.profile_snapshot.honeypot_type != "pritvoryashka" {
        return Err(AppError::not_found());
    }
    let rows: Vec<BaitEngagementRow> = sqlx::query_as(
        "SELECT naa.environment->>'bait_id' AS bait_id, COUNT(*)::bigint AS opens, COUNT(DISTINCT naa.session_key)::bigint AS sessions, MAX(ae.occurred_at) AS last_opened_at FROM normalized_attack_actions naa JOIN attack_events ae ON ae.event_id=naa.event_id WHERE naa.trap_id=$1 AND naa.action_kind='deception.bait_open' AND naa.environment->>'bait_id' IS NOT NULL GROUP BY naa.environment->>'bait_id'",
    )
    .bind(trap_id)
    .fetch_all(pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .filter_map(|row| {
                Uuid::parse_str(&row.bait_id)
                    .ok()
                    .map(|bait_id| BaitEngagement {
                        bait_id,
                        opens: row.opens,
                        sessions: row.sessions,
                        last_opened_at: row.last_opened_at,
                    })
            })
            .collect(),
    ))
}

#[utoipa::path(get,path="/api/v1/traps/{trap_id}/attack-matches",tag="telemetry",security(("bearer"=[])),params(("trap_id"=Uuid,Path)),responses((status=200,body=[AttackGraphMatch]),(status=401,body=crate::errors::ErrorResponse),(status=404,description="Trap missing or owned by another user",body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn list_attack_matches(
    State(state): State<AppState>,
    principal: Principal,
    Path(trap_id): Path<Uuid>,
) -> Result<Json<Vec<AttackGraphMatch>>, AppError> {
    principal.require("attacks.analyze")?;
    let pool = state.pool()?;
    crate::resources::traps::get(pool, &principal, trap_id).await?;
    let rows = sqlx::query("SELECT gp.agent_id,gp.technique_id,gp.session_key,split_part(gp.session_key,':',1) AS evidence_domain,t.technique_key,t.name,gp.status,gp.similarity,gp.active_nodes,gp.evidence_event_ids,gp.node_evidence,gp.last_occurred_at,gp.updated_at FROM attack_graph_progress gp JOIN attack_techniques t USING(technique_id) WHERE gp.trap_id=$1 ORDER BY gp.updated_at DESC LIMIT 100")
        .bind(trap_id).fetch_all(pool).await?;
    use sqlx::Row;
    let technique_ids: Vec<Uuid> = rows.iter().map(|row| row.get("technique_id")).collect();
    let graph_nodes = sqlx::query("SELECT node_id,technique_id,node_key,action_kind,process_class,resource_class,expected_outcome FROM attack_graph_nodes WHERE technique_id=ANY($1) ORDER BY technique_id,node_key")
        .bind(&technique_ids).fetch_all(pool).await?;
    let graph_edges = sqlx::query("SELECT technique_id,from_node,to_node FROM attack_graph_edges WHERE technique_id=ANY($1) ORDER BY technique_id,from_node,to_node")
        .bind(&technique_ids).fetch_all(pool).await?;
    let mut matches = Vec::with_capacity(rows.len());
    for row in rows {
        let scenario_id: Uuid = row.get("technique_id");
        let active: Vec<Uuid> = row.get("active_nodes");
        let raw_evidence: serde_json::Value = row.get("node_evidence");
        let evidence: std::collections::HashMap<Uuid, NodeEvidence> = raw_evidence
            .as_object()
            .into_iter()
            .flat_map(|object| object.iter())
            .filter_map(|(id, value)| {
                Some((
                    Uuid::parse_str(id).ok()?,
                    serde_json::from_value(value.clone()).ok()?,
                ))
            })
            .collect();
        let observations = if graph_nodes.iter().any(|n| {
            n.get::<Uuid, _>("technique_id") == scenario_id
                && !active.contains(&n.get::<Uuid, _>("node_id"))
        }) {
            sqlx::query("SELECT naa.event_id,naa.action_kind,naa.process_class,naa.resource_class,naa.outcome FROM normalized_attack_actions naa JOIN attack_events ae USING(event_id) WHERE naa.agent_id=$1 AND naa.trap_id=$2 AND naa.session_key=$3 AND ae.occurred_at BETWEEN $4::timestamptz - interval '30 minutes' AND $4::timestamptz ORDER BY ae.occurred_at DESC LIMIT 500")
                .bind(row.get::<Uuid, _>("agent_id")).bind(trap_id).bind(row.get::<String, _>("session_key"))
                .bind(row.get::<Option<chrono::DateTime<Utc>>, _>("last_occurred_at"))
                .fetch_all(pool).await?
        } else {
            vec![]
        };
        let mut nodes: Vec<AttackGraphNode> = graph_nodes
            .iter()
            .filter(|n| n.get::<Uuid, _>("technique_id") == scenario_id)
            .map(|n| {
                let node_id: Uuid = n.get("node_id");
                let proof = evidence.get(&node_id);
                let expected_outcome: String = n.get("expected_outcome");
                let action_kind: String = n.get("action_kind");
                let process_class: String = n.get("process_class");
                let resource_class: String = n.get("resource_class");
                let observation = if proof.is_none() && !active.contains(&node_id) {
                    observations.iter().find(|a| {
                        a.get::<String, _>("action_kind") == action_kind
                            && (process_class == "*"
                                || a.get::<String, _>("process_class") == process_class)
                            && (resource_class == "*"
                                || a.get::<String, _>("resource_class") == resource_class)
                    })
                } else {
                    None
                };
                let observed_outcome = proof
                    .map(|p| p.observed_outcome.clone())
                    .or_else(|| observation.map(|a| a.get::<String, _>("outcome")));
                let status = if proof.is_some() {
                    "matched"
                } else if active.contains(&node_id) {
                    "legacy_unattributed"
                } else if observation.is_some()
                    && expected_outcome != "*"
                    && observed_outcome.as_deref() != Some(expected_outcome.as_str())
                {
                    "outcome_mismatch"
                } else if observation.is_some() {
                    "observed_unlinked"
                } else {
                    "missing"
                };
                AttackGraphNode {
                    node_id,
                    node_key: n.get("node_key"),
                    action_kind,
                    process_class,
                    resource_class,
                    status: status.into(),
                    matched_event_ids: proof
                        .map(|p| vec![p.event_id])
                        .or_else(|| observation.map(|a| vec![a.get("event_id")]))
                        .unwrap_or_default(),
                    observed_outcome,
                    expected_outcome,
                }
            })
            .collect();
        let edges: Vec<AttackGraphEdge> = graph_edges
            .iter()
            .filter(|e| e.get::<Uuid, _>("technique_id") == scenario_id)
            .map(|e| {
                let from_node: Uuid = e.get("from_node");
                let to_node: Uuid = e.get("to_node");
                let source = evidence.get(&from_node);
                let target = evidence.get(&to_node);
                let traversed = target.is_some_and(|p| p.from_node == Some(from_node));
                AttackGraphEdge {
                    from_node,
                    to_node,
                    status: if traversed {
                        "matched"
                    } else if active.contains(&from_node)
                        && active.contains(&to_node)
                        && (source.is_none() || target.is_none())
                    {
                        "legacy_unattributed"
                    } else {
                        "missing"
                    }
                    .into(),
                    matched_event_ids: if traversed {
                        target.map(|p| vec![p.event_id]).unwrap_or_default()
                    } else {
                        vec![]
                    },
                    observed_outcome: if traversed {
                        target.map(|p| p.observed_outcome.clone())
                    } else {
                        None
                    },
                    expected_outcome: nodes
                        .iter()
                        .find(|n| n.node_id == to_node)
                        .map(|n| n.expected_outcome.clone())
                        .unwrap_or_default(),
                    time_delta_ms: if traversed {
                        source.zip(target).map(|(a, b)| {
                            b.occurred_at
                                .signed_duration_since(a.occurred_at)
                                .num_milliseconds()
                        })
                    } else {
                        None
                    },
                }
            })
            .collect();
        let mut ordered = Vec::with_capacity(nodes.len());
        while !nodes.is_empty() {
            let next = nodes
                .iter()
                .position(|node| {
                    !edges.iter().any(|edge| {
                        edge.to_node == node.node_id
                            && nodes
                                .iter()
                                .any(|remaining| remaining.node_id == edge.from_node)
                    })
                })
                .unwrap_or(0);
            ordered.push(nodes.remove(next));
        }
        let nodes = ordered;
        let similarity: f32 = row.get("similarity");
        let evidence_event_ids: Vec<Uuid> = row.get("evidence_event_ids");
        matches.push(AttackGraphMatch {
            scenario_id,
            trap_id,
            session_key: row.get("session_key"),
            evidence_domain: row.get("evidence_domain"),
            technique_key: row.get("technique_key"),
            technique_name: row.get("name"),
            status: row.get("status"),
            similarity,
            coverage: similarity,
            matched_event_ids: evidence_event_ids.clone(),
            evidence_event_ids,
            nodes,
            edges,
            updated_at: row.get("updated_at"),
        });
    }
    Ok(Json(matches))
}

#[utoipa::path(get,path="/api/v1/knowledge/proposals",tag="telemetry",security(("bearer"=[])),responses((status=200,body=[AttackGraphProposal]),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn list_graph_proposals(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Json<Vec<AttackGraphProposal>>, AppError> {
    principal.require("graph.view")?;
    let rows = sqlx::query("SELECT proposal_id,action_kind,process_class,resource_class,outcome,sample_event_id,evidence_count,suggested_technique,first_seen,last_seen FROM attack_graph_proposals WHERE status='pending' ORDER BY evidence_count DESC,last_seen DESC LIMIT 100")
        .fetch_all(state.pool()?).await?;
    use sqlx::Row;
    let proposals = rows
        .into_iter()
        .map(|row| AttackGraphProposal {
            proposal_id: row.get("proposal_id"),
            action_kind: row.get("action_kind"),
            process_class: row.get("process_class"),
            resource_class: row.get("resource_class"),
            outcome: row.get("outcome"),
            sample_event_id: row.get("sample_event_id"),
            evidence_count: row.get("evidence_count"),
            suggested_technique: row.get("suggested_technique"),
            first_seen: row.get("first_seen"),
            last_seen: row.get("last_seen"),
        })
        .collect();
    Ok(Json(proposals))
}

/// Human approval is required before a novel action becomes graph knowledge.
/// The accepted node is always attempt-level; a review never grants authority
/// to declare a host escape without independent validated observer evidence.
#[utoipa::path(post,path="/api/v1/knowledge/proposals/{proposal_id}/review",tag="telemetry",security(("bearer"=[])),params(("proposal_id"=Uuid,Path)),request_body=ReviewGraphProposal,responses((status=200,body=ReviewGraphResult),(status=403,body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse)))]
pub async fn review_graph_proposal(
    State(state): State<AppState>,
    principal: Principal,
    Path(proposal_id): Path<Uuid>,
    Json(input): Json<ReviewGraphProposal>,
) -> Result<Json<ReviewGraphResult>, AppError> {
    principal.require("graph.manage")?;
    if !matches!(input.decision.as_str(), "accept" | "reject") {
        return Err(AppError::invalid("Decision must be accept or reject"));
    }
    if input.decision == "reject"
        && (input.technique_id.is_some() || input.predecessor_node_id.is_some())
    {
        return Err(AppError::invalid(
            "Rejected proposals cannot create graph nodes",
        ));
    }
    let mut tx = state.pool()?.begin().await?;
    use sqlx::Row;
    let row = sqlx::query("SELECT status,action_kind,process_class,resource_class,outcome,suggested_technique FROM attack_graph_proposals WHERE proposal_id=$1 FOR UPDATE")
        .bind(proposal_id).fetch_optional(&mut *tx).await?.ok_or_else(AppError::not_found)?;
    if row.get::<String, _>("status") != "pending" {
        return Err(AppError::conflict("Proposal was already reviewed"));
    }
    let mut node_id = None;
    let status = if input.decision == "accept" {
        let technique = input
            .technique_id
            .or(row.get("suggested_technique"))
            .ok_or_else(|| AppError::invalid("Choose an existing technique"))?;
        let known: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attack_techniques WHERE technique_id=$1 AND status='known')")
            .bind(technique).fetch_one(&mut *tx).await?;
        if !known {
            return Err(AppError::invalid("Technique is unknown or pending review"));
        }
        if let Some(predecessor) = input.predecessor_node_id {
            let belongs: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM attack_graph_nodes WHERE node_id=$1 AND technique_id=$2)")
                .bind(predecessor).bind(technique).fetch_one(&mut *tx).await?;
            if !belongs {
                return Err(AppError::invalid(
                    "Predecessor does not belong to technique",
                ));
            }
        }
        let id = Uuid::new_v4();
        let node_key = format!("variant.{}", id.simple());
        sqlx::query("INSERT INTO attack_graph_nodes(node_id,technique_id,node_key,action_kind,process_class,resource_class,expected_outcome,evidence_level) VALUES($1,$2,$3,$4,$5,$6,$7,'attempt')")
            .bind(id).bind(technique).bind(node_key)
            .bind(row.get::<String, _>("action_kind"))
            .bind(row.get::<String, _>("process_class"))
            .bind(row.get::<String, _>("resource_class"))
            .bind(row.get::<String, _>("outcome"))
            .execute(&mut *tx).await?;
        if let Some(predecessor) = input.predecessor_node_id {
            sqlx::query(
                "INSERT INTO attack_graph_edges(technique_id,from_node,to_node) VALUES($1,$2,$3)",
            )
            .bind(technique)
            .bind(predecessor)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        node_id = Some(id);
        "accepted"
    } else {
        "rejected"
    };
    sqlx::query("UPDATE attack_graph_proposals SET status=$2,reviewed_by=$3,reviewed_at=now(),accepted_node_id=$4 WHERE proposal_id=$1")
        .bind(proposal_id).bind(status).bind(principal.user.id).bind(node_id)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(ReviewGraphResult {
        proposal_id,
        status: status.to_owned(),
        node_id,
    }))
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
    persist_batch(state, batch, false).await
}

async fn persist_batch(
    state: AppState,
    mut batch: TelemetryBatch,
    trusted_center: bool,
) -> Result<(StatusCode, Json<IngestResponse>), AppError> {
    batch
        .validate(&state.config.telemetry, Utc::now())
        .map_err(validation_error)?;
    let pool = state.pool()?;
    let body = serde_json::to_vec(&batch).map_err(|_| AppError::invalid("Invalid telemetry"))?;
    let batch_hash = Sha256::digest(body).to_vec();
    let mut tx = pool.begin().await?;
    // A per-agent transaction lock serializes progress, including its first INSERT.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(batch.agent_id.to_string())
        .execute(&mut *tx)
        .await?;

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

    batch
        .events
        .sort_by_key(|event| (event.occurred_at, event.sequence_no));
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
            // Middle may send the same event directly before Center mirrors it.
            // The trusted, agent-bound Center delivery must still index the graph.
            if trusted_center {
                crate::attack_graph::observe(&mut tx, batch.agent_id, batch.server_id, event, true)
                    .await?;
            }
            duplicate_events += 1;
            continue;
        }
        insert_event(&mut tx, &batch, event, &hash, received_at, expires_at).await?;
        crate::attack_graph::observe(
            &mut tx,
            batch.agent_id,
            batch.server_id,
            event,
            trusted_center,
        )
        .await?;
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

/// Center-to-PostgreSQL mirror. The trusted center supplies agent identity and
/// event; the backend resolves server ownership from the registered trap.
#[utoipa::path(post,path="/internal/v1/center/events",tag="telemetry",security(("telemetry_bearer"=[])),request_body=CenterEventInput,responses((status=202,body=IngestResponse),(status=401,body=crate::errors::ErrorResponse),(status=404,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse)))]
pub async fn ingest_from_center(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CenterEventInput>,
) -> Result<(StatusCode, Json<IngestResponse>), AppError> {
    authorize_center(&state, &headers)?;
    let pool = state.pool()?;
    let trap_id = input.event.trap_id;
    let server_id: Uuid = sqlx::query_scalar("SELECT t.server_id FROM traps t JOIN center_agent_traps cat ON cat.trap_id=t.trap_id JOIN center_agent_servers cas ON cas.agent_id=cat.agent_id AND cas.server_id=t.server_id WHERE t.trap_id=$1 AND cat.agent_id=$2 AND cat.state <> 'removed'")
        .bind(trap_id).bind(input.agent_id).fetch_optional(pool).await?.ok_or_else(AppError::not_found)?;
    let batch = TelemetryBatch {
        schema_version: SCHEMA_VERSION,
        // Stable across retries, so the existing idempotent batch path applies.
        batch_id: input.event.event_id,
        agent_id: input.agent_id,
        server_id,
        events: vec![input.event],
    };
    let result = persist_batch(state.clone(), batch, true).await?;
    sqlx::query("UPDATE center_agent_traps SET state='running',updated_at=now() WHERE trap_id=$1 AND agent_id=$2 AND state='provisioning'")
        .bind(trap_id).bind(input.agent_id).execute(state.pool()?).await?;
    Ok(result)
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

pub(crate) fn authorize_center(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let expected = state
        .config
        .center_ingest_token
        .as_ref()
        .ok_or_else(AppError::unauthorized)?;
    if !constant_time_eq(
        expected.expose().as_bytes(),
        telemetry_bearer(headers).unwrap_or_default(),
    ) {
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
