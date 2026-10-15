use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{
    access_admin::{
        self, AcceptInvitation, AuditEntry, AuditQuery, CreateInvitation, InvitationCreated,
        InvitationView,
    },
    api::AppState,
    auth::Principal,
    errors::{AppError, RequestId},
    management::User,
};

#[utoipa::path(post,path="/api/v1/invitations",tag="access",security(("bearer"=[])),request_body=CreateInvitation,responses((status=201,body=InvitationCreated),(status=403,body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse)))]
pub async fn create_invitation(
    State(state): State<AppState>,
    principal: Principal,
    Extension(request): Extension<RequestId>,
    Json(input): Json<CreateInvitation>,
) -> Result<(StatusCode, Json<InvitationCreated>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(
            access_admin::create_invitation(
                state.pool()?,
                &principal,
                request.0,
                input,
                &state.config.app_origin,
            )
            .await?,
        ),
    ))
}

#[utoipa::path(get,path="/api/v1/invitations",tag="access",security(("bearer"=[])),responses((status=200,body=[InvitationView]),(status=403,body=crate::errors::ErrorResponse)))]
pub async fn list_invitations(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Json<Vec<InvitationView>>, AppError> {
    Ok(Json(
        access_admin::list_invitations(state.pool()?, &principal).await?,
    ))
}

#[utoipa::path(delete,path="/api/v1/invitations/{id}",tag="access",security(("bearer"=[])),params(("id"=Uuid,Path)),responses((status=204),(status=403,body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse)))]
pub async fn revoke_invitation(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Extension(request): Extension<RequestId>,
) -> Result<StatusCode, AppError> {
    access_admin::revoke_invitation(state.pool()?, &principal, id, request.0).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post,path="/api/v1/auth/accept-invitation",tag="auth",request_body=AcceptInvitation,responses((status=201,body=User),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=429,body=crate::errors::ErrorResponse)))]
pub async fn accept_invitation(
    State(state): State<AppState>,
    Extension(request): Extension<RequestId>,
    Json(input): Json<AcceptInvitation>,
) -> Result<(StatusCode, Json<User>), AppError> {
    state.auth()?.allow_login().await?;
    Ok((
        StatusCode::CREATED,
        Json(
            access_admin::accept_invitation(state.pool()?, state.auth()?, request.0, input).await?,
        ),
    ))
}

#[utoipa::path(get,path="/api/v1/audit/roles",tag="access",security(("bearer"=[])),params(AuditQuery),responses((status=200,body=[AuditEntry]),(status=403,body=crate::errors::ErrorResponse)))]
pub async fn role_audit(
    State(state): State<AppState>,
    principal: Principal,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, AppError> {
    Ok(Json(
        access_admin::role_audit(state.pool()?, &principal, query).await?,
    ))
}
