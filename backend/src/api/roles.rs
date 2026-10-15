use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{
    api::AppState,
    auth::Principal,
    errors::{AppError, RequestId},
    rbac::{
        self, AssignRoles, CopyRoleInput, EffectiveAccess, PermissionInfo, RoleInput, RoleView,
    },
};

#[utoipa::path(get,path="/api/v1/permissions",tag="roles",security(("bearer"=[])),responses((status=200,body=[PermissionInfo]),(status=403,body=crate::errors::ErrorResponse)))]
pub async fn permissions(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Json<Vec<PermissionInfo>>, AppError> {
    principal.require("roles.view")?;
    Ok(Json(rbac::permissions(state.pool()?).await?))
}

#[utoipa::path(get,path="/api/v1/roles",tag="roles",security(("bearer"=[])),responses((status=200,body=[RoleView]),(status=403,body=crate::errors::ErrorResponse)))]
pub async fn list(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Json<Vec<RoleView>>, AppError> {
    Ok(Json(rbac::list(state.pool()?, &principal).await?))
}

#[utoipa::path(post,path="/api/v1/roles",tag="roles",security(("bearer"=[])),request_body=RoleInput,responses((status=201,body=RoleView),(status=403,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse)))]
pub async fn create(
    State(state): State<AppState>,
    principal: Principal,
    Extension(request): Extension<RequestId>,
    Json(input): Json<RoleInput>,
) -> Result<(StatusCode, Json<RoleView>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(rbac::create(state.pool()?, &principal, request.0, input).await?),
    ))
}

#[utoipa::path(put,path="/api/v1/roles/{id}",tag="roles",security(("bearer"=[])),params(("id"=Uuid,Path)),request_body=RoleInput,responses((status=200,body=RoleView),(status=403,body=crate::errors::ErrorResponse),(status=404,body=crate::errors::ErrorResponse)))]
pub async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Extension(request): Extension<RequestId>,
    Json(input): Json<RoleInput>,
) -> Result<Json<RoleView>, AppError> {
    Ok(Json(
        rbac::update(state.pool()?, &principal, id, request.0, input).await?,
    ))
}

#[utoipa::path(post,path="/api/v1/roles/{id}/copy",tag="roles",security(("bearer"=[])),params(("id"=Uuid,Path)),request_body=CopyRoleInput,responses((status=201,body=RoleView),(status=403,body=crate::errors::ErrorResponse),(status=404,body=crate::errors::ErrorResponse)))]
pub async fn copy(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Extension(request): Extension<RequestId>,
    Json(input): Json<CopyRoleInput>,
) -> Result<(StatusCode, Json<RoleView>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(rbac::copy(state.pool()?, &principal, id, request.0, input).await?),
    ))
}

#[utoipa::path(delete,path="/api/v1/roles/{id}",tag="roles",security(("bearer"=[])),params(("id"=Uuid,Path)),responses((status=204),(status=403,body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse)))]
pub async fn delete(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Extension(request): Extension<RequestId>,
) -> Result<StatusCode, AppError> {
    rbac::delete(state.pool()?, &principal, id, request.0).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get,path="/api/v1/users/{id}/permissions",tag="users",security(("bearer"=[])),params(("id"=Uuid,Path)),responses((status=200,body=EffectiveAccess),(status=403,body=crate::errors::ErrorResponse)))]
pub async fn user_access(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<EffectiveAccess>, AppError> {
    Ok(Json(
        rbac::effective_access(state.pool()?, &principal, id).await?,
    ))
}

#[utoipa::path(put,path="/api/v1/users/{id}/roles",tag="users",security(("bearer"=[])),params(("id"=Uuid,Path)),request_body=AssignRoles,responses((status=200,body=EffectiveAccess),(status=403,body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse)))]
pub async fn assign_user(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Extension(request): Extension<RequestId>,
    Json(input): Json<AssignRoles>,
) -> Result<Json<EffectiveAccess>, AppError> {
    Ok(Json(
        rbac::assign(state.pool()?, &principal, id, request.0, input).await?,
    ))
}
