use crate::resources::TrapQuery;
use crate::{
    api::AppState,
    auth::Principal,
    errors::{AppError, RequestId},
    resources::{self, CreateTrap, Trap, TrapPage, UpdateTrap},
};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use uuid::Uuid;

/// Export configuration only. No deployment or actual-state transition occurs.
#[utoipa::path(get,path="/api/v1/traps/{trap_id}/runtime-config",tag="traps",security(("bearer"=[])),params(("trap_id"=Uuid,Path)),responses((status=200,body=crate::kozyavka::RuntimeConfig),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,body=crate::errors::ErrorResponse),(status=409,description="No adapter for this profile",body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn runtime_config(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::kozyavka::RuntimeConfig>, AppError> {
    let trap = resources::traps::get(state.pool()?, &principal, id).await?;
    Ok(Json(crate::kozyavka::runtime_config(&trap)?))
}

#[utoipa::path(post,path="/api/v1/traps",tag="traps",security(("bearer"=[])),request_body=CreateTrap,responses((status=201,body=Trap),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn create(
    State(state): State<AppState>,
    principal: Principal,
    Extension(request): Extension<RequestId>,
    Json(input): Json<CreateTrap>,
) -> Result<(StatusCode, Json<Trap>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(resources::traps::create(state.pool()?, &principal, request.0, input).await?),
    ))
}

#[utoipa::path(get,path="/api/v1/traps",tag="traps",security(("bearer"=[])),params(TrapQuery),responses((status=200,body=TrapPage),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn list(
    State(state): State<AppState>,
    principal: Principal,
    Query(query): Query<TrapQuery>,
) -> Result<Json<TrapPage>, AppError> {
    Ok(Json(
        resources::traps::list(state.pool()?, &principal, query).await?,
    ))
}

#[utoipa::path(get,path="/api/v1/traps/{trap_id}",tag="traps",security(("bearer"=[])),params(("trap_id"=Uuid,Path)),responses((status=200,body=Trap),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn get(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<Trap>, AppError> {
    Ok(Json(
        resources::traps::get(state.pool()?, &principal, id).await?,
    ))
}

#[utoipa::path(put,path="/api/v1/traps/{trap_id}",tag="traps",security(("bearer"=[])),params(("trap_id"=Uuid,Path)),request_body=UpdateTrap,responses((status=200,body=Trap),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Extension(request): Extension<RequestId>,
    Json(input): Json<UpdateTrap>,
) -> Result<Json<Trap>, AppError> {
    Ok(Json(
        resources::traps::update(state.pool()?, &principal, id, request.0, input).await?,
    ))
}

#[utoipa::path(delete,path="/api/v1/traps/{trap_id}",tag="traps",security(("bearer"=[])),params(("trap_id"=Uuid,Path)),responses((status=204,description="Registration removed; no remote command is executed"),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn delete(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Extension(request): Extension<RequestId>,
) -> Result<StatusCode, AppError> {
    resources::traps::delete(state.pool()?, &principal, id, request.0).await?;
    Ok(StatusCode::NO_CONTENT)
}
