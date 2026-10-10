use crate::management::Page;
use crate::{
    api::AppState,
    auth::Principal,
    errors::{AppError, RequestId},
    resources::{self, Server, ServerInput, ServerPage, UpdateServer},
};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use uuid::Uuid;

#[utoipa::path(post,path="/api/v1/servers",tag="servers",security(("bearer"=[])),request_body=ServerInput,responses((status=201,body=Server),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn create(
    State(state): State<AppState>,
    principal: Principal,
    Extension(request): Extension<RequestId>,
    Json(input): Json<ServerInput>,
) -> Result<(StatusCode, Json<Server>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(resources::servers::create(state.pool()?, &principal, request.0, input).await?),
    ))
}

#[utoipa::path(get,path="/api/v1/servers",tag="servers",security(("bearer"=[])),params(Page),responses((status=200,body=ServerPage),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn list(
    State(state): State<AppState>,
    principal: Principal,
    Query(query): Query<Page>,
) -> Result<Json<ServerPage>, AppError> {
    Ok(Json(
        resources::servers::list(state.pool()?, &principal, query).await?,
    ))
}

#[utoipa::path(get,path="/api/v1/servers/{server_id}",tag="servers",security(("bearer"=[])),params(("server_id"=Uuid,Path)),responses((status=200,body=Server),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn get(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<Server>, AppError> {
    Ok(Json(
        resources::servers::get(state.pool()?, &principal, id).await?,
    ))
}

#[utoipa::path(put,path="/api/v1/servers/{server_id}",tag="servers",security(("bearer"=[])),params(("server_id"=Uuid,Path)),request_body=UpdateServer,responses((status=200,body=Server),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Extension(request): Extension<RequestId>,
    Json(input): Json<UpdateServer>,
) -> Result<Json<Server>, AppError> {
    Ok(Json(
        resources::servers::update(state.pool()?, &principal, id, request.0, input).await?,
    ))
}

#[utoipa::path(delete,path="/api/v1/servers/{server_id}",tag="servers",security(("bearer"=[])),params(("server_id"=Uuid,Path)),responses((status=204,description="Registration removed; no remote command is executed"),(status=401,body=crate::errors::ErrorResponse),(status=403,body=crate::errors::ErrorResponse),(status=404,description="Missing or owned by another user",body=crate::errors::ErrorResponse),(status=409,body=crate::errors::ErrorResponse),(status=422,body=crate::errors::ErrorResponse),(status=503,body=crate::errors::ErrorResponse)))]
pub async fn delete(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Extension(request): Extension<RequestId>,
) -> Result<StatusCode, AppError> {
    resources::servers::delete(state.pool()?, &principal, id, request.0).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get,path="/api/v1/servers/{server_id}/ports",tag="servers",security(("bearer"=[])),params(("server_id"=Uuid,Path)),responses((status=200,body=[crate::resources::PortReservation]),(status=401,body=crate::errors::ErrorResponse),(status=404,body=crate::errors::ErrorResponse)))]
pub async fn ports(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<crate::resources::PortReservation>>, AppError> {
    Ok(Json(
        resources::servers::ports(state.pool()?, &principal, id).await?,
    ))
}
