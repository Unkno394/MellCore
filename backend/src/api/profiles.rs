use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{
    api::AppState,
    auth::Principal,
    errors::{AppError, RequestId},
    management::{self, Page, Profile, ProfileInput, ProfilePage, UpdateProfile},
};

#[utoipa::path(post, path="/api/v1/profiles", tag="profiles", security(("bearer"=[])), request_body=ProfileInput, responses((status=201, body=Profile), (status=403, body=crate::errors::ErrorResponse), (status=422, body=crate::errors::ErrorResponse)))]
pub async fn create(
    State(state): State<AppState>,
    principal: Principal,
    Extension(id): Extension<RequestId>,
    Json(input): Json<ProfileInput>,
) -> Result<(StatusCode, Json<Profile>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(management::profiles::create(state.pool()?, &principal, id.0, input).await?),
    ))
}

#[utoipa::path(get, path="/api/v1/profiles", tag="profiles", security(("bearer"=[])), params(Page), responses((status=200, body=ProfilePage), (status=401, body=crate::errors::ErrorResponse)))]
pub async fn list(
    State(state): State<AppState>,
    _principal: Principal,
    Query(page): Query<Page>,
) -> Result<Json<ProfilePage>, AppError> {
    Ok(Json(
        management::profiles::list(state.pool()?, &_principal, page).await?,
    ))
}

#[utoipa::path(get, path="/api/v1/profiles/{id}", tag="profiles", security(("bearer"=[])), params(("id"=Uuid, Path)), responses((status=200, body=Profile), (status=401, body=crate::errors::ErrorResponse), (status=404, body=crate::errors::ErrorResponse)))]
pub async fn get(
    State(state): State<AppState>,
    _principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<Profile>, AppError> {
    Ok(Json(
        management::profiles::get(state.pool()?, &_principal, id).await?,
    ))
}

#[utoipa::path(put, path="/api/v1/profiles/{id}", tag="profiles", security(("bearer"=[])), params(("id"=Uuid, Path)), request_body=UpdateProfile, responses((status=200, body=Profile), (status=403, body=crate::errors::ErrorResponse), (status=404, body=crate::errors::ErrorResponse), (status=409, body=crate::errors::ErrorResponse)))]
pub async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(target): Path<Uuid>,
    Extension(id): Extension<RequestId>,
    Json(input): Json<UpdateProfile>,
) -> Result<Json<Profile>, AppError> {
    Ok(Json(
        management::profiles::update(state.pool()?, &principal, target, id.0, input).await?,
    ))
}

#[utoipa::path(delete, path="/api/v1/profiles/{id}", tag="profiles", security(("bearer"=[])), params(("id"=Uuid, Path)), responses((status=204, description="Profile removed"), (status=403, body=crate::errors::ErrorResponse), (status=404, body=crate::errors::ErrorResponse), (status=409, body=crate::errors::ErrorResponse)))]
pub async fn delete(
    State(state): State<AppState>,
    principal: Principal,
    Path(target): Path<Uuid>,
    Extension(id): Extension<RequestId>,
) -> Result<StatusCode, AppError> {
    management::profiles::delete(state.pool()?, &principal, target, id.0).await?;
    Ok(StatusCode::NO_CONTENT)
}
