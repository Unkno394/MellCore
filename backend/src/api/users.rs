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
    management::{self, CreateUser, Page, UpdateUser, User, UserPage},
};

#[utoipa::path(post, path="/api/v1/users", tag="users", security(("bearer"=[])), request_body=CreateUser, responses((status=201, body=User), (status=403, body=crate::errors::ErrorResponse), (status=409, body=crate::errors::ErrorResponse), (status=422, body=crate::errors::ErrorResponse)))]
pub async fn create(
    State(state): State<AppState>,
    principal: Principal,
    Extension(id): Extension<RequestId>,
    Json(input): Json<CreateUser>,
) -> Result<(StatusCode, Json<User>), AppError> {
    Ok((
        StatusCode::CREATED,
        Json(
            management::users::create(state.pool()?, state.auth()?, &principal, id.0, input)
                .await?,
        ),
    ))
}

#[utoipa::path(get, path="/api/v1/users", tag="users", security(("bearer"=[])), params(Page), responses((status=200, body=UserPage), (status=403, body=crate::errors::ErrorResponse)))]
pub async fn list(
    State(state): State<AppState>,
    principal: Principal,
    Query(page): Query<Page>,
) -> Result<Json<UserPage>, AppError> {
    Ok(Json(
        management::users::list(state.pool()?, &principal, page).await?,
    ))
}

#[utoipa::path(get, path="/api/v1/users/{id}", tag="users", security(("bearer"=[])), params(("id"=Uuid, Path)), responses((status=200, body=User), (status=403, body=crate::errors::ErrorResponse), (status=404, body=crate::errors::ErrorResponse)))]
pub async fn get(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<User>, AppError> {
    Ok(Json(
        management::users::get(state.pool()?, &principal, id).await?,
    ))
}

#[utoipa::path(put, path="/api/v1/users/{id}", tag="users", security(("bearer"=[])), params(("id"=Uuid, Path)), request_body=UpdateUser, responses((status=200, body=User), (status=403, body=crate::errors::ErrorResponse), (status=404, body=crate::errors::ErrorResponse), (status=409, body=crate::errors::ErrorResponse)))]
pub async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(target): Path<Uuid>,
    Extension(id): Extension<RequestId>,
    Json(input): Json<UpdateUser>,
) -> Result<Json<User>, AppError> {
    Ok(Json(
        management::users::update(
            state.pool()?,
            state.auth()?,
            &principal,
            target,
            id.0,
            input,
        )
        .await?,
    ))
}

#[utoipa::path(delete, path="/api/v1/users/{id}", tag="users", security(("bearer"=[])), params(("id"=Uuid, Path)), responses((status=204, description="User removed and sessions revoked"), (status=403, body=crate::errors::ErrorResponse), (status=404, body=crate::errors::ErrorResponse), (status=409, body=crate::errors::ErrorResponse)))]
pub async fn delete(
    State(state): State<AppState>,
    principal: Principal,
    Path(target): Path<Uuid>,
    Extension(id): Extension<RequestId>,
) -> Result<StatusCode, AppError> {
    management::users::delete(state.pool()?, &principal, target, id.0).await?;
    Ok(StatusCode::NO_CONTENT)
}
