use crate::{
    auth::Principal,
    errors::AppError,
    management::{self, Page, Profile, ProfileInput, ProfilePage, UpdateProfile},
};
use sqlx::PgPool;
use uuid::Uuid;

pub async fn create(
    pool: &PgPool,
    principal: &Principal,
    request_id: Uuid,
    input: ProfileInput,
) -> Result<Profile, AppError> {
    principal.require_admin()?;
    input.validate()?;
    let resources = input.resolved_resources();
    let mut tx = management::admin_tx(pool, principal.user.id).await?;
    let profile = sqlx::query_as::<_, Profile>("INSERT INTO trap_profiles(id,name,description,level,honeypot_type,service_type,config,resources) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *")
        .bind(Uuid::new_v4()).bind(input.name.trim()).bind(input.description).bind(input.level).bind(input.honeypot_type).bind(input.service_type).bind(input.config).bind(sqlx::types::Json(resources)).fetch_one(&mut *tx).await?;
    management::audit(
        &mut tx,
        principal.user.id,
        "profile.create",
        profile.id,
        request_id,
    )
    .await?;
    tx.commit().await?;
    Ok(profile)
}

pub async fn list(
    pool: &PgPool,
    _principal: &Principal,
    page: Page,
) -> Result<ProfilePage, AppError> {
    let limit = page.size()?;
    let mut items = sqlx::query_as::<_, Profile>(
        "SELECT * FROM trap_profiles WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT $2",
    )
    .bind(page.after)
    .bind((limit + 1) as i64)
    .fetch_all(pool)
    .await?;
    let next_cursor = if items.len() > limit {
        items.truncate(limit);
        items.last().map(|p| p.id)
    } else {
        None
    };
    Ok(ProfilePage { items, next_cursor })
}

pub async fn get(pool: &PgPool, _principal: &Principal, id: Uuid) -> Result<Profile, AppError> {
    Ok(sqlx::query_as("SELECT * FROM trap_profiles WHERE id=$1")
        .bind(id)
        .fetch_one(pool)
        .await?)
}

pub async fn update(
    pool: &PgPool,
    principal: &Principal,
    target: Uuid,
    request_id: Uuid,
    input: UpdateProfile,
) -> Result<Profile, AppError> {
    principal.require_admin()?;
    input.profile.validate()?;
    if input.expected_version < 1 {
        return Err(AppError::invalid("expected_version must be positive"));
    }
    let mut tx = management::admin_tx(pool, principal.user.id).await?;
    let version: i64 =
        sqlx::query_scalar("SELECT version FROM trap_profiles WHERE id=$1 FOR UPDATE")
            .bind(target)
            .fetch_one(&mut *tx)
            .await?;
    if version != input.expected_version {
        return Err(AppError::conflict("Profile version has changed"));
    }
    let p = input.profile;
    let resources = p.resolved_resources();
    let profile = sqlx::query_as::<_, Profile>("UPDATE trap_profiles SET name=$2,description=$3,level=$4,honeypot_type=$5,service_type=$6,config=$7,resources=$8,version=version+1,updated_at=now() WHERE id=$1 RETURNING *")
        .bind(target).bind(p.name.trim()).bind(p.description).bind(p.level).bind(p.honeypot_type).bind(p.service_type).bind(p.config).bind(sqlx::types::Json(resources)).fetch_one(&mut *tx).await?;
    management::audit(
        &mut tx,
        principal.user.id,
        "profile.update",
        target,
        request_id,
    )
    .await?;
    tx.commit().await?;
    Ok(profile)
}

pub async fn delete(
    pool: &PgPool,
    principal: &Principal,
    target: Uuid,
    request_id: Uuid,
) -> Result<(), AppError> {
    principal.require_admin()?;
    let mut tx = management::admin_tx(pool, principal.user.id).await?;
    if sqlx::query("DELETE FROM trap_profiles WHERE id=$1")
        .bind(target)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 0
    {
        return Err(AppError::not_found());
    }
    management::audit(
        &mut tx,
        principal.user.id,
        "profile.delete",
        target,
        request_id,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
