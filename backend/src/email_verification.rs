use crate::{auth, errors::AppError, mail::TokenDelivery, management};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone)]
pub struct EmailVerifications {
    queue: mpsc::Sender<(String, Uuid)>,
}
impl EmailVerifications {
    pub fn start(pool: PgPool, delivery: Arc<dyn TokenDelivery>) -> Self {
        let (queue, mut receiver) = mpsc::channel::<(String, Uuid)>(64);
        tokio::spawn(async move {
            while let Some((email, request_id)) = receiver.recv().await {
                if issue(&pool, delivery.as_ref(), &email, request_id)
                    .await
                    .is_err()
                {
                    tracing::warn!(%request_id,"email verification delivery failed");
                }
            }
        });
        Self { queue }
    }
    pub fn enqueue(&self, email: String, request_id: Uuid) -> Result<(), AppError> {
        self.queue
            .try_send((email, request_id))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => AppError::busy(),
                mpsc::error::TrySendError::Closed(_) => AppError::mail_unavailable(),
            })
    }
}
async fn issue(
    pool: &PgPool,
    delivery: &dyn TokenDelivery,
    email: &str,
    request_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;
    let user:Option<Uuid>=sqlx::query_scalar("SELECT id FROM users WHERE email=$1 AND is_active AND email_verified_at IS NULL FOR UPDATE").bind(email).fetch_optional(&mut *tx).await?;
    let Some(user) = user else {
        return Ok(());
    };
    let recent:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_verifications WHERE user_id=$1 AND created_at>now()-interval '1 minute')").bind(user).fetch_one(&mut *tx).await?;
    if recent {
        return Ok(());
    }
    let token = auth::new_token();
    let hash = auth::digest(&token);
    sqlx::query("INSERT INTO email_verifications(user_id,email,token_hash,expires_at) VALUES ($1,$2,$3,now()+interval '24 hours') ON CONFLICT(user_id) DO UPDATE SET email=EXCLUDED.email,token_hash=EXCLUDED.token_hash,created_at=now(),expires_at=EXCLUDED.expires_at")
        .bind(user).bind(email).bind(&hash).execute(&mut *tx).await?;
    management::audit(
        &mut tx,
        user,
        "auth.verification_requested",
        user,
        request_id,
    )
    .await?;
    tx.commit().await?;
    if tokio::time::timeout(Duration::from_secs(20), delivery.send(email, &token))
        .await
        .unwrap_or_else(|_| Err(AppError::mail_unavailable()))
        .is_err()
    {
        sqlx::query("DELETE FROM email_verifications WHERE user_id=$1 AND token_hash=$2")
            .bind(user)
            .bind(&hash)
            .execute(pool)
            .await?;
        return Err(AppError::mail_unavailable());
    }
    Ok(())
}

pub async fn consume(pool: &PgPool, token: &str, request_id: Uuid) -> Result<(), AppError> {
    let invalid = || AppError::invalid("Invalid or expired verification token");
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let hash = auth::digest(token);
    let user: Uuid = sqlx::query_scalar(
        "SELECT user_id FROM email_verifications WHERE token_hash=$1 AND expires_at>now()",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await?
    .ok_or_else(invalid)?;
    let mut tx = pool.begin().await?;
    let email:Option<String>=sqlx::query_scalar("SELECT email FROM users WHERE id=$1 AND is_active AND email_verified_at IS NULL FOR UPDATE").bind(user).fetch_optional(&mut *tx).await?.flatten();
    let email = email.ok_or_else(invalid)?;
    let consumed=sqlx::query("DELETE FROM email_verifications WHERE user_id=$1 AND email=$2 AND token_hash=$3 AND expires_at>now()").bind(user).bind(&email).bind(&hash).execute(&mut *tx).await?.rows_affected();
    if consumed != 1 {
        return Err(invalid());
    }
    sqlx::query("UPDATE users SET email_verified_at=now(),updated_at=now() WHERE id=$1")
        .bind(user)
        .execute(&mut *tx)
        .await?;
    management::revoke_credentials(&mut tx, user).await?;
    management::audit(&mut tx, user, "auth.email_verified", user, request_id).await?;
    tx.commit().await?;
    Ok(())
}
