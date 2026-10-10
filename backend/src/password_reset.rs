//! Bounded asynchronous delivery keeps account existence out of HTTP timing/status.
pub use crate::mail::{DeliveryFuture, TokenDelivery as ResetDelivery};
use crate::{auth, errors::AppError, management};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone)]
pub struct PasswordResets {
    queue: mpsc::Sender<(String, Uuid)>,
}
impl PasswordResets {
    pub fn start(pool: PgPool, delivery: Arc<dyn ResetDelivery>) -> Self {
        let (queue, mut receiver) = mpsc::channel::<(String, Uuid)>(64);
        tokio::spawn(async move {
            while let Some((email, request_id)) = receiver.recv().await {
                if issue(&pool, delivery.as_ref(), &email, request_id)
                    .await
                    .is_err()
                {
                    // Never log provider errors (may contain recipient, credentials or token).
                    tracing::warn!(%request_id, "password reset delivery failed");
                }
            }
        });
        Self { queue }
    }
    pub fn enqueue(&self, email: String, request_id: Uuid) -> Result<(), AppError> {
        self.queue
            .try_send((email, request_id))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => AppError::busy(),
                mpsc::error::TrySendError::Closed(_) => AppError::unavailable(),
            })
    }
}
async fn issue(
    pool: &PgPool,
    delivery: &dyn ResetDelivery,
    email: &str,
    request_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;
    let user: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE email=$1 AND is_active FOR UPDATE")
            .bind(email)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(user) = user else {
        return Ok(());
    };
    let recent: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM password_resets WHERE user_id=$1 AND created_at>now()-interval '1 minute')").bind(user).fetch_one(&mut *tx).await?;
    if recent {
        return Ok(());
    }
    let token = auth::new_token();
    let hash = auth::digest(&token);
    sqlx::query("INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES ($1,$2,now()+interval '30 minutes') ON CONFLICT(user_id) DO UPDATE SET token_hash=EXCLUDED.token_hash,created_at=now(),expires_at=EXCLUDED.expires_at")
        .bind(user).bind(&hash).execute(&mut *tx).await?;
    management::audit(&mut tx, user, "auth.reset_requested", user, request_id).await?;
    tx.commit().await?;
    if tokio::time::timeout(Duration::from_secs(20), delivery.send(email, &token))
        .await
        .unwrap_or_else(|_| Err(AppError::unavailable()))
        .is_err()
    {
        sqlx::query("DELETE FROM password_resets WHERE user_id=$1 AND token_hash=$2")
            .bind(user)
            .bind(&hash)
            .execute(pool)
            .await?;
        return Err(AppError::unavailable());
    }
    Ok(())
}
