//! SMTP adapter shared by reset and verification; no provider details reach HTTP/logs.
use crate::{config::SmtpConfig, errors::AppError};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use std::{future::Future, pin::Pin, time::Duration};
pub type DeliveryFuture<'a> = Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>>;
pub trait TokenDelivery: Send + Sync {
    fn send<'a>(&'a self, email: &'a str, token: &'a str) -> DeliveryFuture<'a>;
}
#[derive(Clone, Copy)]
pub enum MailPurpose {
    PasswordReset,
    EmailVerification,
}
pub struct SmtpDelivery {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    link_base: String,
    purpose: MailPurpose,
}
impl SmtpDelivery {
    pub fn new(
        config: &SmtpConfig,
        frontend: &str,
        path: &str,
        purpose: MailPurpose,
    ) -> Result<Self, AppError> {
        let builder = if config.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
        }
        .map_err(|_| AppError::invalid("Invalid SMTP configuration"))?;
        let transport = builder
            .port(config.port)
            .timeout(Some(Duration::from_secs(10)))
            .credentials(Credentials::new(
                config.username.clone(),
                config.password.expose().to_owned(),
            ))
            .build();
        let from = config
            .from
            .parse()
            .map_err(|_| AppError::invalid("Invalid SMTP sender"))?;
        Ok(Self {
            transport,
            from,
            link_base: format!("{frontend}{path}"),
            purpose,
        })
    }
    pub fn message(&self, email: &str, token: &str) -> Result<Message, AppError> {
        let (subject, instruction) = match self.purpose {
            MailPurpose::PasswordReset => (
                "HoneyForge: password reset",
                "Reset your password within 30 minutes",
            ),
            MailPurpose::EmailVerification => (
                "HoneyForge: verify your email",
                "Verify your email address within 24 hours",
            ),
        };
        Message::builder()
            .from(self.from.clone())
            .to(email.parse().map_err(|_| AppError::internal())?)
            .subject(subject)
            .body(format!(
                "{instruction}:\n{}#token={}\n\nIf you did not request this, ignore this email.",
                self.link_base, token
            ))
            .map_err(|_| AppError::internal())
    }
}
impl TokenDelivery for SmtpDelivery {
    fn send<'a>(&'a self, email: &'a str, token: &'a str) -> DeliveryFuture<'a> {
        Box::pin(async move {
            self.transport
                .send(self.message(email, token)?)
                .await
                .map_err(|_| AppError::mail_unavailable())?;
            Ok(())
        })
    }
}
