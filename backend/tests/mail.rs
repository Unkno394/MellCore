use honeyforge_backend::{
    config::Config,
    mail::{MailPurpose, SmtpDelivery},
};

#[test]
fn emails_use_configured_sender_and_frontend_routes_without_secret_leakage() {
    let config = Config::from_lookup(|key| {
        Ok(match key {
            "FRONTEND_URL" => Some("https://dashboard.example.test".into()),
            "FRONTEND_RESET_PATH" => Some("/auth/reset".into()),
            "FRONTEND_VERIFY_PATH" => Some("/auth/verify".into()),
            "SMTP_HOST" => Some("smtp.example.test".into()),
            "SMTP_USERNAME" => Some("mail-account".into()),
            "SMTP_PASSWORD" => Some("smtp-secret-never-in-email".into()),
            "SMTP_FROM" => Some("honeyforge@example.test".into()),
            _ => None,
        })
    })
    .unwrap();
    for (purpose, path) in [
        (MailPurpose::PasswordReset, &config.frontend_reset_path),
        (MailPurpose::EmailVerification, &config.frontend_verify_path),
    ] {
        let mail = SmtpDelivery::new(
            config.smtp.as_ref().unwrap(),
            &config.frontend_url,
            path,
            purpose,
        )
        .unwrap();
        let rendered = String::from_utf8(
            mail.message("user@example.test", "example-token")
                .unwrap()
                .formatted(),
        )
        .unwrap();
        assert!(rendered.contains("honeyforge@example.test"));
        assert!(rendered.contains(&format!("https://dashboard.example.test{path}")));
        assert!(rendered.contains("example-token"));
        assert!(!rendered.contains("smtp-secret"));
    }
}
