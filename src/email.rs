use crate::config::AuthConfig;
use crate::errors::AuthError;
use async_trait::async_trait;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send_email(&self, recipient: &str, subject: &str, body: &str)
        -> Result<(), AuthError>;
}

pub struct LettreEmailSender {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    from_email: String,
    from_name: String,
}

impl LettreEmailSender {
    pub fn new(config: &AuthConfig) -> Self {
        let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

        // Basic builder, might need more config for TLS/StartTLS depending on requirements
        // For now assuming standard SMTP
        // Use builder() for explicit control. relay() implies TLS logic often.
        // For local development with Mailpit (port 1025), we usually want unencrypted.
        let mailer = if config.smtp_port == 1025 {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_server)
                .port(config.smtp_port)
                .build()
        } else if config.smtp_starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_server)
                .expect("Failed to build SMTP transport (invalid host?)")
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_server)
                .expect("Failed to build SMTP transport (invalid host?)")
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        };

        Self {
            mailer,
            from_email: config.mail_from.clone(),
            from_name: config.mail_from_name.clone(),
        }
    }
}

#[async_trait]
impl EmailSender for LettreEmailSender {
    async fn send_email(
        &self,
        recipient: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), AuthError> {
        let email = Message::builder()
            .from(
                format!("{} <{}>", self.from_name, self.from_email)
                    .parse()
                    .map_err(|e| AuthError::EmailError(format!("Invalid from address: {}", e)))?,
            )
            .to(recipient
                .parse()
                .map_err(|e| AuthError::EmailError(format!("Invalid to address: {}", e)))?)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| AuthError::EmailError(format!("Failed to build email: {}", e)))?;

        self.mailer
            .send(email)
            .await
            .map_err(|e| AuthError::EmailError(format!("Failed to send email: {}", e)))?;
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub struct TestEmailSender {
    pub sent_emails: std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
}

#[cfg(test)]
impl TestEmailSender {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
#[async_trait]
impl EmailSender for TestEmailSender {
    async fn send_email(
        &self,
        recipient: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), AuthError> {
        self.sent_emails.lock().unwrap().push((
            recipient.to_string(),
            subject.to_string(),
            body.to_string(),
        ));
        Ok(())
    }
}
