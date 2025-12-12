use async_trait::async_trait;
use axum::Router;
use axum_email_otp_auth::{
    axum_api::auth_router, AuthConfig, AuthError, AuthService, EmailSender, RedisStorage,
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct TestEmailSender {
    pub sent_emails: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl TestEmailSender {
    pub fn new() -> Self {
        Self::default()
    }
}

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

#[allow(dead_code)]
pub async fn spawn_app() -> (Router, Arc<TestEmailSender>, Arc<RedisStorage>) {
    let mut auth_config = AuthConfig::from_env().unwrap_or_else(|_| AuthConfig::default());
    auth_config.enable_magic_login = false;

    // Ensure Redis URL is set correctly for Docker environment
    if let Ok(host) = std::env::var("REDIS_HOST") {
        auth_config.redis_url = format!("redis://{}:6379/", host);
    }
    // Also specific override if needed
    if let Ok(url) = std::env::var("REDIS_URL") {
        auth_config.redis_url = url;
    }

    let redis_storage = Arc::new(RedisStorage::new(&auth_config.redis_url).unwrap());
    let email_sender = Arc::new(TestEmailSender::new());

    let auth_service = Arc::new(AuthService::new(
        auth_config,
        redis_storage.clone(),
        email_sender.clone(),
    ));

    let router = auth_router(auth_service);
    (router, email_sender, redis_storage)
}
