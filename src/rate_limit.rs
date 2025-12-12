use crate::config::AuthConfig;
use crate::errors::AuthError;
use crate::storage::Storage;
use std::sync::Arc;

pub struct RateLimiter {
    storage: Arc<dyn Storage>,
    config: AuthConfig,
}

impl RateLimiter {
    pub fn new(storage: Arc<dyn Storage>, config: AuthConfig) -> Self {
        Self { storage, config }
    }

    pub async fn check_rate_limit(&self, email: &str) -> Result<(), AuthError> {
        let key = format!("rate_limit:{}", email);
        let count = self.storage.increment_rate_limit(&key, 60).await?; // 1 minute window

        if count > self.config.otp_rate_limit_per_minute {
            return Err(AuthError::RateLimitExceeded);
        }
        Ok(())
    }
}
