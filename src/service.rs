use crate::config::{AuthConfig, OtpType};
use crate::email::EmailSender;
use crate::errors::AuthError;
use crate::rate_limit::RateLimiter;
use crate::storage::Storage;
use crate::token::TokenService;
use rand::Rng;
use std::sync::Arc;

pub struct AuthService {
    pub config: AuthConfig,
    storage: Arc<dyn Storage>,
    email_sender: Arc<dyn EmailSender>,
    token_service: TokenService,
    rate_limiter: RateLimiter,
}

impl AuthService {
    pub fn new(
        config: AuthConfig,
        storage: Arc<dyn Storage>,
        email_sender: Arc<dyn EmailSender>,
    ) -> Self {
        let token_service = TokenService::new(config.clone());
        let rate_limiter = RateLimiter::new(storage.clone(), config.clone());
        Self {
            config,
            storage,
            email_sender,
            token_service,
            rate_limiter,
        }
    }

    pub async fn request_otp(&self, email: &str) -> Result<(), AuthError> {
        self.rate_limiter.check_rate_limit(email).await?;

        let otp = if self.config.enable_magic_login {
            "000000".to_string()
        } else {
            self.generate_otp()
        };

        self.storage
            .set_otp(email, &otp, self.config.otp_expiry_seconds)
            .await?;

        if self.config.enable_magic_login {
            return Ok(());
        }

        self.email_sender
            .send_email(
                email,
                "Your verification code",
                &format!("Your verification code is: {}", otp),
            )
            .await?;

        Ok(())
    }

    pub async fn verify_otp(&self, email: &str, otp: &str) -> Result<(String, String), AuthError> {
        // Check max attempts
        let attempts = self.storage.get_attempts(email).await?;
        if attempts >= self.config.otp_max_verify_attempts {
            self.storage.delete_otp(email).await?;
            self.storage.clear_attempts(email).await?;
            return Err(AuthError::TooManyAttempts);
        }

        let stored_otp = self.storage.get_otp(email).await?;
        match stored_otp {
            Some(s_otp) if s_otp == otp => {
                self.storage.delete_otp(email).await?;
                self.storage.clear_attempts(email).await?;

                let access_token = self.token_service.create_access_token(email)?;
                let refresh_token = self.token_service.create_refresh_token(email)?;

                Ok((access_token, refresh_token))
            }
            Some(_) => {
                self.storage
                    .increment_attempts(email, self.config.otp_expiry_seconds)
                    .await?;
                Err(AuthError::InvalidOtp)
            }
            None => Err(AuthError::OtpExpired),
        }
    }

    pub async fn logout(
        &self,
        access_token: &str,
        refresh_token: Option<&str>,
    ) -> Result<(), AuthError> {
        if let Ok(claims) = self.token_service.verify_token(access_token, "access") {
            let ttl = (claims.exp as i64 - chrono::Utc::now().timestamp()) as u64;
            if ttl > 0 {
                self.storage.blacklist_token(&claims.jti, ttl).await?;
            }
        }

        if let Some(rt) = refresh_token {
            if let Ok(claims) = self.token_service.verify_token(rt, "refresh") {
                let ttl = (claims.exp as i64 - chrono::Utc::now().timestamp()) as u64;
                if ttl > 0 {
                    self.storage.blacklist_token(&claims.jti, ttl).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<String, AuthError> {
        let claims = self.token_service.verify_token(refresh_token, "refresh")?;

        if self.storage.is_token_blacklisted(&claims.jti).await? {
            return Err(AuthError::TokenError(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            )));
        }

        let access_token = self.token_service.create_access_token(&claims.sub)?;
        Ok(access_token)
    }

    pub fn verify_access_token(&self, token: &str) -> Result<crate::token::Claims, AuthError> {
        self.token_service.verify_token(token, "access")
    }

    fn generate_otp(&self) -> String {
        let mut rng = rand::thread_rng();
        match self.config.otp_type {
            OtpType::Numeric => {
                let range = 10u32.pow(self.config.otp_length as u32);
                let num = rng.gen_range(0..range);
                format!("{:0width$}", num, width = self.config.otp_length)
            }
            OtpType::Alphanumeric => {
                let chars: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                (0..self.config.otp_length)
                    .map(|_| {
                        let idx = rng.gen_range(0..chars.len());
                        chars[idx] as char
                    })
                    .collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::MockEmailSender;
    use crate::storage::MockStorage;
    use mockall::predicate::*;

    #[tokio::test]
    async fn test_request_otp_success() {
        let mut mock_storage = MockStorage::new();
        let mut mock_email = MockEmailSender::new();
        let config = AuthConfig::default();

        mock_storage
            .expect_increment_rate_limit()
            .with(eq("rate_limit:test@example.com"), eq(60))
            .times(1)
            .returning(|_, _| Ok(1));

        mock_storage
            .expect_set_otp()
            .with(eq("test@example.com"), always(), eq(300))
            .times(1)
            .returning(|_, _, _| Ok(()));

        mock_email
            .expect_send_email()
            .with(
                eq("test@example.com"),
                eq("Your verification code"),
                always(),
            )
            .times(1)
            .returning(|_, _, _| Ok(()));

        let service = AuthService::new(config, Arc::new(mock_storage), Arc::new(mock_email));

        let result = service.request_otp("test@example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_otp_rate_limit_exceeded() {
        let mut mock_storage = MockStorage::new();
        let mock_email = MockEmailSender::new();
        let config = AuthConfig::default();

        mock_storage
            .expect_increment_rate_limit()
            .returning(|_, _| Ok(10)); // > 5

        let service = AuthService::new(config, Arc::new(mock_storage), Arc::new(mock_email));

        let result = service.request_otp("test@example.com").await;
        assert!(matches!(result, Err(AuthError::RateLimitExceeded)));
    }

    #[tokio::test]
    async fn test_verify_otp_success() {
        let mut mock_storage = MockStorage::new();
        let mock_email = MockEmailSender::new();
        let config = AuthConfig::default();

        mock_storage.expect_get_attempts().returning(|_| Ok(0));

        mock_storage
            .expect_get_otp()
            .with(eq("test@example.com"))
            .returning(|_| Ok(Some("123456".to_string())));

        mock_storage
            .expect_delete_otp()
            .with(eq("test@example.com"))
            .times(1)
            .returning(|_| Ok(()));

        mock_storage
            .expect_clear_attempts()
            .with(eq("test@example.com"))
            .times(1)
            .returning(|_| Ok(()));

        let service = AuthService::new(config, Arc::new(mock_storage), Arc::new(mock_email));

        let result = service.verify_otp("test@example.com", "123456").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_otp_invalid() {
        let mut mock_storage = MockStorage::new();
        let mock_email = MockEmailSender::new();
        let config = AuthConfig::default();

        mock_storage.expect_get_attempts().returning(|_| Ok(0));

        mock_storage
            .expect_get_otp()
            .returning(|_| Ok(Some("123456".to_string())));

        mock_storage
            .expect_increment_attempts()
            .times(1)
            .returning(|_, _| Ok(1));

        let service = AuthService::new(config, Arc::new(mock_storage), Arc::new(mock_email));

        let result = service.verify_otp("test@example.com", "000000").await;
        assert!(matches!(result, Err(AuthError::InvalidOtp)));
    }
}
