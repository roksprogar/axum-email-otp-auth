#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub otp_expiry_seconds: u64,
    pub otp_max_verify_attempts: u32,
    pub otp_rate_limit_per_minute: u32,
    pub jwt_secret: String,
    pub jwt_algorithm: jsonwebtoken::Algorithm,
    pub access_token_expire_minutes: i64,
    pub refresh_token_expire_days: i64,
    pub enable_magic_login: bool, // Magic OTP
    pub otp_length: usize,
    pub otp_type: OtpType,
    pub redis_url: String,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_starttls: bool,
    pub smtp_username: String,
    pub smtp_password: String,
    pub mail_from: String,
    pub mail_from_name: String,
    pub storage_type: StorageType,
    pub refresh_cookie_name: String,
    pub refresh_cookie_domain: Option<String>,
    pub refresh_cookie_path: String,
    pub refresh_cookie_secure: bool,
    pub refresh_cookie_same_site: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StorageType {
    Memory,
    Redis,
}

#[derive(Debug, Clone, Copy)]
pub enum OtpType {
    Numeric,
    Alphanumeric,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            otp_expiry_seconds: 300,
            otp_max_verify_attempts: 3,
            otp_rate_limit_per_minute: 5,
            jwt_secret: "secret".to_string(),
            jwt_algorithm: jsonwebtoken::Algorithm::HS256,
            access_token_expire_minutes: 60,
            refresh_token_expire_days: 365,
            enable_magic_login: false,
            otp_length: 6,
            otp_type: OtpType::Numeric,
            redis_url: "redis://127.0.0.1/".to_string(),
            smtp_server: "localhost".to_string(),
            smtp_port: 1025,
            smtp_starttls: true,
            smtp_username: "".to_string(),
            smtp_password: "".to_string(),
            mail_from: "noreply@example.com".to_string(),
            mail_from_name: "Auth Service".to_string(),
            storage_type: StorageType::Redis,
            refresh_cookie_name: "refresh_token".to_string(),
            refresh_cookie_domain: None,
            refresh_cookie_path: "/".to_string(),
            refresh_cookie_secure: true,
            refresh_cookie_same_site: "Lax".to_string(),
        }
    }
}

use crate::errors::AuthError;

impl AuthConfig {
    pub fn from_env() -> Result<Self, AuthError> {
        let mut config = Self::default();

        if let Ok(val) = std::env::var("OTP_EXPIRY_SECONDS") {
            config.otp_expiry_seconds = val
                .parse()
                .map_err(|_| AuthError::ConfigError("Invalid OTP_EXPIRY_SECONDS".to_string()))?;
        }
        if let Ok(val) = std::env::var("OTP_MAX_VERIFY_ATTEMPTS") {
            config.otp_max_verify_attempts = val.parse().map_err(|_| {
                AuthError::ConfigError("Invalid OTP_MAX_VERIFY_ATTEMPTS".to_string())
            })?;
        }
        if let Ok(val) = std::env::var("OTP_RATE_LIMIT_PER_MINUTE") {
            config.otp_rate_limit_per_minute = val.parse().map_err(|_| {
                AuthError::ConfigError("Invalid OTP_RATE_LIMIT_PER_MINUTE".to_string())
            })?;
        }

        // Required in production, but we can default to env or keep default if not set for dev
        if let Ok(val) = std::env::var("JWT_SECRET") {
            config.jwt_secret = val;
        }

        if let Ok(val) = std::env::var("ACCESS_TOKEN_EXPIRE_MINUTES") {
            config.access_token_expire_minutes = val.parse().map_err(|_| {
                AuthError::ConfigError("Invalid ACCESS_TOKEN_EXPIRE_MINUTES".to_string())
            })?;
        }
        if let Ok(val) = std::env::var("REFRESH_TOKEN_EXPIRE_DAYS") {
            config.refresh_token_expire_days = val.parse().map_err(|_| {
                AuthError::ConfigError("Invalid REFRESH_TOKEN_EXPIRE_DAYS".to_string())
            })?;
        }
        if let Ok(val) = std::env::var("ENABLE_MAGIC_LOGIN") {
            config.enable_magic_login = val.parse().unwrap_or(false);
        }
        if let Ok(val) = std::env::var("OTP_LENGTH") {
            config.otp_length = val
                .parse()
                .map_err(|_| AuthError::ConfigError("Invalid OTP_LENGTH".to_string()))?;
        }

        if let Ok(val) = std::env::var("STORAGE_TYPE") {
            config.storage_type = match val.to_lowercase().as_str() {
                "memory" => StorageType::Memory,
                "redis" => StorageType::Redis,
                _ => {
                    return Err(AuthError::ConfigError(
                        "Invalid STORAGE_TYPE: must be 'memory' or 'redis'".to_string(),
                    ))
                }
            };
        }

        let redis_host = std::env::var("REDIS_HOST")
            .map_err(|_| AuthError::ConfigError("REDIS_HOST must be set".to_string()))?;
        let redis_port = std::env::var("REDIS_PORT")
            .map_err(|_| AuthError::ConfigError("REDIS_PORT must be set".to_string()))?;

        config.redis_url = format!("redis://{}:{}/", redis_host, redis_port);

        let smtp_host = std::env::var("SMTP_HOST")
            .map_err(|_| AuthError::ConfigError("SMTP_HOST must be set".to_string()))?;
        config.smtp_server = smtp_host;

        let smtp_port = std::env::var("SMTP_PORT")
            .map_err(|_| AuthError::ConfigError("SMTP_PORT must be set".to_string()))?;
        config.smtp_port = smtp_port
            .parse()
            .map_err(|_| AuthError::ConfigError("Invalid SMTP_PORT".to_string()))?;

        if let Ok(val) = std::env::var("SMTP_STARTTLS") {
            config.smtp_starttls = val.parse().unwrap_or(true);
        }

        if let Ok(val) = std::env::var("SMTP_USERNAME") {
            config.smtp_username = val;
        }
        if let Ok(val) = std::env::var("SMTP_PASSWORD") {
            config.smtp_password = val;
        }
        let mail_from = std::env::var("SMTP_MAIL_FROM")
            .map_err(|_| AuthError::ConfigError("SMTP_MAIL_FROM must be set".to_string()))?;
        config.mail_from = mail_from;

        let mail_from_name = std::env::var("SMTP_MAIL_FROM_NAME")
            .map_err(|_| AuthError::ConfigError("SMTP_MAIL_FROM_NAME must be set".to_string()))?;
        config.mail_from_name = mail_from_name;

        if let Ok(val) = std::env::var("JWT_AUTH_REFRESH_COOKIE") {
            config.refresh_cookie_name = val;
        }
        if let Ok(val) = std::env::var("JWT_AUTH_COOKIE_DOMAIN") {
            config.refresh_cookie_domain = Some(val);
        }
        if let Ok(val) = std::env::var("JWT_AUTH_REFRESH_COOKIE_PATH") {
            config.refresh_cookie_path = val;
        }
        if let Ok(val) = std::env::var("JWT_AUTH_COOKIE_SECURE") {
            config.refresh_cookie_secure = val.parse().unwrap_or(true);
        }
        if let Ok(val) = std::env::var("JWT_AUTH_COOKIE_SAMESITE") {
            config.refresh_cookie_same_site = val;
        }

        Ok(config)
    }
}
