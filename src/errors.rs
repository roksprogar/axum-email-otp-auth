use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),

    #[error("Email error: {0}")]
    EmailError(String),

    #[error("Token error: {0}")]
    TokenError(#[from] jsonwebtoken::errors::Error),

    #[error("Invalid token")]
    InvalidToken,

    #[error("Invalid OTP")]
    InvalidOtp,

    #[error("OTP expired or not requested")]
    OtpExpired,

    #[error("Too many failed attempts")]
    TooManyAttempts,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Storage error: {0}")]
    StorageError(String),
}
