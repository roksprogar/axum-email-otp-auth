use crate::errors::AuthError;
use async_trait::async_trait;

pub mod memory;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Storage: Send + Sync {
    async fn set_otp(&self, email: &str, otp: &str, expiry_seconds: u64) -> Result<(), AuthError>;
    async fn get_otp(&self, email: &str) -> Result<Option<String>, AuthError>;
    async fn delete_otp(&self, email: &str) -> Result<(), AuthError>;

    async fn increment_attempts(&self, email: &str, expiry_seconds: u64) -> Result<u32, AuthError>;
    async fn get_attempts(&self, email: &str) -> Result<u32, AuthError>;
    async fn clear_attempts(&self, email: &str) -> Result<(), AuthError>;

    async fn increment_rate_limit(&self, key: &str, expiry_seconds: u64) -> Result<u32, AuthError>;

    async fn blacklist_token(&self, jti: &str, ttl_seconds: u64) -> Result<(), AuthError>;
    async fn is_token_blacklisted(&self, jti: &str) -> Result<bool, AuthError>;
}

pub mod redis;
pub use self::memory::InMemoryStorage;
pub use self::redis::RedisStorage;
