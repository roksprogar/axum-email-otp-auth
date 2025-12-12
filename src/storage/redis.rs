use crate::errors::AuthError;
use crate::storage::Storage;
use async_trait::async_trait;
use redis::AsyncCommands;

pub struct RedisStorage {
    client: redis::Client,
}

impl RedisStorage {
    pub fn new(redis_url: &str) -> Result<Self, AuthError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Storage for RedisStorage {
    async fn set_otp(&self, email: &str, otp: &str, expiry_seconds: u64) -> Result<(), AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("otp:{}", email);
        conn.set_ex::<_, _, ()>(key, otp, expiry_seconds).await?;
        Ok(())
    }

    async fn get_otp(&self, email: &str) -> Result<Option<String>, AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("otp:{}", email);
        let otp: Option<String> = conn.get(key).await?;
        Ok(otp)
    }

    async fn delete_otp(&self, email: &str) -> Result<(), AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("otp:{}", email);
        conn.del::<_, ()>(key).await?;
        Ok(())
    }

    async fn increment_attempts(&self, email: &str, expiry_seconds: u64) -> Result<u32, AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("attempts:{}", email);
        let attempts: u32 = conn.incr(&key, 1).await?;
        if attempts == 1 {
            conn.expire::<_, ()>(&key, expiry_seconds as i64).await?;
        }
        Ok(attempts)
    }

    async fn get_attempts(&self, email: &str) -> Result<u32, AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("attempts:{}", email);
        let attempts: Option<u32> = conn.get(key).await?;
        Ok(attempts.unwrap_or(0))
    }

    async fn clear_attempts(&self, email: &str) -> Result<(), AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("attempts:{}", email);
        conn.del::<_, ()>(key).await?;
        Ok(())
    }

    async fn increment_rate_limit(&self, key: &str, expiry_seconds: u64) -> Result<u32, AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let count: u32 = conn.incr(key, 1).await?;
        if count == 1 {
            conn.expire::<_, ()>(key, expiry_seconds as i64).await?;
        }
        Ok(count)
    }

    async fn blacklist_token(&self, jti: &str, ttl_seconds: u64) -> Result<(), AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("blacklist:{}", jti);
        conn.set_ex::<_, _, ()>(key, "revoked", ttl_seconds).await?;
        Ok(())
    }

    async fn is_token_blacklisted(&self, jti: &str) -> Result<bool, AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("blacklist:{}", jti);
        let exists: bool = conn.exists(key).await?;
        Ok(exists)
    }
}
