use crate::errors::AuthError;
use crate::storage::Storage;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
struct OtpEntry {
    otp: String,
    expiry: u64, // Unix timestamp
}

#[derive(Clone)]
struct AttemptsEntry {
    count: u32,
    expiry: u64,
}

#[derive(Clone)]
struct RateLimitEntry {
    count: u32,
    start_window: u64,
}

#[derive(Clone)]
struct BlacklistEntry {
    expiry: u64,
}

pub struct InMemoryStorage {
    otps: Arc<RwLock<HashMap<String, OtpEntry>>>,
    attempts: Arc<RwLock<HashMap<String, AttemptsEntry>>>,
    rate_limits: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    blacklist: Arc<RwLock<HashMap<String, BlacklistEntry>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            otps: Arc::new(RwLock::new(HashMap::new())),
            attempts: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            blacklist: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Storage for InMemoryStorage {
    async fn set_otp(&self, email: &str, otp: &str, expiry_seconds: u64) -> Result<(), AuthError> {
        let mut map = self
            .otps
            .write()
            .map_err(|_| AuthError::StorageError("Lock poisoned".into()))?;
        map.insert(
            email.to_string(),
            OtpEntry {
                otp: otp.to_string(),
                expiry: Self::now() + expiry_seconds,
            },
        );
        Ok(())
    }

    async fn get_otp(&self, email: &str) -> Result<Option<String>, AuthError> {
        let map = self
            .otps
            .read()
            .map_err(|_| AuthError::StorageError("Lock poisoned".into()))?;
        if let Some(entry) = map.get(email) {
            if entry.expiry > Self::now() {
                return Ok(Some(entry.otp.clone()));
            }
        }
        Ok(None)
    }

    async fn delete_otp(&self, email: &str) -> Result<(), AuthError> {
        let mut map = self
            .otps
            .write()
            .map_err(|_| AuthError::StorageError("Lock poisoned".into()))?;
        map.remove(email);
        Ok(())
    }

    async fn increment_attempts(&self, email: &str, expiry_seconds: u64) -> Result<u32, AuthError> {
        let mut map = self
            .attempts
            .write()
            .map_err(|_| AuthError::StorageError("Lock poisoned".into()))?;
        let now = Self::now();

        let entry = map.entry(email.to_string()).or_insert(AttemptsEntry {
            count: 0,
            expiry: now + expiry_seconds,
        });

        if now > entry.expiry {
            entry.count = 1;
            entry.expiry = now + expiry_seconds;
        } else {
            entry.count += 1;
        }

        Ok(entry.count)
    }

    async fn get_attempts(&self, email: &str) -> Result<u32, AuthError> {
        let map = self
            .attempts
            .read()
            .map_err(|_| AuthError::StorageError("Lock poisoned".into()))?;
        if let Some(entry) = map.get(email) {
            if entry.expiry > Self::now() {
                return Ok(entry.count);
            }
        }
        Ok(0)
    }

    async fn clear_attempts(&self, email: &str) -> Result<(), AuthError> {
        let mut map = self
            .attempts
            .write()
            .map_err(|_| AuthError::StorageError("Lock poisoned".into()))?;
        map.remove(email);
        Ok(())
    }

    async fn increment_rate_limit(&self, key: &str, window_seconds: u64) -> Result<u32, AuthError> {
        let mut map = self
            .rate_limits
            .write()
            .map_err(|_| AuthError::StorageError("Lock poisoned".into()))?;
        let now = Self::now();

        let entry = map.entry(key.to_string()).or_insert(RateLimitEntry {
            count: 0,
            start_window: now,
        });

        if now > entry.start_window + window_seconds {
            entry.count = 1;
            entry.start_window = now;
        } else {
            entry.count += 1;
        }

        Ok(entry.count)
    }

    async fn blacklist_token(&self, jti: &str, ttl_seconds: u64) -> Result<(), AuthError> {
        let mut map = self
            .blacklist
            .write()
            .map_err(|_| AuthError::StorageError("Lock poisoned".into()))?;
        map.insert(
            jti.to_string(),
            BlacklistEntry {
                expiry: Self::now() + ttl_seconds,
            },
        );
        Ok(())
    }

    async fn is_token_blacklisted(&self, jti: &str) -> Result<bool, AuthError> {
        let map = self
            .blacklist
            .read()
            .map_err(|_| AuthError::StorageError("Lock poisoned".into()))?;
        if let Some(entry) = map.get(jti) {
            if entry.expiry > Self::now() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_otp_flow() {
        let storage = InMemoryStorage::new();
        let email = "test@example.com";
        let otp = "123456";

        // Set
        storage.set_otp(email, otp, 60).await.unwrap();

        // Get
        let retrieved = storage.get_otp(email).await.unwrap();
        assert_eq!(retrieved, Some(otp.to_string()));

        // Delete
        storage.delete_otp(email).await.unwrap();
        let retrieved = storage.get_otp(email).await.unwrap();
        assert_eq!(retrieved, None);
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let storage = InMemoryStorage::new();
        let key = "limit:test";

        let count = storage.increment_rate_limit(key, 60).await.unwrap();
        assert_eq!(count, 1);

        let count = storage.increment_rate_limit(key, 60).await.unwrap();
        assert_eq!(count, 2);
    }
}
