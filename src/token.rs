use crate::config::AuthConfig;
use crate::errors::AuthError;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub jti: String,
    pub typ: String, // "access" or "refresh"
}

pub struct TokenService {
    config: AuthConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl TokenService {
    pub fn new(config: AuthConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());
        Self {
            config,
            encoding_key,
            decoding_key,
        }
    }

    pub fn create_access_token(&self, email: &str) -> Result<String, AuthError> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::minutes(self.config.access_token_expire_minutes))
            .expect("valid timestamp")
            .timestamp() as usize;

        let claims = Claims {
            sub: email.to_string(),
            exp: expiration,
            jti: Uuid::new_v4().to_string(),
            typ: "access".to_string(),
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)?;
        Ok(token)
    }

    pub fn create_refresh_token(&self, email: &str) -> Result<String, AuthError> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::days(self.config.refresh_token_expire_days))
            .expect("valid timestamp")
            .timestamp() as usize;

        let claims = Claims {
            sub: email.to_string(),
            exp: expiration,
            jti: Uuid::new_v4().to_string(),
            typ: "refresh".to_string(),
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)?;
        Ok(token)
    }

    pub fn verify_token(&self, token: &str, expected_type: &str) -> Result<Claims, AuthError> {
        let validation = Validation::new(self.config.jwt_algorithm);
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;

        if token_data.claims.typ != expected_type {
            return Err(AuthError::TokenError(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidToken,
            )));
        }

        Ok(token_data.claims)
    }
}
