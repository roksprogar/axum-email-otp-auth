#![doc = include_str!("../README.md")]

#[cfg(feature = "axum")]
pub use tower_cookies;

#[cfg(feature = "axum")]
pub mod axum_api;
pub mod config;
pub mod cron;
pub mod email;
pub mod errors;
pub mod rate_limit;
pub mod service;
pub mod storage;
pub mod token;

pub use config::{AuthConfig, StorageType};
pub use email::{EmailSender, LettreEmailSender};
pub use errors::AuthError;
pub use service::AuthService;
pub use storage::{InMemoryStorage, RedisStorage, Storage};
