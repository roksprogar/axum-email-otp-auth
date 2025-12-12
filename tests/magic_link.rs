use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use axum_email_otp_auth::{axum_api::auth_router, AuthConfig, AuthService, RedisStorage};
use serde_json::json;
use std::sync::Arc;
use tower::util::ServiceExt; // for oneshot

mod common;
use common::TestEmailSender;

#[tokio::test]
async fn test_magic_login_flow() {
    let mut auth_config = AuthConfig::from_env().unwrap_or_else(|_| AuthConfig::default());
    auth_config.enable_magic_login = true; // Enabled!
    auth_config.redis_url = "redis://127.0.0.1/".to_string();
    if let Ok(host) = std::env::var("REDIS_HOST") {
        auth_config.redis_url = format!("redis://{}:6379/", host);
    }
    if let Ok(url) = std::env::var("REDIS_URL") {
        auth_config.redis_url = url;
    }

    let storage = Arc::new(RedisStorage::new(&auth_config.redis_url).unwrap());
    let email_sender = Arc::new(TestEmailSender::new());
    let auth_service = Arc::new(AuthService::new(
        auth_config,
        storage.clone(),
        email_sender.clone(),
    ));

    let app = auth_router(auth_service).layer(tower_cookies::CookieManagerLayer::new());

    // 1. Request OTP
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/request-otp")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "email": "magic@example.com" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify NO email sent
    {
        let sent = email_sender.sent_emails.lock().unwrap();
        assert_eq!(sent.len(), 0);
    }

    // 2. Verify with "000000"
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify-otp")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "email": "magic@example.com", "otp": "000000" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
