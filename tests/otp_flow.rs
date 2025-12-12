use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use axum_email_otp_auth::Storage;
use serde_json::json;
use tower::util::ServiceExt; // for oneshot

mod common;
use common::spawn_app;

#[tokio::test]
async fn test_request_otp_success() {
    let (app, email_sender, _) = spawn_app().await;
    let email = "test_lib@example.com";

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/request-otp")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "email": email }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let sent = email_sender.sent_emails.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, email);
}

#[tokio::test]
async fn test_verify_otp_invalid() {
    let (app, _, storage) = spawn_app().await;
    let email = "test_lib_inv@example.com";

    // Manually set OTP
    storage.set_otp(email, "123456", 300).await.unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify-otp")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "email": email, "otp": "000000" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
