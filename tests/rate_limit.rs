use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use serde_json::json;
use tower::util::ServiceExt; // for oneshot
use uuid::Uuid;

mod common;
use common::spawn_app;

#[tokio::test]
async fn test_request_otp_rate_limit() {
    let (app, _, _) = spawn_app().await;
    let email = format!("rate_limit_{}@example.com", Uuid::new_v4());

    // 5 allowed attempts (default config)
    for _ in 0..5 {
        let response = app
            .clone()
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
    }

    // 6th attempt should fail
    let response = app
        .clone()
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

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}
