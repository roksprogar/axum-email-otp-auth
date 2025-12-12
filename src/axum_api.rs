#[cfg(feature = "axum")]
use crate::errors::AuthError;
#[cfg(feature = "axum")]
use crate::service::AuthService;
#[cfg(feature = "axum")]
use axum::{
    extract::{Json, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
#[cfg(feature = "axum")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "axum")]
use std::sync::Arc;

#[cfg(feature = "axum")]
#[derive(Clone)]
pub struct AppState {
    pub auth_service: Arc<AuthService>,
}

#[cfg(feature = "axum")]
#[derive(Deserialize)]
pub struct RequestOtpRequest {
    pub email: String,
}

#[cfg(feature = "axum")]
#[derive(Deserialize)]
pub struct VerifyOtpRequest {
    pub email: String,
    pub otp: String,
}

#[cfg(feature = "axum")]
#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[cfg(feature = "axum")]
#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
}

#[cfg(feature = "axum")]
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::RedisError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AuthError::EmailError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send email"),
            AuthError::TokenError(_) => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::InvalidOtp => (StatusCode::BAD_REQUEST, "Invalid OTP"),
            AuthError::OtpExpired => (StatusCode::BAD_REQUEST, "OTP expired or not requested"),
            AuthError::TooManyAttempts => {
                (StatusCode::TOO_MANY_REQUESTS, "Too many failed attempts")
            }
            AuthError::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"),
            AuthError::ConfigError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error"),
            AuthError::StorageError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Storage error"),
        };

        let body = Json(serde_json::json!({
            "error": error_message,
            "details": self.to_string(),
        }));

        (status, body).into_response()
    }
}

#[cfg(feature = "axum")]
pub async fn request_otp(
    State(state): State<AppState>,
    Json(payload): Json<RequestOtpRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    state.auth_service.request_otp(&payload.email).await?;
    Ok(Json(
        serde_json::json!({ "message": "OTP sent successfully" }),
    ))
}

#[cfg(feature = "axum")]
pub async fn verify_otp(
    State(state): State<AppState>,
    Json(payload): Json<VerifyOtpRequest>,
) -> Result<Json<TokenResponse>, AuthError> {
    let (access_token, refresh_token) = state
        .auth_service
        .verify_otp(&payload.email, &payload.otp)
        .await?;

    Ok(Json(TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
    }))
}

#[cfg(feature = "axum")]
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let access_token = state
        .auth_service
        .refresh_token(&payload.refresh_token)
        .await?;
    Ok(Json(
        serde_json::json!({ "access_token": access_token, "token_type": "Bearer" }),
    ))
}

#[cfg(feature = "axum")]
pub async fn verify_jwt(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(AuthError::InvalidToken)?;

    let claims = state.auth_service.verify_access_token(token)?;

    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}
#[cfg(feature = "axum")]
pub fn set_refresh_cookie(
    cookies: &tower_cookies::Cookies,
    refresh_token: &str,
    config: &crate::config::AuthConfig,
) {
    use tower_cookies::{cookie::time::Duration, cookie::SameSite, Cookie};

    let same_site = match config.refresh_cookie_same_site.as_str() {
        "Strict" => SameSite::Strict,
        "Lax" => SameSite::Lax,
        "None" => SameSite::None,
        _ => SameSite::Lax,
    };

    let mut cookie = Cookie::build((
        config.refresh_cookie_name.clone(),
        refresh_token.to_string(),
    ))
    .http_only(true)
    .secure(config.refresh_cookie_secure)
    .same_site(same_site)
    .path(config.refresh_cookie_path.clone())
    .max_age(Duration::days(config.refresh_token_expire_days));

    if let Some(domain) = &config.refresh_cookie_domain {
        cookie = cookie.domain(domain.clone());
    }

    cookies.add(cookie.build());
}

#[cfg(feature = "axum")]
pub fn auth_router(auth_service: Arc<AuthService>) -> Router {
    let state = AppState { auth_service };
    Router::new()
        .route("/request-otp", post(request_otp))
        .route("/verify-otp", post(verify_otp))
        .route("/refresh", post(refresh_token))
        .with_state(state)
}
