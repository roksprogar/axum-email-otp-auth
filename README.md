# OTP Email Auth

# OTP Email Auth

A production-ready, framework-agnostic Rust library for OTP email authentication, providing a complete "batteries-included" authentication solution.

## Key Benefits

*   **Production Ready**: Built with industry-standard security practices (JWTs, secure cookies, constant-time comparisons).
*   **Framework Agnostic**: The core logic is decoupled from any web framework. Use it with Axum, Actix Web, Rocket, or purely as a library.
*   **Batteries Included**: Comes with built-in optional support for **Axum**, providing ready-to-use handlers and middleware.
*   **Type Safe**: Leveraging Rust's strong type system to make invalid authentication states unrepresentable.
*   **Async First**: Built on top of `tokio` for high-performance non-blocking I/O.

## Features

- **Core Logic**: Complete implementation of OTP generation, Redis storage, Email sending (via Lettre), and JWT token management.
- **Secure Cookie Management**: Direct integration with `tower-cookies` for setting secure, HTTP-only refresh tokens.
- **Magic Login**: Developer-friendly "Magic OTP" mode for local testing without sending real emails.
- **Configurable**: Highly configurable via `AuthConfig` struct (environment variables, custom settings).

## Local Development / Magic OTP

To simplify local development, you can disable the actual email sending and use a fixed OTP code ("000000").

1.  Set `DISABLE_LOCAL_AUTH=true` in your environment variables.
2.  The library will now:
    -   Skip sending emails via SMTP.
    -   Accept **"000000"** as the valid OTP for any email address.

This allows you to login locally without needing to check a mailpit/inbox.

## Configuration via Environment Variables

### Configuration

The library is configured via environment variables.

#### Core Settings
*   `JWT_SECRET`: Secret key for signing JWTs (Required in production)
*   `ACCESS_TOKEN_EXPIRE_MINUTES`: Access token validity duration (default: 30)
*   `REFRESH_TOKEN_EXPIRE_DAYS`: Refresh token validity duration (default: 7)
*   `OTP_EXPIRY_SECONDS`: OTP validity duration (default: 300)
*   `ENABLE_MAGIC_LOGIN`: If set to `true`, OTP generation is skipped and the code `000000` is accepted (skips email sending). Default: `false` (Secure/Send Email).

#### Redis Configuration
*   `REDIS_HOST`: Hostname of the Redis server (Required)
*   `REDIS_PORT`: Port of the Redis server (Required)

#### Cookie Configuration (Optional)
*   `JWT_AUTH_REFRESH_COOKIE`: Name of the refresh token cookie (default: "refresh_token")
*   `JWT_AUTH_COOKIE_DOMAIN`: Domain for the cookie (optional)
*   `JWT_AUTH_COOKIE_PATH`: Path for the cookie (default: "/")
*   `JWT_AUTH_COOKIE_SECURE`: Secure flag (default: true)
*   `JWT_AUTH_COOKIE_SAMESITE`: SameSite policy (default: "Lax")

#### SMTP Configuration
Required if `ENABLE_MAGIC_LOGIN` is false (default).

*   `SMTP_HOST`: SMTP server hostname (Required)
*   `SMTP_PORT`: SMTP server port (Required)
*   `SMTP_USERNAME`: SMTP username (Optional)
*   `SMTP_PASSWORD`: SMTP password (Optional)
*   `SMTP_MAIL_FROM`: Email address to send from (Required)
*   `SMTP_MAIL_FROM_NAME`: Name to send from (Required)

**Note on Redis Config**: You must use `REDIS_HOST` and `REDIS_PORT` to configure the Redis connection. If omitted, it defaults to `redis://127.0.0.1:1025/`.

## Usage

### Core Usage

```rust,ignore
use axum_email_otp_auth::{AuthConfig, AuthService, RedisStorage, LettreEmailSender};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let config = AuthConfig::default();
    let storage = Arc::new(RedisStorage::new(&config.redis_url).unwrap());
    let email_sender = Arc::new(LettreEmailSender::new(&config));
    
    let auth_service = AuthService::new(config, storage, email_sender);
    
    // Request OTP
    auth_service.request_otp("user@example.com").await.unwrap();
    
    // Verify OTP
    let tokens = auth_service.verify_otp("user@example.com", "123456").await.unwrap();
}
```

### Axum Usage

Add `axum` feature to `Cargo.toml`:
```toml
[dependencies]
axum-email-otp-auth = { path = "...", features = ["axum"] }
```

```rust,ignore
use axum_email_otp_auth::axum_api::auth_router;
use axum_email_otp_auth::tower_cookies::CookieManagerLayer;
use axum::Router;

let app = Router::new()
    .nest("/auth", auth_router(Arc::new(auth_service)))
    .layer(CookieManagerLayer::new());
```



## Testing

Run tests with:

```bash
cargo test
```
