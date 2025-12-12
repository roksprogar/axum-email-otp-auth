# Axum Email OTP Auth

<div align="center">

[![Crates.io](https://img.shields.io/crates/v/axum-email-otp-auth.svg)](https://crates.io/crates/axum-email-otp-auth)
[![Documentation](https://docs.rs/axum-email-otp-auth/badge.svg)](https://docs.rs/axum-email-otp-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

A production-ready, framework-agnostic Rust library for OTP (One-Time Password) email authentication, with built-in support for **Axum**.

---

## Why OTP?

Passwords are a pain. Users forget them, reuse them, and they are a prime target for attackers. Storing them securely is a liability.

**Axum Email OTP Auth** solves this by eliminating passwords entirely:

- 🧠 **No Memory Required**: Users don't need to remember complex passwords.
- 💾 **Zero Password Storage**: You don't have to worry about hashing, salting, or leaking passwords.
- 🔄 **Simplified Flows**: No more "Forgot Password" or "Reset Password" complexity.
- 🛡️ **Enhanced Security**: OTPs are short-lived and one-time use, mitigating credential stuffing and replay attacks.

## Features

- 🔐 **Secure OTP Generation**: Cryptographically secure 6-digit codes.
- ⚡ **Redis-Backed**: Fast and reliable storage for OTPs with automatic expiration.
- 📧 **Email Delivery**: Integrated email sending via `lettre`.
- 🎫 **JWT Support**: Auto-generates Access and Refresh tokens upon verification.
- 🍪 **HttpOnly Cookies**: Securely stores refresh tokens in HttpOnly cookies (with `tower-cookies`).
- 🔌 **Axum Integration**: Drop-in `Router` for quick setup.
- ⚙️ **Configurable**: Fully customizable via environment variables.
- 🦀 **Rust Native**: Type-safe, async-first, and built for performance.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
axum-email-otp-auth = { version = "0.1.0", features = ["axum"] }
```

## Configuration

The library is configured using environment variables.

### Core Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | Secret key for signing JWTs | **Required** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token lifetime | `30` |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token lifetime | `7` |
| `OTP_EXPIRY_SECONDS` | OTP validity duration | `300` (5 minutes) |
| `ENABLE_MAGIC_LOGIN` | Enable "Magic OTP" flow (skips email, accepts `000000`) | `false` |

### Redis Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_HOST` | Redis server hostname | **Required** |
| `REDIS_PORT` | Redis server port | **Required** |

### SMTP Configuration (Required if `ENABLE_MAGIC_LOGIN` is false)

| Variable | Description | Default |
|----------|-------------|---------|
| `SMTP_HOST` | SMTP server hostname | **Required** |
| `SMTP_PORT` | SMTP server port | **Required** |
| `SMTP_USERNAME` | SMTP username | `None` |
| `SMTP_PASSWORD` | SMTP password | `None` |
| `SMTP_MAIL_FROM` | Sender email address | **Required** |
| `SMTP_MAIL_FROM_NAME` | Sender name | **Required** |

## Local Development (Magic OTP)

To simplify local development and testing, you can enable the "Magic OTP" flow. This allows you to log in as **any user** using the fixed OTP code `000000`, without sending actual emails with the OTP.

1.  Set `ENABLE_MAGIC_LOGIN=true` in your **local** `.env` file environment.
2.  Request an OTP for any email (e.g., `test@example.com`).
3.  Verify using the code `000000`.

> [!WARNING]
> **Security Risk**: Ensure this environment variable is **NEVER** set to `true` in production environments.

## Usage

### 1. Setup Service

Initialize the service in your `main.rs`:

```rust
use axum_email_otp_auth::{AuthConfig, AuthService, RedisStorage, LettreEmailSender};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // 1. Load Config
    let config = AuthConfig::from_env().expect("Failed to load config");
    
    // 2. Initialize Components
    let storage = Arc::new(RedisStorage::new(&config.redis_url).unwrap());
    let email_sender = Arc::new(LettreEmailSender::new(&config));
    
    // 3. Create Service
    let auth_service = Arc::new(AuthService::new(config, storage, email_sender));
}
```

### 2. Axum Integration

Expose the API endpoints directly in your Axum router:

```rust
use axum_email_otp_auth::axum_api::auth_router;
use axum_email_otp_auth::tower_cookies::CookieManagerLayer;
use axum::Router;

let app = Router::new()
    .nest("/auth", auth_router(auth_service.clone()))
    .layer(CookieManagerLayer::new());
```

### 3. API Endpoints

Once mounted at `/auth`, the following endpoints are available:

#### Request OTP
`POST /auth/request-otp`

```json
{
  "email": "user@example.com"
}
```

#### Verify OTP
`POST /auth/verify-otp`

```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsIn...",
  "expires_in": 1800
}
```
*The secure refresh token is automatically set as an `HttpOnly` cookie.*

#### Refresh Token
`POST /auth/refresh`

(No body required, relies on the `refresh_token` cookie)

## Testing

Run the test suite with:

```bash
cargo test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [MIT License](LICENSE).
