use axum::{
    Json,
    http::{StatusCode, header},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::utils::hash_api_key;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardScannerEntry {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold")]
    pub threshold: f32,
    #[serde(default)]
    pub settings_json: String,
}

fn default_true() -> bool {
    true
}

fn default_threshold() -> f32 {
    0.5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    pub scan_mode: String,
    #[serde(default)]
    pub input_scanners: std::collections::HashMap<String, GuardScannerEntry>,
    #[serde(default)]
    pub output_scanners: std::collections::HashMap<String, GuardScannerEntry>,
    #[serde(default)]
    pub sanitize: bool,
    #[serde(default)]
    pub fail_fast: bool,
}

#[derive(Debug, Clone)]
pub struct ApiKeyInfo {
    pub id: uuid::Uuid,
    pub organization_id: uuid::Uuid,
    #[allow(dead_code)]
    pub scopes: Vec<String>,
    pub rate_limit_rpm: i32,
    pub guard_config: Option<GuardConfig>,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub session_id: String,
}

#[derive(Serialize, Clone)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ErrorResponse {
    pub fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

async fn validate_api_key(pool: &PgPool, api_key: &str) -> Result<ApiKeyInfo, String> {
    let key_hash = hash_api_key(api_key);

    let result = sqlx::query(
        r#"
        UPDATE api_key
        SET last_used_at = NOW()
        WHERE key_hash = $1
          AND (expires_at IS NULL OR expires_at > NOW())
          AND revoked_at IS NULL
        RETURNING id, organization_id, scopes, rate_limit_rpm, guard_config
        "#,
    )
    .bind(&key_hash)
    .fetch_optional(pool)
    .await;

    match result {
        Ok(Some(row)) => {
            use sqlx::Row;

            let guard_config: Option<GuardConfig> = row
                .get::<Option<serde_json::Value>, _>("guard_config")
                .and_then(|v| serde_json::from_value(v).ok());

            Ok(ApiKeyInfo {
                id: row.get("id"),
                organization_id: row.get("organization_id"),
                scopes: row
                    .get::<Option<Vec<String>>, _>("scopes")
                    .unwrap_or_default(),
                rate_limit_rpm: row.get::<Option<i32>, _>("rate_limit_rpm").unwrap_or(60),
                guard_config,
            })
        }
        Ok(None) => Err("Invalid API key".to_string()),
        Err(e) => Err(format!("Database error: {}", e)),
    }
}

async fn validate_session(db: &PgPool, token: &str) -> Result<AuthenticatedUser, String> {
    let result = sqlx::query(
        r#"
        SELECT
            s.id as session_id,
            s.user_id,
            u.email,
            u.name
        FROM session s
        JOIN "user" u ON s.user_id = u.id
        WHERE s.token = $1
          AND s.expires_at > NOW()
        "#,
    )
    .bind(token)
    .fetch_optional(db)
    .await;

    match result {
        Ok(Some(row)) => {
            use sqlx::Row;
            Ok(AuthenticatedUser {
                session_id: row.get("session_id"),
                user_id: row.get("user_id"),
                email: row.get("email"),
                name: row.get("name"),
            })
        }
        Ok(None) => Err("Invalid or expired session".to_string()),
        Err(e) => Err(format!("Database error: {}", e)),
    }
}

pub async fn require_session_from_headers(
    db: &PgPool,
    headers: &axum::http::HeaderMap,
) -> Result<AuthenticatedUser, (StatusCode, Json<ErrorResponse>)> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "Session token required. Please log in.",
                    "SESSION_REQUIRED",
                )),
            ));
        }
    };

    validate_session(db, token).await.map_err(|err| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(err, "SESSION_INVALID")),
        )
    })
}

pub async fn require_api_key_from_headers(
    db: &PgPool,
    headers: &axum::http::HeaderMap,
) -> Result<ApiKeyInfo, (StatusCode, Json<ErrorResponse>)> {
    let token = headers
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
        });

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "API key required. Use X-API-Key header or Authorization: Bearer <key>",
                    "API_KEY_REQUIRED",
                )),
            ));
        }
    };

    validate_api_key(db, token).await.map_err(|err| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(err, "API_KEY_INVALID")),
        )
    })
}
