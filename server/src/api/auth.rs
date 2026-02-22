use axum::{Json, extract::State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use super::AppState;
use crate::utils::hash_api_key;

#[derive(Debug, Deserialize)]
pub struct VerifySessionRequest {
    pub session_token: String,
}

#[derive(Debug, Serialize)]
pub struct VerifySessionResponse {
    pub valid: bool,
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyApiKeyRequest {
    pub api_key: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyApiKeyResponse {
    pub valid: bool,
    pub organization_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub rate_limit: Option<RateLimit>,
}

#[derive(Debug, Serialize)]
pub struct RateLimit {
    pub requests_per_minute: u32,
    pub requests_remaining: u32,
    pub reset_at: DateTime<Utc>,
}

pub async fn verify_session(
    State(state): State<AppState>,
    Json(req): Json<VerifySessionRequest>,
) -> Json<VerifySessionResponse> {
    let session = sqlx::query(
        r#"
        SELECT
            s.id,
            s.user_id,
            s.expires_at,
            u.email
        FROM session s
        JOIN "user" u ON s.user_id = u.id
        WHERE s.token = $1 AND s.expires_at > NOW()
        "#,
    )
    .bind(&req.session_token)
    .fetch_optional(&state.db)
    .await;

    match session {
        Ok(Some(row)) => {
            let user_id: String = row.get("user_id");
            let email: Option<String> = row.get("email");
            let expires_at: chrono::NaiveDateTime = row.get("expires_at");

            Json(VerifySessionResponse {
                valid: true,
                user_id: Some(user_id),
                email,
                expires_at: Some(expires_at.and_utc()),
            })
        }
        _ => Json(VerifySessionResponse {
            valid: false,
            user_id: None,
            email: None,
            expires_at: None,
        }),
    }
}

pub async fn verify_api_key(
    State(state): State<AppState>,
    Json(req): Json<VerifyApiKeyRequest>,
) -> Json<VerifyApiKeyResponse> {
    let key_hash = hash_api_key(&req.api_key);

    let key = sqlx::query(
        r#"
        SELECT
            ak.id,
            ak.organization_id,
            ak.scopes,
            ak.rate_limit_rpm,
            ak.expires_at
        FROM api_key ak
        WHERE ak.key_hash = $1
          AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
          AND ak.revoked_at IS NULL
        "#,
    )
    .bind(&key_hash)
    .fetch_optional(&state.db)
    .await;

    match key {
        Ok(Some(row)) => {
            let organization_id: Uuid = row.get("organization_id");
            let scopes: Option<Vec<String>> = row.get("scopes");
            let rate_limit_rpm: Option<i32> = row.get("rate_limit_rpm");

            let rate_limit = RateLimit {
                requests_per_minute: rate_limit_rpm.unwrap_or(60) as u32,
                requests_remaining: 60,
                reset_at: Utc::now(),
            };

            Json(VerifyApiKeyResponse {
                valid: true,
                organization_id: Some(organization_id),
                scopes: scopes.unwrap_or_default(),
                rate_limit: Some(rate_limit),
            })
        }
        _ => Json(VerifyApiKeyResponse {
            valid: false,
            organization_id: None,
            scopes: vec![],
            rate_limit: None,
        }),
    }
}
