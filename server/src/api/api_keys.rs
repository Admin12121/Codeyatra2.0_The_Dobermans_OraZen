use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use super::AppState;
use crate::middleware::auth::GuardConfig;
use crate::middleware::{ErrorResponse, require_session_from_headers};
use crate::utils::{generate_api_key, hash_api_key};

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub guard_config: Option<GuardConfig>,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub key: String,
    pub prefix: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub guard_config: Option<GuardConfig>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyItem {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Option<Vec<String>>,
    pub rate_limit_rpm: Option<i32>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub guard_config: Option<GuardConfig>,
}

#[derive(Debug, Serialize)]
pub struct ListApiKeysResponse {
    pub keys: Vec<ApiKeyItem>,
}

#[derive(Debug, Serialize)]
pub struct RevokeApiKeyResponse {
    pub success: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateGuardConfigRequest {
    pub guard_config: Option<GuardConfig>,
}

#[derive(Debug, Serialize)]
pub struct UpdateGuardConfigResponse {
    pub success: bool,
    pub guard_config: Option<GuardConfig>,
}

#[derive(Debug, Serialize)]
pub struct GetGuardConfigResponse {
    pub key_id: Uuid,
    pub key_name: String,
    pub guard_config: Option<GuardConfig>,
}

async fn get_user_org_id(
    db: &sqlx::PgPool,
    user_id: &str,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let row = sqlx::query(
        r#"
        SELECT om.organization_id
        FROM organization_member om
        WHERE om.user_id = $1
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                format!("Database error: {}", e),
                "DB_ERROR",
            )),
        )
    })?;

    match row {
        Some(r) => Ok(r.get("organization_id")),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "Organization not found. Create one first.",
                "ORG_NOT_FOUND",
            )),
        )),
    }
}

fn validate_guard_config(config: &GuardConfig) -> Result<(), String> {
    match config.scan_mode.as_str() {
        "prompt_only" | "output_only" | "both" => {}
        other => {
            return Err(format!(
                "Invalid scan_mode '{}'. Must be one of: prompt_only, output_only, both",
                other
            ));
        }
    }

    for (name, entry) in &config.input_scanners {
        if entry.threshold < 0.0 || entry.threshold > 1.0 {
            return Err(format!(
                "Input scanner '{}' threshold {} is out of range [0.0, 1.0]",
                name, entry.threshold
            ));
        }
    }
    for (name, entry) in &config.output_scanners {
        if entry.threshold < 0.0 || entry.threshold > 1.0 {
            return Err(format!(
                "Output scanner '{}' threshold {} is out of range [0.0, 1.0]",
                name, entry.threshold
            ));
        }
    }

    Ok(())
}

pub async fn create_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    if req.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "API key name cannot be empty",
                "INVALID_NAME",
            )),
        ));
    }

    if let Some(ref gc) = req.guard_config {
        validate_guard_config(gc).map_err(|msg| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(msg, "INVALID_GUARD_CONFIG")),
            )
        })?;
    }

    let (key, prefix) = generate_api_key();
    let key_hash = hash_api_key(&key);

    let guard_config_json: Option<serde_json::Value> = req
        .guard_config
        .as_ref()
        .map(|gc| serde_json::to_value(gc).unwrap());

    let row = sqlx::query(
        r#"
        INSERT INTO api_key (organization_id, name, key_prefix, key_hash, scopes, created_by, guard_config)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, created_at
        "#,
    )
    .bind(org_id)
    .bind(&req.name)
    .bind(&prefix)
    .bind(&key_hash)
    .bind(&req.scopes)
    .bind(&user.user_id)
    .bind(&guard_config_json)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create API key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to create API key",
                "DB_INSERT_FAILED",
            )),
        )
    })?;

    let id: Uuid = row.get("id");
    let created_at: chrono::NaiveDateTime = row.get("created_at");

    Ok(Json(CreateApiKeyResponse {
        id,
        key,
        prefix,
        name: req.name,
        scopes: req.scopes,
        guard_config: req.guard_config,
        created_at: created_at.and_utc(),
    }))
}

pub async fn list_api_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListApiKeysResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, name, key_prefix, scopes, rate_limit_rpm,
               last_used_at, expires_at, revoked_at, created_by, created_at,
               guard_config
        FROM api_key
        WHERE organization_id = $1 AND revoked_at IS NULL
        ORDER BY created_at DESC
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to list API keys: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to list API keys",
                "DB_QUERY_FAILED",
            )),
        )
    })?;

    let keys: Vec<ApiKeyItem> = rows
        .into_iter()
        .map(|row| {
            let guard_config: Option<GuardConfig> = row
                .get::<Option<serde_json::Value>, _>("guard_config")
                .and_then(|v| serde_json::from_value(v).ok());

            ApiKeyItem {
                id: row.get("id"),
                organization_id: row.get("organization_id"),
                name: row.get("name"),
                key_prefix: row.get("key_prefix"),
                scopes: row.get("scopes"),
                rate_limit_rpm: row.get("rate_limit_rpm"),
                last_used_at: row
                    .get::<Option<chrono::NaiveDateTime>, _>("last_used_at")
                    .map(|dt| dt.and_utc()),
                expires_at: row
                    .get::<Option<chrono::NaiveDateTime>, _>("expires_at")
                    .map(|dt| dt.and_utc()),
                revoked_at: row
                    .get::<Option<chrono::NaiveDateTime>, _>("revoked_at")
                    .map(|dt| dt.and_utc()),
                created_by: row.get("created_by"),
                created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
                guard_config,
            }
        })
        .collect();

    Ok(Json(ListApiKeysResponse { keys }))
}

pub async fn revoke_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(key_id): axum::extract::Path<Uuid>,
) -> Result<Json<RevokeApiKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    let result = sqlx::query(
        r#"
        UPDATE api_key
        SET revoked_at = NOW()
        WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(key_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to revoke API key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to revoke API key",
                "DB_UPDATE_FAILED",
            )),
        )
    })?;

    Ok(Json(RevokeApiKeyResponse {
        success: result.rows_affected() > 0,
    }))
}

pub async fn update_guard_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(key_id): axum::extract::Path<Uuid>,
    Json(req): Json<UpdateGuardConfigRequest>,
) -> Result<Json<UpdateGuardConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    if let Some(ref gc) = req.guard_config {
        validate_guard_config(gc).map_err(|msg| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(msg, "INVALID_GUARD_CONFIG")),
            )
        })?;
    }

    let guard_config_json: Option<serde_json::Value> = req
        .guard_config
        .as_ref()
        .map(|gc| serde_json::to_value(gc).unwrap());

    let result = sqlx::query(
        r#"
        UPDATE api_key
        SET guard_config = $1
        WHERE id = $2 AND organization_id = $3 AND revoked_at IS NULL
        "#,
    )
    .bind(&guard_config_json)
    .bind(key_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update guard config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to update guard config",
                "DB_UPDATE_FAILED",
            )),
        )
    })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "API key not found or already revoked",
                "KEY_NOT_FOUND",
            )),
        ));
    }

    Ok(Json(UpdateGuardConfigResponse {
        success: true,
        guard_config: req.guard_config,
    }))
}


pub async fn get_guard_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(key_id): axum::extract::Path<Uuid>,
) -> Result<Json<GetGuardConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    let row = sqlx::query(
        r#"
        SELECT id, name, guard_config
        FROM api_key
        WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(key_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to get guard config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to get guard config",
                "DB_QUERY_FAILED",
            )),
        )
    })?;

    match row {
        Some(r) => {
            let guard_config: Option<GuardConfig> = r
                .get::<Option<serde_json::Value>, _>("guard_config")
                .and_then(|v| serde_json::from_value(v).ok());

            Ok(Json(GetGuardConfigResponse {
                key_id: r.get("id"),
                key_name: r.get("name"),
                guard_config,
            }))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "API key not found or already revoked",
                "KEY_NOT_FOUND",
            )),
        )),
    }
}
