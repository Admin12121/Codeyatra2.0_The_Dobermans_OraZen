use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json;
use sqlx::Row;
use uuid::Uuid;

use super::AppState;
use crate::middleware::{ErrorResponse, require_session_from_headers};
use crate::utils::encryption;


#[derive(Debug, Deserialize)]
pub struct CreateModelConfigRequest {
    pub name: String,
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub settings: Option<serde_json::Value>,
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateModelConfigRequest {
    pub name: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub settings: Option<serde_json::Value>,
    #[serde(default)]
    pub clear_api_key: bool,
    #[serde(default)]
    pub clear_base_url: bool,
}

#[derive(Debug, Serialize)]
pub struct ModelConfigItem {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub provider: String,
    pub model: String,
    pub base_url: Option<String>,
    pub settings: Option<serde_json::Value>,
    pub is_default: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ListModelConfigsResponse {
    pub models: Vec<ModelConfigItem>,
}

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub success: bool,
}


async fn get_user_org_id(
    db: &sqlx::PgPool,
    user_id: &str,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let row =
        sqlx::query("SELECT organization_id FROM organization_member WHERE user_id = $1 LIMIT 1")
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
                "Organization not found",
                "ORG_NOT_FOUND",
            )),
        )),
    }
}

pub async fn create_model_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateModelConfigRequest>,
) -> Result<Json<ModelConfigItem>, (StatusCode, Json<ErrorResponse>)> {
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
                "Model name cannot be empty",
                "INVALID_NAME",
            )),
        ));
    }

    if req.is_default {
        let _ =
            sqlx::query("UPDATE model_config SET is_default = FALSE WHERE organization_id = $1")
                .bind(org_id)
                .execute(&state.db)
                .await;
    }

    // Encrypt the model API key if provided
    let encrypted_api_key = match &req.api_key {
        Some(key) if !key.is_empty() => {
            let encrypted = encryption::encrypt(key).map_err(|e| {
                tracing::error!("Failed to encrypt model API key: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::new(
                        "Failed to encrypt API key",
                        "ENCRYPTION_FAILED",
                    )),
                )
            })?;
            Some(encrypted)
        }
        _ => None,
    };

    let row = sqlx::query(
        r#"
        INSERT INTO model_config (organization_id, name, provider, model, api_key_encrypted, base_url, settings, is_default)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, organization_id, name, provider, model, base_url, settings, is_default, created_at, updated_at
        "#
    )
    .bind(org_id)
    .bind(&req.name)
    .bind(&req.provider)
    .bind(&req.model)
    .bind(&encrypted_api_key)
    .bind(&req.base_url)
    .bind(&req.settings)
    .bind(req.is_default)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create model config: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(
            "Failed to create model configuration", "DB_INSERT_FAILED"
        )))
    })?;

    Ok(Json(ModelConfigItem {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        name: row.get("name"),
        provider: row.get("provider"),
        model: row.get("model"),
        base_url: row.get("base_url"),
        settings: row.get("settings"),
        is_default: row.get("is_default"),
        created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
        updated_at: row.get::<chrono::NaiveDateTime, _>("updated_at").and_utc(),
    }))
}

pub async fn list_model_configs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListModelConfigsResponse>, (StatusCode, Json<ErrorResponse>)> {
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
        SELECT id, organization_id, name, provider, model, base_url, settings, is_default, created_at, updated_at
        FROM model_config
        WHERE organization_id = $1
        ORDER BY created_at DESC
        "#
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to list model configs: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(
            "Failed to list model configurations", "DB_QUERY_FAILED"
        )))
    })?;

    let models: Vec<ModelConfigItem> = rows
        .into_iter()
        .map(|row| ModelConfigItem {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            name: row.get("name"),
            provider: row.get("provider"),
            model: row.get("model"),
            base_url: row.get("base_url"),
            settings: row.get("settings"),
            is_default: row.get("is_default"),
            created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
            updated_at: row.get::<chrono::NaiveDateTime, _>("updated_at").and_utc(),
        })
        .collect();

    Ok(Json(ListModelConfigsResponse { models }))
}

pub async fn delete_model_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(model_id): Path<Uuid>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    let result = sqlx::query("DELETE FROM model_config WHERE id = $1 AND organization_id = $2")
        .bind(model_id)
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete model config: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "Failed to delete model configuration",
                    "DB_DELETE_FAILED",
                )),
            )
        })?;

    Ok(Json(DeleteResponse {
        success: result.rows_affected() > 0,
    }))
}

pub async fn update_model_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(model_id): Path<Uuid>,
    Json(req): Json<UpdateModelConfigRequest>,
) -> Result<Json<ModelConfigItem>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    let existing = sqlx::query(
        "SELECT id, name, provider, model, api_key_encrypted, base_url, settings FROM model_config WHERE id = $1 AND organization_id = $2",
    )
    .bind(model_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch model config for update: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error", "DB_ERROR")),
        )
    })?;

    let existing = existing.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "Model configuration not found",
                "MODEL_NOT_FOUND",
            )),
        )
    })?;
    let new_name = req
        .name
        .unwrap_or_else(|| existing.get::<String, _>("name"));
    let new_provider = req
        .provider
        .unwrap_or_else(|| existing.get::<String, _>("provider"));
    let new_model = req
        .model
        .unwrap_or_else(|| existing.get::<String, _>("model"));

    if new_name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Model name cannot be empty",
                "INVALID_NAME",
            )),
        ));
    }

    let new_base_url: Option<String> = if req.clear_base_url {
        None
    } else if let Some(url) = req.base_url {
        if url.is_empty() { None } else { Some(url) }
    } else {
        existing.get::<Option<String>, _>("base_url")
    };

    let new_settings: Option<serde_json::Value> = if let Some(s) = req.settings {
        Some(s)
    } else {
        existing.get::<Option<serde_json::Value>, _>("settings")
    };

    let new_encrypted_api_key: Option<String> = if req.clear_api_key {
        None
    } else if let Some(ref key) = req.api_key {
        if key.is_empty() {
            None
        } else {
            let encrypted = encryption::encrypt(key).map_err(|e| {
                tracing::error!("Failed to encrypt model API key: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::new(
                        "Failed to encrypt API key",
                        "ENCRYPTION_FAILED",
                    )),
                )
            })?;
            Some(encrypted)
        }
    } else {
        existing.get::<Option<String>, _>("api_key_encrypted")
    };

    let row = sqlx::query(
        r#"
        UPDATE model_config
        SET name = $1, provider = $2, model = $3, api_key_encrypted = $4,
            base_url = $5, settings = $6, updated_at = NOW()
        WHERE id = $7 AND organization_id = $8
        RETURNING id, organization_id, name, provider, model, base_url, settings, is_default, created_at, updated_at
        "#,
    )
    .bind(&new_name)
    .bind(&new_provider)
    .bind(&new_model)
    .bind(&new_encrypted_api_key)
    .bind(&new_base_url)
    .bind(&new_settings)
    .bind(model_id)
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update model config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to update model configuration",
                "DB_UPDATE_FAILED",
            )),
        )
    })?;

    Ok(Json(ModelConfigItem {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        name: row.get("name"),
        provider: row.get("provider"),
        model: row.get("model"),
        base_url: row.get("base_url"),
        settings: row.get("settings"),
        is_default: row.get("is_default"),
        created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
        updated_at: row.get::<chrono::NaiveDateTime, _>("updated_at").and_utc(),
    }))
}

pub async fn set_default_model(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(model_id): Path<Uuid>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    let _ = sqlx::query("UPDATE model_config SET is_default = FALSE WHERE organization_id = $1")
        .bind(org_id)
        .execute(&state.db)
        .await;

    let result = sqlx::query(
        "UPDATE model_config SET is_default = TRUE WHERE id = $1 AND organization_id = $2",
    )
    .bind(model_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to set default model: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to set default model",
                "DB_UPDATE_FAILED",
            )),
        )
    })?;

    Ok(Json(DeleteResponse {
        success: result.rows_affected() > 0,
    }))
}
