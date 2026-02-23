use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Datelike, NaiveDate, NaiveTime, Utc};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use super::AppState;
use crate::middleware::{ErrorResponse, require_session_from_headers};

#[derive(Debug, Serialize)]
pub struct OrganizationResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub owner_id: String,
    pub plan: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct OrganizationUsageResponse {
    pub organization_id: Uuid,
    pub plan: Option<String>,
    pub guard_scans_used: i64,
    pub garak_scans_used: i64,
    pub api_keys_used: i64,
    pub model_configs_used: i64,
    pub threats_blocked: i64,
    pub avg_latency_ms: i64,
    pub billing_period_start: DateTime<Utc>,
    pub billing_period_end: DateTime<Utc>,
}

pub async fn get_or_create_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OrganizationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let existing = sqlx::query(
        r#"
        SELECT o.id, o.name, o.slug, o.owner_id, o.plan, o.created_at, o.updated_at
        FROM organization o
        JOIN organization_member om ON o.id = om.organization_id
        WHERE om.user_id = $1
        LIMIT 1
        "#,
    )
    .bind(&user.user_id)
    .fetch_optional(&state.db)
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

    if let Some(row) = existing {
        return Ok(Json(OrganizationResponse {
            id: row.get("id"),
            name: row.get("name"),
            slug: row.get("slug"),
            owner_id: row.get("owner_id"),
            plan: row.get("plan"),
            created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
            updated_at: row.get::<chrono::NaiveDateTime, _>("updated_at").and_utc(),
        }));
    }

    let display_name = user.email.split('@').next().unwrap_or("user");
    let slug = format!(
        "org-{}-{}",
        &user.user_id[..8.min(user.user_id.len())],
        chrono::Utc::now().timestamp_millis()
    );
    let org_name = format!(
        "{}'s Organization",
        user.name.as_deref().unwrap_or(display_name)
    );

    let row = sqlx::query(
        r#"
        INSERT INTO organization (name, slug, owner_id)
        VALUES ($1, $2, $3)
        RETURNING id, name, slug, owner_id, plan, created_at, updated_at
        "#,
    )
    .bind(&org_name)
    .bind(&slug)
    .bind(&user.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create organization: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to create organization",
                "DB_INSERT_FAILED",
            )),
        )
    })?;

    let org_id: Uuid = row.get("id");

    let _ = sqlx::query(
        "INSERT INTO organization_member (organization_id, user_id, role) VALUES ($1, $2, 'owner')",
    )
    .bind(org_id)
    .bind(&user.user_id)
    .execute(&state.db)
    .await;

    Ok(Json(OrganizationResponse {
        id: row.get("id"),
        name: row.get("name"),
        slug: row.get("slug"),
        owner_id: row.get("owner_id"),
        plan: row.get("plan"),
        created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
        updated_at: row.get::<chrono::NaiveDateTime, _>("updated_at").and_utc(),
    }))
}

pub async fn get_current_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Option<OrganizationResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let row = sqlx::query(
        r#"
        SELECT o.id, o.name, o.slug, o.owner_id, o.plan, o.created_at, o.updated_at
        FROM organization o
        JOIN organization_member om ON o.id = om.organization_id
        WHERE om.user_id = $1
        LIMIT 1
        "#,
    )
    .bind(&user.user_id)
    .fetch_optional(&state.db)
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
        Some(r) => Ok(Json(Some(OrganizationResponse {
            id: r.get("id"),
            name: r.get("name"),
            slug: r.get("slug"),
            owner_id: r.get("owner_id"),
            plan: r.get("plan"),
            created_at: r.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
            updated_at: r.get::<chrono::NaiveDateTime, _>("updated_at").and_utc(),
        }))),
        None => Ok(Json(None)),
    }
}
fn current_billing_period() -> (DateTime<Utc>, DateTime<Utc>) {
    let now = Utc::now();
    let start = NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
        .unwrap_or(now.date_naive())
        .and_time(NaiveTime::MIN)
        .and_utc();

    let (next_year, next_month) = if now.month() == 12 {
        (now.year() + 1, 1)
    } else {
        (now.year(), now.month() + 1)
    };

    let end = NaiveDate::from_ymd_opt(next_year, next_month, 1)
        .unwrap_or(now.date_naive())
        .and_time(NaiveTime::MIN)
        .and_utc();

    (start, end)
}

pub async fn get_organization_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OrganizationUsageResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_row = sqlx::query(
        r#"
        SELECT o.id, o.plan
        FROM organization o
        JOIN organization_member om ON o.id = om.organization_id
        WHERE om.user_id = $1
        LIMIT 1
        "#,
    )
    .bind(&user.user_id)
    .fetch_optional(&state.db)
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

    let org_row = org_row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "Organization not found",
                "ORG_NOT_FOUND",
            )),
        )
    })?;

    let org_id: Uuid = org_row.get("id");
    let plan: Option<String> = org_row.get("plan");

    let (period_start, period_end) = current_billing_period();

    let (guard_result, garak_result, api_keys_result, models_result) = tokio::join!(
        sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_scans,
                COUNT(*) FILTER (WHERE is_safe = false) as threats_blocked,
                COALESCE(AVG(latency_ms)::BIGINT, 0) as avg_latency
            FROM guard_log
            WHERE organization_id = $1
              AND created_at >= $2
              AND created_at < $3
            "#,
        )
        .bind(org_id)
        .bind(period_start.naive_utc())
        .bind(period_end.naive_utc())
        .fetch_one(&state.db),
        sqlx::query(
            r#"
            SELECT COUNT(*) as total_scans
            FROM scan
            WHERE organization_id = $1
              AND created_at >= $2
              AND created_at < $3
            "#,
        )
        .bind(org_id)
        .bind(period_start.naive_utc())
        .bind(period_end.naive_utc())
        .fetch_one(&state.db),
        sqlx::query(
            r#"
            SELECT COUNT(*) as total_keys
            FROM api_key
            WHERE organization_id = $1
              AND revoked_at IS NULL
            "#,
        )
        .bind(org_id)
        .fetch_one(&state.db),
        sqlx::query(
            r#"
            SELECT COUNT(*) as total_models
            FROM model_config
            WHERE organization_id = $1
            "#,
        )
        .bind(org_id)
        .fetch_one(&state.db),
    );

    let guard_row = guard_result.map_err(|e| {
        tracing::error!("Failed to query guard usage: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to get usage data",
                "DB_QUERY_FAILED",
            )),
        )
    })?;

    let garak_row = garak_result.map_err(|e| {
        tracing::error!("Failed to query garak usage: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to get usage data",
                "DB_QUERY_FAILED",
            )),
        )
    })?;

    let api_keys_row = api_keys_result.map_err(|e| {
        tracing::error!("Failed to query api keys: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to get usage data",
                "DB_QUERY_FAILED",
            )),
        )
    })?;

    let models_row = models_result.map_err(|e| {
        tracing::error!("Failed to query model configs: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to get usage data",
                "DB_QUERY_FAILED",
            )),
        )
    })?;

    Ok(Json(OrganizationUsageResponse {
        organization_id: org_id,
        plan,
        guard_scans_used: guard_row.get::<i64, _>("total_scans"),
        garak_scans_used: garak_row.get::<i64, _>("total_scans"),
        api_keys_used: api_keys_row.get::<i64, _>("total_keys"),
        model_configs_used: models_row.get::<i64, _>("total_models"),
        threats_blocked: guard_row.get::<i64, _>("threats_blocked"),
        avg_latency_ms: guard_row.get::<i64, _>("avg_latency"),
        billing_period_start: period_start,
        billing_period_end: period_end,
    }))
}
