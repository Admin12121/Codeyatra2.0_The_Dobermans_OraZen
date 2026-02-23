use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use chrono::{DateTime, Utc};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashSet;
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use uuid::Uuid;

use std::collections::HashMap;

use super::AppState;
use crate::db::blockchain::append_scan_chain_block;
use crate::grpc::ml_client::{CustomEndpointInfo, ModelConfig as GrpcModelConfig};
use crate::middleware::{ErrorResponse, require_session_from_headers};

const MAX_CONCURRENT_SCANS: usize = 4;
const POLL_INTERVAL_SECS: u64 = 5;
const MAX_VULNERABILITIES_PER_PAGE: i64 = 100;

struct ScanEventStream {
    rx: mpsc::Receiver<Event>,
}

impl Stream for ScanEventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(event)) => Poll::Ready(Some(Ok(event))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct StartScanRequest {
    pub model_config: ModelConfig,
    pub scan_type: ScanType,
    #[serde(default)]
    pub probes: Vec<String>,
    #[serde(default)]
    pub custom_endpoint: Option<CustomEndpointConfig>,
    #[serde(default)]
    pub max_prompts_per_probe: Option<i32>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct CustomEndpointConfig {
    pub url: String,
    #[serde(default = "default_http_method")]
    pub method: String,
    #[serde(default = "default_request_template")]
    pub request_template: String,
    #[serde(default = "default_response_path")]
    pub response_path: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

fn default_http_method() -> String {
    "POST".to_string()
}
fn default_request_template() -> String {
    r#"{"prompt": "{{prompt}}"}"#.to_string()
}
fn default_response_path() -> String {
    "response".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct ModelConfig {
    #[serde(deserialize_with = "validate_provider")]
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
}

fn validate_provider<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let provider = String::deserialize(deserializer)?;
    let valid_providers = [
        "openai",
        "anthropic",
        "huggingface",
        "ollama",
        "groq",
        "together",
        "openrouter",
        "cohere",
        "replicate",
        "custom",
    ];

    if !valid_providers.contains(&provider.to_lowercase().as_str()) {
        return Err(serde::de::Error::custom(format!(
            "Invalid provider '{}'. Valid providers: {:?}",
            provider, valid_providers
        )));
    }

    Ok(provider)
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Quick,
    Standard,
    Comprehensive,
    Custom,
}

impl ScanType {
    fn as_str(&self) -> &str {
        match self {
            ScanType::Quick => "quick",
            ScanType::Standard => "standard",
            ScanType::Comprehensive => "comprehensive",
            ScanType::Custom => "custom",
        }
    }

    fn estimated_duration_seconds(&self, probe_count: usize) -> u32 {
        let count = if probe_count > 0 {
            probe_count as u32
        } else {
            match self {
                ScanType::Quick => 2,
                ScanType::Standard => 6,
                ScanType::Comprehensive => 16,
                ScanType::Custom => 6,
            }
        };
        // ~60s setup/health-check + per-probe allowance
        let base = 60u32;
        let per_probe = match self {
            ScanType::Quick => 30,
            ScanType::Standard => 60,
            ScanType::Comprehensive => 90,
            ScanType::Custom => 60,
        };
        base + count * per_probe
    }
}

#[derive(Debug, Serialize)]
pub struct StartScanResponse {
    pub scan_id: Uuid,
    pub status: String,
    pub estimated_duration_seconds: u32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ProbeListResponse {
    pub categories: Vec<ProbeCategoryItem>,
    pub probes: Vec<ProbeInfoItem>,
}

#[derive(Debug, Serialize)]
pub struct ProbeCategoryItem {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub probe_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProbeInfoItem {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub severity_range: String,
    pub default_enabled: bool,
    pub tags: Vec<String>,
    pub class_paths: Vec<String>,
    pub available: bool,
}

#[derive(Debug, Serialize)]
pub struct ScanStatusResponse {
    pub scan_id: Uuid,
    pub status: String,
    pub progress: u8,
    pub probes_completed: u32,
    pub probes_total: u32,
    pub vulnerabilities_found: u32,
    pub started_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RetestRequest {
    pub vulnerability_id: Uuid,
    pub model_config: ModelConfig,
    #[serde(default = "default_retest_attempts")]
    pub num_attempts: i32,
}

fn default_retest_attempts() -> i32 {
    3
}

#[derive(Debug, Serialize)]
pub struct RetestResponse {
    pub vulnerability_id: Uuid,
    pub probe_name: String,
    pub total_attempts: i32,
    pub vulnerable_count: i32,
    pub safe_count: i32,
    pub confirmation_rate: f32,
    pub confirmed: Option<bool>,
    pub results: Vec<RetestAttemptResult>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RetestAttemptResult {
    pub attempt_number: i32,
    pub is_vulnerable: bool,
    pub model_response: String,
    pub detector_score: f32,
    pub duration_ms: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanLogsResponse {
    pub scan_id: Uuid,
    pub logs: Vec<ProbeLogEntry>,
    pub summary: ScanLogSummary,
}

#[derive(Debug, Serialize)]
pub struct ProbeLogEntry {
    pub id: Uuid,
    pub probe_name: String,
    pub probe_class: Option<String>,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i32>,
    pub prompts_sent: i32,
    pub prompts_passed: i32,
    pub prompts_failed: i32,
    pub detector_name: Option<String>,
    pub error_message: Option<String>,
    pub log_lines: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanLogSummary {
    pub total_probes: i32,
    pub probes_passed: i32,
    pub probes_failed: i32,
    pub probes_errored: i32,
    pub total_prompts_sent: i32,
    pub total_duration_ms: i32,
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

fn default_page() -> u32 {
    1
}
fn default_per_page() -> u32 {
    50
}

#[derive(Debug, Serialize)]
pub struct ScanResultsResponse {
    pub scan_id: Uuid,
    pub status: String,
    pub summary: ScanSummary,
    pub vulnerabilities: Vec<Vulnerability>,
    pub pagination: PaginationInfo,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    pub page: u32,
    pub per_page: u32,
    pub total_items: u32,
    pub total_pages: u32,
}

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub total_probes: u32,
    pub passed: u32,
    pub failed: u32,
    pub risk_score: f32,
    pub severity_breakdown: SeverityBreakdown,
}

#[derive(Debug, Serialize)]
pub struct SeverityBreakdown {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

#[derive(Debug, Serialize)]
pub struct Vulnerability {
    pub id: Uuid,
    pub probe_name: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub attack_prompt: String,
    pub model_response: String,
    pub recommendation: String,
    pub success_rate: Option<f32>,
    pub detector_name: Option<String>,
    pub probe_class: Option<String>,
    pub probe_duration_ms: Option<i32>,
    pub confirmed: Option<bool>,
    pub retest_count: i32,
    pub retest_confirmed: i32,
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
                "Organization not found. Please access the dashboard first to create your organization.",
                "ORG_NOT_FOUND",
            )),
        )),
    }
}
pub async fn start_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut req): Json<StartScanRequest>,
) -> Result<Json<StartScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    tracing::info!(
        "Scan started by user: {} ({}) for org: {}",
        user.email,
        user.user_id,
        org_id
    );
    let active_scan_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM scan WHERE status IN ('queued', 'running')")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    if active_scan_count as usize >= MAX_CONCURRENT_SCANS {
        tracing::warn!(
            "Concurrent scan limit reached: {} active scans (limit: {})",
            active_scan_count,
            MAX_CONCURRENT_SCANS
        );
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse::new(
                format!(
                    "Maximum concurrent scans ({}) reached. Please wait for existing scans to complete.",
                    MAX_CONCURRENT_SCANS
                ),
                "TOO_MANY_SCANS",
            )),
        ));
    }
    let provider_lower = req.model_config.provider.to_lowercase();
    if provider_lower != "ollama"
        && provider_lower != "custom"
        && req.model_config.api_key.is_none()
        && req.custom_endpoint.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "API key is required for this provider",
                "MISSING_API_KEY",
            )),
        ));
    }
    if provider_lower == "custom" && req.custom_endpoint.is_none() {
        if let Some(ref base_url) = req.model_config.base_url {
            if !base_url.trim().is_empty() {
                tracing::info!(
                    "Auto-constructing custom endpoint config from base_url: {}",
                    base_url
                );
                req.custom_endpoint = Some(CustomEndpointConfig {
                    url: base_url.clone(),
                    method: default_http_method(),
                    request_template: default_request_template(),
                    response_path: default_response_path(),
                    headers: HashMap::new(),
                });
            }
        }
    }
    if provider_lower == "custom" && req.custom_endpoint.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Custom endpoint configuration is required when provider is 'custom'. Provide url, request_template, response_path, or at least a base_url in the model config.",
                "MISSING_CUSTOM_ENDPOINT",
            )),
        ));
    }

    let mut client = state.get_ml_client().await.map_err(|e| {
        tracing::error!("ML sidecar unavailable: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "Scanning service is currently unavailable",
                    "ML_SERVICE_UNAVAILABLE",
                )
                .with_details(e),
            ),
        )
    })?;

    if let Err(e) = client.health_check().await {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "Scanning service health check failed",
                    "ML_SERVICE_UNHEALTHY",
                )
                .with_details(e.to_string()),
            ),
        ));
    }

    let scan_id = Uuid::new_v4();
    let scan_type_str = req.scan_type.as_str();
    let now = Utc::now();
    let provider_str = req.model_config.provider.clone();
    let model_str = req.model_config.model.clone();
    let base_url_str = req.model_config.base_url.clone();

    sqlx::query(
        r#"
        INSERT INTO scan (id, organization_id, scan_type, status, progress, created_by, created_at, provider, model, base_url)
        VALUES ($1, $2, $3, 'queued', 0, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(scan_id)
    .bind(org_id)
    .bind(scan_type_str)
    .bind(&user.user_id)
    .bind(now.naive_utc())
    .bind(&provider_str)
    .bind(&model_str)
    .bind(&base_url_str)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create scan record: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to create scan record", "DB_INSERT_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?;

    let state_clone = state.clone();
    let model_config = req.model_config.clone();
    let probes = req.probes.clone();
    let probe_count = probes.len();
    let scan_type = req.scan_type.clone();
    let custom_endpoint = req.custom_endpoint.clone();
    let max_prompts_per_probe = req.max_prompts_per_probe;

    tokio::spawn(async move {
        run_garak_scan(
            state_clone,
            org_id,
            scan_id,
            model_config,
            probes,
            scan_type,
            custom_endpoint,
            max_prompts_per_probe,
        )
        .await;
    });

    Ok(Json(StartScanResponse {
        scan_id,
        status: "queued".to_string(),
        estimated_duration_seconds: req.scan_type.estimated_duration_seconds(probe_count),
        created_at: now,
    }))
}

async fn run_garak_scan(
    state: AppState,
    org_id: Uuid,
    scan_id: Uuid,
    model_config: ModelConfig,
    probes: Vec<String>,
    scan_type: ScanType,
    custom_endpoint: Option<CustomEndpointConfig>,
    max_prompts_per_probe: Option<i32>,
) {
    if let Err(e) = sqlx::query("UPDATE scan SET status = 'running', started_at = $2 WHERE id = $1")
        .bind(scan_id)
        .bind(Utc::now().naive_utc())
        .execute(&state.db)
        .await
    {
        tracing::error!("Failed to update scan status to running: {}", e);
        return;
    }

    let mut client = match state.get_ml_client().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                "Failed to connect to ML sidecar for scan {}: {}",
                scan_id,
                e
            );
            mark_scan_failed(
                &state,
                scan_id,
                &format!("ML service connection failed: {}", e),
            )
            .await;
            return;
        }
    };

    let grpc_config = GrpcModelConfig {
        provider: model_config.provider,
        model: model_config.model,
        api_key: model_config.api_key,
        base_url: model_config.base_url,
    };

    let grpc_custom_endpoint = custom_endpoint.map(|ce| CustomEndpointInfo {
        url: ce.url,
        method: ce.method,
        request_template: ce.request_template,
        response_path: ce.response_path,
        headers: ce.headers,
    });

    let remote_scan_id = match client
        .start_garak_scan(
            grpc_config,
            probes,
            scan_type.as_str(),
            grpc_custom_endpoint,
            max_prompts_per_probe,
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("Failed to start Garak scan {}: {}", scan_id, e);
            mark_scan_failed(&state, scan_id, &format!("Failed to start scan: {}", e)).await;
            return;
        }
    };

    tracing::info!(
        "Started Garak scan {} with remote ID: {}",
        scan_id,
        remote_scan_id
    );
    if let Err(e) = sqlx::query("UPDATE scan SET remote_scan_id = $2 WHERE id = $1")
        .bind(scan_id)
        .bind(&remote_scan_id)
        .execute(&state.db)
        .await
    {
        tracing::warn!("Failed to store remote_scan_id for scan {}: {}", scan_id, e);
    }

    tracing::info!(
        "Polling scan {} (remote {}) until completion — no timeout",
        scan_id,
        remote_scan_id
    );
    poll_scan_status(state, org_id, scan_id, remote_scan_id).await;
}

async fn mark_scan_failed(state: &AppState, scan_id: Uuid, error_message: &str) {
    if let Err(e) =
        sqlx::query("UPDATE scan SET status = 'failed', error_message = $2 WHERE id = $1")
            .bind(scan_id)
            .bind(error_message)
            .execute(&state.db)
            .await
    {
        tracing::error!("Failed to mark scan {} as failed: {}", scan_id, e);
    }
}

async fn poll_scan_status(state: AppState, org_id: Uuid, scan_id: Uuid, remote_scan_id: String) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(POLL_INTERVAL_SECS));
    let mut consecutive_failures = 0;
    const MAX_CONSECUTIVE_FAILURES: u32 = 10;

    let mut stored_vuln_keys: HashSet<String> = HashSet::new();
    let mut stored_log_keys: HashSet<String> = HashSet::new();

    loop {
        interval.tick().await;
        let db_status = sqlx::query_scalar::<_, String>("SELECT status FROM scan WHERE id = $1")
            .bind(scan_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

        if db_status.as_deref() == Some("cancelled") {
            tracing::info!(
                "Scan {} was cancelled by user — stopping poll loop",
                scan_id
            );
            break;
        }

        let mut client = match state.get_ml_client().await {
            Ok(c) => {
                consecutive_failures = 0;
                c
            }
            Err(e) => {
                consecutive_failures += 1;
                tracing::warn!(
                    "Failed to get ML client (attempt {}): {}",
                    consecutive_failures,
                    e
                );

                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    mark_scan_failed(&state, scan_id, "Lost connection to ML service").await;
                    break;
                }
                continue;
            }
        };
        let status_response = match client.get_garak_status(&remote_scan_id).await {
            Ok(s) => s,
            Err(e) => {
                consecutive_failures += 1;
                tracing::warn!(
                    "Failed to get scan status (attempt {}): {}",
                    consecutive_failures,
                    e
                );

                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    mark_scan_failed(
                        &state,
                        scan_id,
                        &format!("Failed to get scan status: {}", e),
                    )
                    .await;
                    break;
                }
                continue;
            }
        };

        consecutive_failures = 0;

        if let Err(e) = sqlx::query(
            r#"
            UPDATE scan
            SET progress = $2,
                probes_completed = $3,
                probes_total = $4,
                vulnerabilities_found = $5
            WHERE id = $1
            "#,
        )
        .bind(scan_id)
        .bind(status_response.progress)
        .bind(status_response.probes_completed)
        .bind(status_response.probes_total)
        .bind(status_response.vulnerabilities_found)
        .execute(&state.db)
        .await
        {
            tracing::warn!("Failed to update scan progress: {}", e);
        }
        for vuln in &status_response.vulnerabilities {
            let dedup_key = format!(
                "{}:{}:{}",
                vuln.probe_name,
                vuln.probe_class,
                &vuln.attack_prompt.get(..80).unwrap_or(&vuln.attack_prompt)
            );

            if stored_vuln_keys.contains(&dedup_key) {
                continue;
            }

            if let Err(e) = insert_scan_result_with_chain(&state, org_id, scan_id, vuln).await {
                tracing::error!("Failed to store intermediate vulnerability: {}", e);
            } else {
                stored_vuln_keys.insert(dedup_key);
                tracing::debug!(
                    "Stored intermediate vuln for scan {}: {} ({})",
                    scan_id,
                    vuln.probe_name,
                    vuln.severity
                );
            }
        }
        for plog in &status_response.probe_logs {
            let log_key = format!("{}:{}", plog.probe_name, plog.probe_class);
            if stored_log_keys.contains(&log_key) {
                continue;
            }
            if plog.status == "running" {
                continue;
            }

            if let Err(e) = insert_scan_log_with_chain(&state, org_id, scan_id, plog).await {
                tracing::error!("Failed to store probe log: {}", e);
            } else {
                stored_log_keys.insert(log_key);
            }
        }

        match status_response.status.as_str() {
            "completed" => {
                for vuln in &status_response.vulnerabilities {
                    let dedup_key = format!(
                        "{}:{}:{}",
                        vuln.probe_name,
                        vuln.probe_class,
                        &vuln.attack_prompt.get(..80).unwrap_or(&vuln.attack_prompt)
                    );
                    if stored_vuln_keys.contains(&dedup_key) {
                        continue;
                    }
                    if let Err(e) =
                        insert_scan_result_with_chain(&state, org_id, scan_id, vuln).await
                    {
                        tracing::warn!("Failed to store completion-time vulnerability: {}", e);
                    } else {
                        stored_vuln_keys.insert(dedup_key);
                    }
                }

                let risk_score = calculate_risk_score(&status_response.vulnerabilities);

                if let Err(e) = sqlx::query(
                    "UPDATE scan SET status = 'completed', risk_score = $2, completed_at = $3 WHERE id = $1"
                )
                .bind(scan_id)
                .bind(risk_score)
                .bind(Utc::now().naive_utc())
                .execute(&state.db)
                .await {
                    tracing::error!("Failed to mark scan as completed: {}", e);
                }

                let summary_payload = serde_json::json!({
                    "status": "completed",
                    "scan_id": scan_id,
                    "remote_scan_id": remote_scan_id,
                    "progress": status_response.progress,
                    "probes_completed": status_response.probes_completed,
                    "probes_total": status_response.probes_total,
                    "vulnerabilities_found": status_response.vulnerabilities_found,
                    "risk_score": risk_score,
                });
                if let Err(e) = append_scan_chain_block(
                    &state.db,
                    org_id,
                    scan_id,
                    "scan_summary",
                    Some(scan_id),
                    &summary_payload,
                )
                .await
                {
                    tracing::warn!("Failed to append scan summary chain block: {}", e);
                }

                tracing::info!(
                    "Scan {} completed with {} vulnerabilities (risk score: {:.2}), {} probe logs stored",
                    scan_id,
                    status_response.vulnerabilities_found,
                    risk_score,
                    stored_log_keys.len()
                );
                break;
            }
            "failed" => {
                mark_scan_failed(&state, scan_id, &status_response.error_message).await;
                let failed_payload = serde_json::json!({
                    "status": "failed",
                    "scan_id": scan_id,
                    "remote_scan_id": remote_scan_id,
                    "error_message": status_response.error_message,
                    "progress": status_response.progress,
                });
                if let Err(e) = append_scan_chain_block(
                    &state.db,
                    org_id,
                    scan_id,
                    "scan_failed",
                    Some(scan_id),
                    &failed_payload,
                )
                .await
                {
                    tracing::warn!("Failed to append failed-scan chain block: {}", e);
                }
                tracing::error!("Scan {} failed: {}", scan_id, status_response.error_message);
                break;
            }
            _ => {}
        }
    }
}

async fn insert_scan_result_with_chain(
    state: &AppState,
    org_id: Uuid,
    scan_id: Uuid,
    vuln: &crate::grpc::ml_client::VulnerabilityInfo,
) -> Result<Uuid, sqlx::Error> {
    let row = sqlx::query(
        r#"
        INSERT INTO scan_result (
            scan_id, probe_name, category, severity, description,
            attack_prompt, model_response, recommendation,
            success_rate, detector_name, probe_class, probe_duration_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING id
        "#,
    )
    .bind(scan_id)
    .bind(&vuln.probe_name)
    .bind(&vuln.category)
    .bind(&vuln.severity)
    .bind(&vuln.description)
    .bind(&vuln.attack_prompt)
    .bind(&vuln.model_response)
    .bind(&vuln.recommendation)
    .bind(vuln.success_rate)
    .bind(&vuln.detector_name)
    .bind(&vuln.probe_class)
    .bind(vuln.probe_duration_ms)
    .fetch_one(&state.db)
    .await?;

    let result_id: Uuid = row.get("id");
    let payload = serde_json::json!({
        "scan_id": scan_id,
        "scan_result_id": result_id,
        "type": "vulnerability",
        "vulnerability": vuln,
    });

    if let Err(e) = append_scan_chain_block(
        &state.db,
        org_id,
        scan_id,
        "scan_result",
        Some(result_id),
        &payload,
    )
    .await
    {
        tracing::warn!(
            "Failed to append chain block for scan_result {}: {}",
            result_id,
            e
        );
    }

    Ok(result_id)
}

async fn insert_scan_log_with_chain(
    state: &AppState,
    org_id: Uuid,
    scan_id: Uuid,
    plog: &crate::grpc::ml_client::ProbeLogInfo,
) -> Result<Uuid, sqlx::Error> {
    let log_entries_json = serde_json::to_value(&plog.log_lines).unwrap_or(serde_json::json!([]));
    let detector_scores_json =
        serde_json::to_value(&plog.detector_scores).unwrap_or(serde_json::json!([]));

    let row = sqlx::query(
        r#"
        INSERT INTO scan_log (
            scan_id, probe_name, probe_class, status,
            started_at, completed_at, duration_ms,
            prompts_sent, prompts_passed, prompts_failed,
            detector_name, detector_scores, error_message, log_entries
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING id
        "#,
    )
    .bind(scan_id)
    .bind(&plog.probe_name)
    .bind(&plog.probe_class)
    .bind(&plog.status)
    .bind(chrono::DateTime::from_timestamp_millis(plog.started_at_ms).map(|dt| dt.naive_utc()))
    .bind(if plog.completed_at_ms > 0 {
        chrono::DateTime::from_timestamp_millis(plog.completed_at_ms).map(|dt| dt.naive_utc())
    } else {
        None
    })
    .bind(plog.duration_ms)
    .bind(plog.prompts_sent)
    .bind(plog.prompts_passed)
    .bind(plog.prompts_failed)
    .bind(&plog.detector_name)
    .bind(&detector_scores_json)
    .bind(if plog.error_message.is_empty() {
        None
    } else {
        Some(&plog.error_message)
    })
    .bind(&log_entries_json)
    .fetch_one(&state.db)
    .await?;

    let log_id: Uuid = row.get("id");
    let payload = serde_json::json!({
        "scan_id": scan_id,
        "scan_log_id": log_id,
        "type": "probe_log",
        "probe_log": plog,
    });

    if let Err(e) = append_scan_chain_block(
        &state.db,
        org_id,
        scan_id,
        "scan_log",
        Some(log_id),
        &payload,
    )
    .await
    {
        tracing::warn!(
            "Failed to append chain block for scan_log {}: {}",
            log_id,
            e
        );
    }

    Ok(log_id)
}

#[derive(Debug, Serialize)]
pub struct CancelScanResponse {
    pub scan_id: Uuid,
    pub status: String,
    pub message: String,
}
pub async fn cancel_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(scan_id): Path<Uuid>,
) -> Result<Json<CancelScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let row = sqlx::query("SELECT status, created_by FROM scan WHERE id = $1")
        .bind(scan_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch scan for cancel: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error", "DB_ERROR")),
            )
        })?;

    let row = row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Scan not found", "SCAN_NOT_FOUND")),
        )
    })?;

    let status: String = row.get("status");
    let created_by: Option<String> = row.get("created_by");

    if created_by.as_deref() != Some(&user.user_id) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new(
                "You can only cancel your own scans",
                "FORBIDDEN",
            )),
        ));
    }

    if status != "running" && status != "queued" {
        return Ok(Json(CancelScanResponse {
            scan_id,
            status: status.clone(),
            message: format!("Scan is already '{}' and cannot be cancelled", status),
        }));
    }

    let remote_id: Option<String> =
        sqlx::query_scalar("SELECT remote_scan_id FROM scan WHERE id = $1")
            .bind(scan_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    if let Some(remote_scan_id) = remote_id {
        match state.get_ml_client().await {
            Ok(mut client) => match client.cancel_garak_scan(&remote_scan_id).await {
                Ok(cancel_status) => {
                    tracing::info!(
                        "Cancelled ML sidecar scan {} (remote {}): {}",
                        scan_id,
                        remote_scan_id,
                        cancel_status
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "ML sidecar cancel failed for scan {} (remote {}): {} — \
                             DB status will still be set to cancelled",
                        scan_id,
                        remote_scan_id,
                        e
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    "Could not connect to ML sidecar to cancel scan {}: {}",
                    scan_id,
                    e
                );
            }
        }
    } else {
        tracing::warn!(
            "No remote_scan_id stored for scan {} — marking cancelled in DB only",
            scan_id
        );
    }

    let now = Utc::now().naive_utc();
    sqlx::query(
        "UPDATE scan SET status = 'cancelled', error_message = 'Cancelled by user', completed_at = $2 WHERE id = $1 AND status IN ('running', 'queued')",
    )
    .bind(scan_id)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to mark scan as cancelled: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to cancel scan",
                "DB_UPDATE_FAILED",
            )),
        )
    })?;

    tracing::info!("Scan {} cancelled by user {}", scan_id, user.email);

    Ok(Json(CancelScanResponse {
        scan_id,
        status: "cancelled".to_string(),
        message: "Scan has been cancelled. It will stop after the current probe finishes."
            .to_string(),
    }))
}

fn calculate_risk_score(vulnerabilities: &[crate::grpc::ml_client::VulnerabilityInfo]) -> f32 {
    if vulnerabilities.is_empty() {
        return 0.0;
    }

    let mut score = 0.0f32;
    for vuln in vulnerabilities {
        score += match vuln.severity.as_str() {
            "critical" => 1.0,
            "high" => 0.75,
            "medium" => 0.5,
            "low" => 0.25,
            _ => 0.1,
        };
    }

    (score / vulnerabilities.len() as f32).min(1.0)
}

#[derive(Debug, Deserialize)]
pub struct ListScansParams {
    #[serde(default = "default_scan_limit")]
    pub limit: i64,
}

fn default_scan_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct ScanListItem {
    pub id: Uuid,
    pub organization_id: Option<Uuid>,
    pub model_config_id: Option<Uuid>,
    pub scan_type: String,
    pub status: String,
    pub progress: i32,
    pub probes_total: i32,
    pub probes_completed: i32,
    pub vulnerabilities_found: i32,
    pub risk_score: Option<f32>,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ListScansResponse {
    pub scans: Vec<ScanListItem>,
}

pub async fn list_scans(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ListScansParams>,
) -> Result<Json<ListScansResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let limit = params.limit.min(100).max(1);

    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, model_config_id, scan_type, status, progress,
               probes_total, probes_completed, vulnerabilities_found, risk_score,
               error_message, started_at, completed_at, created_by, created_at
        FROM scan
        WHERE created_by = $1
        ORDER BY created_at DESC
        LIMIT $2
        "#,
    )
    .bind(&user.user_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to list scans: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to list scans",
                "DB_QUERY_FAILED",
            )),
        )
    })?;

    let scans: Vec<ScanListItem> = rows
        .into_iter()
        .map(|row| ScanListItem {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            model_config_id: row.get("model_config_id"),
            scan_type: row.get("scan_type"),
            status: row.get("status"),
            progress: row.get("progress"),
            probes_total: row.get("probes_total"),
            probes_completed: row.get("probes_completed"),
            vulnerabilities_found: row.get("vulnerabilities_found"),
            risk_score: row.get("risk_score"),
            error_message: row.get("error_message"),
            started_at: row
                .get::<Option<chrono::NaiveDateTime>, _>("started_at")
                .map(|dt| dt.and_utc()),
            completed_at: row
                .get::<Option<chrono::NaiveDateTime>, _>("completed_at")
                .map(|dt| dt.and_utc()),
            created_by: row.get("created_by"),
            created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
        })
        .collect();

    Ok(Json(ListScansResponse { scans }))
}

pub async fn get_scan_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(scan_id): Path<Uuid>,
) -> Result<Json<ScanStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
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
        SELECT id, status, progress, probes_completed, probes_total,
               vulnerabilities_found, started_at, created_at, error_message
        FROM scan WHERE id = $1 AND created_by = $2
        "#,
    )
    .bind(scan_id)
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error fetching scan status: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to fetch scan status", "DB_QUERY_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?;

    match row {
        Some(row) => {
            let status: String = row.get("status");
            let progress: i32 = row.get("progress");
            let probes_completed: i32 = row.get("probes_completed");
            let probes_total: i32 = row.get("probes_total");
            let vulnerabilities_found: i32 = row.get("vulnerabilities_found");
            let started_at: Option<chrono::NaiveDateTime> = row.get("started_at");
            let created_at: chrono::NaiveDateTime = row.get("created_at");
            let error_message: Option<String> = row.get("error_message");

            Ok(Json(ScanStatusResponse {
                scan_id,
                status,
                progress: progress as u8,
                probes_completed: probes_completed as u32,
                probes_total: probes_total as u32,
                vulnerabilities_found: vulnerabilities_found as u32,
                started_at: started_at.map(|dt| dt.and_utc()),
                updated_at: created_at.and_utc(),
                error_message,
            }))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Scan not found", "SCAN_NOT_FOUND")),
        )),
    }
}

pub async fn get_scan_results(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(scan_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<ScanResultsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;
    let page = pagination.page.max(1);
    let per_page = pagination
        .per_page
        .min(MAX_VULNERABILITIES_PER_PAGE as u32)
        .max(1);
    let offset = ((page - 1) * per_page) as i64;

    let scan = sqlx::query(
        r#"
        SELECT id, status, probes_total, risk_score, completed_at, error_message
        FROM scan WHERE id = $1 AND created_by = $2
        "#,
    )
    .bind(scan_id)
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error fetching scan: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to fetch scan", "DB_QUERY_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Scan not found", "SCAN_NOT_FOUND")),
        )
    })?;

    let status: String = scan.get("status");
    let probes_total: i32 = scan.get("probes_total");
    let risk_score: Option<f32> = scan.get("risk_score");
    let completed_at: Option<chrono::NaiveDateTime> = scan.get("completed_at");

    if status != "completed" && status != "failed" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                format!(
                    "Scan is still {}. Results are only available for completed scans.",
                    status
                ),
                "SCAN_NOT_COMPLETE",
            )),
        ));
    }

    let count_row = sqlx::query("SELECT COUNT(*) as count FROM scan_result WHERE scan_id = $1")
        .bind(scan_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Database error counting vulnerabilities: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    ErrorResponse::new("Failed to count vulnerabilities", "DB_QUERY_FAILED")
                        .with_details(e.to_string()),
                ),
            )
        })?;

    let total_items: i64 = count_row.get("count");
    let total_pages = ((total_items as f64) / (per_page as f64)).ceil() as u32;

    let vuln_rows = sqlx::query(
        r#"
        SELECT id, probe_name, category, severity, description,
               attack_prompt, model_response, recommendation
        FROM scan_result
        WHERE scan_id = $1
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            probe_name
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(scan_id)
    .bind(per_page as i64)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error fetching vulnerabilities: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to fetch vulnerabilities", "DB_QUERY_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?;
    let severity_rows = sqlx::query(
        r#"
        SELECT severity, COUNT(*) as count
        FROM scan_result
        WHERE scan_id = $1
        GROUP BY severity
        "#,
    )
    .bind(scan_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error fetching severity breakdown: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to fetch severity breakdown", "DB_QUERY_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?;

    let mut severity_breakdown = SeverityBreakdown {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };

    for row in severity_rows {
        let severity: String = row.get("severity");
        let count: i64 = row.get("count");
        match severity.as_str() {
            "critical" => severity_breakdown.critical = count as u32,
            "high" => severity_breakdown.high = count as u32,
            "medium" => severity_breakdown.medium = count as u32,
            "low" => severity_breakdown.low = count as u32,
            _ => {}
        }
    }

    let vulnerabilities: Vec<Vulnerability> = vuln_rows
        .into_iter()
        .map(|row| Vulnerability {
            id: row.get("id"),
            probe_name: row.get("probe_name"),
            category: row.get("category"),
            severity: row.get("severity"),
            description: row.get("description"),
            attack_prompt: row.get("attack_prompt"),
            model_response: row.get("model_response"),
            recommendation: row.get("recommendation"),
            success_rate: row.try_get("success_rate").ok().flatten(),
            detector_name: row.try_get("detector_name").ok().flatten(),
            probe_class: row.try_get("probe_class").ok().flatten(),
            probe_duration_ms: row.try_get("probe_duration_ms").ok().flatten(),
            confirmed: row.try_get("confirmed").ok().flatten(),
            retest_count: row.try_get("retest_count").ok().unwrap_or(0),
            retest_confirmed: row.try_get("retest_confirmed").ok().unwrap_or(0),
        })
        .collect();

    let failed = total_items as u32;
    let passed = (probes_total as u32).saturating_sub(failed);

    Ok(Json(ScanResultsResponse {
        scan_id,
        status,
        summary: ScanSummary {
            total_probes: probes_total as u32,
            passed,
            failed,
            risk_score: risk_score.unwrap_or(0.0),
            severity_breakdown,
        },
        vulnerabilities,
        pagination: PaginationInfo {
            page,
            per_page,
            total_items: total_items as u32,
            total_pages,
        },
        completed_at: completed_at.map(|dt| dt.and_utc()),
    }))
}
pub async fn retest_vulnerability(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RetestRequest>,
) -> Result<Json<RetestResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let vuln_row = sqlx::query(
        r#"
        SELECT sr.id, sr.scan_id, sr.probe_name, sr.probe_class, sr.attack_prompt, sr.category,
               s.provider, s.model, s.base_url, s.created_by
        FROM scan_result sr
        JOIN scan s ON sr.scan_id = s.id
        WHERE sr.id = $1 AND s.created_by = $2
        "#,
    )
    .bind(req.vulnerability_id)
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Database error", "DB_ERROR").with_details(e.to_string())),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "Vulnerability not found or access denied",
                "VULN_NOT_FOUND",
            )),
        )
    })?;

    let scan_id: Uuid = vuln_row.get("scan_id");
    let probe_name: String = vuln_row.get("probe_name");
    let probe_class: Option<String> = vuln_row.get("probe_class");
    let attack_prompt: Option<String> = vuln_row.get("attack_prompt");

    let attack_prompt = attack_prompt.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Vulnerability has no attack prompt to retest",
                "NO_ATTACK_PROMPT",
            )),
        )
    })?;

    let grpc_config = GrpcModelConfig {
        provider: req.model_config.provider.clone(),
        model: req.model_config.model.clone(),
        api_key: req.model_config.api_key.clone(),
        base_url: req.model_config.base_url.clone(),
    };

    let mut client = state.get_ml_client().await.map_err(|e| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new("ML service unavailable", "ML_SERVICE_UNAVAILABLE")
                    .with_details(e),
            ),
        )
    })?;

    let retest_result = client
        .retest_probe(
            &scan_id.to_string(),
            &probe_name,
            probe_class.as_deref().unwrap_or(""),
            &attack_prompt,
            grpc_config,
            req.num_attempts,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    ErrorResponse::new("Retest failed", "RETEST_FAILED")
                        .with_details(e.to_string()),
                ),
            )
        })?;

    for r in &retest_result.results {
        let _ = sqlx::query(
            r#"
            INSERT INTO scan_retest (
                original_result_id, scan_id, probe_name, attempt_number,
                status, attack_prompt, model_response, detector_score,
                is_vulnerable, duration_ms, error_message, completed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
            "#,
        )
        .bind(req.vulnerability_id)
        .bind(scan_id)
        .bind(&probe_name)
        .bind(r.attempt_number)
        .bind(if r.is_vulnerable {
            "vulnerable"
        } else {
            "safe"
        })
        .bind(&attack_prompt)
        .bind(&r.model_response)
        .bind(r.detector_score)
        .bind(r.is_vulnerable)
        .bind(r.duration_ms)
        .bind(if r.error_message.is_empty() {
            None
        } else {
            Some(&r.error_message)
        })
        .execute(&state.db)
        .await;
    }

    let confirmed = if retest_result.confirmation_rate >= 0.5 {
        Some(true)
    } else if retest_result.total_attempts > 0 {
        Some(false)
    } else {
        None
    };

    let _ = sqlx::query(
        r#"
        UPDATE scan_result
        SET retest_count = COALESCE(retest_count, 0) + $2,
            retest_confirmed = COALESCE(retest_confirmed, 0) + $3,
            confirmed = $4
        WHERE id = $1
        "#,
    )
    .bind(req.vulnerability_id)
    .bind(retest_result.total_attempts)
    .bind(retest_result.vulnerable_count)
    .bind(confirmed)
    .execute(&state.db)
    .await;

    tracing::info!(
        "Retest for vuln {}: {}/{} confirmed (rate: {:.0}%)",
        req.vulnerability_id,
        retest_result.vulnerable_count,
        retest_result.total_attempts,
        retest_result.confirmation_rate * 100.0
    );

    Ok(Json(RetestResponse {
        vulnerability_id: req.vulnerability_id,
        probe_name: retest_result.probe_name,
        total_attempts: retest_result.total_attempts,
        vulnerable_count: retest_result.vulnerable_count,
        safe_count: retest_result.safe_count,
        confirmation_rate: retest_result.confirmation_rate,
        confirmed,
        results: retest_result
            .results
            .into_iter()
            .map(|r| RetestAttemptResult {
                attempt_number: r.attempt_number,
                is_vulnerable: r.is_vulnerable,
                model_response: r.model_response,
                detector_score: r.detector_score,
                duration_ms: r.duration_ms,
                error_message: if r.error_message.is_empty() {
                    None
                } else {
                    Some(r.error_message)
                },
            })
            .collect(),
        status: retest_result.status,
        error_message: if retest_result.error_message.is_empty() {
            None
        } else {
            Some(retest_result.error_message)
        },
    }))
}

pub async fn get_scan_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(scan_id): Path<Uuid>,
) -> Result<Json<ScanLogsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let scan_exists = sqlx::query("SELECT id FROM scan WHERE id = $1 AND created_by = $2")
        .bind(scan_id)
        .bind(&user.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error", "DB_ERROR").with_details(e.to_string())),
            )
        })?;

    if scan_exists.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Scan not found", "SCAN_NOT_FOUND")),
        ));
    }

    let log_rows = sqlx::query(
        r#"
        SELECT id, probe_name, probe_class, status, started_at, completed_at,
               duration_ms, prompts_sent, prompts_passed, prompts_failed,
               detector_name, error_message, log_entries
        FROM scan_log
        WHERE scan_id = $1
        ORDER BY started_at ASC
        "#,
    )
    .bind(scan_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to fetch scan logs", "DB_QUERY_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?;

    let mut total_prompts_sent = 0i32;
    let mut total_duration_ms = 0i32;
    let mut probes_passed = 0i32;
    let mut probes_failed = 0i32;
    let mut probes_errored = 0i32;

    let logs: Vec<ProbeLogEntry> = log_rows
        .into_iter()
        .map(|row| {
            let status: String = row.get("status");
            let prompts_sent: i32 = row.get("prompts_sent");
            let duration_ms: Option<i32> = row.get("duration_ms");

            total_prompts_sent += prompts_sent;
            total_duration_ms += duration_ms.unwrap_or(0);
            match status.as_str() {
                "passed" => probes_passed += 1,
                "failed" => probes_failed += 1,
                "error" => probes_errored += 1,
                _ => {}
            }

            let log_entries_json: Option<serde_json::Value> = row.get("log_entries");
            let log_lines: Vec<String> = log_entries_json
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();

            ProbeLogEntry {
                id: row.get("id"),
                probe_name: row.get("probe_name"),
                probe_class: row.get("probe_class"),
                status,
                started_at: row.get::<chrono::NaiveDateTime, _>("started_at").and_utc(),
                completed_at: row
                    .get::<Option<chrono::NaiveDateTime>, _>("completed_at")
                    .map(|dt| dt.and_utc()),
                duration_ms,
                prompts_sent,
                prompts_passed: row.get("prompts_passed"),
                prompts_failed: row.get("prompts_failed"),
                detector_name: row.get("detector_name"),
                error_message: row.get("error_message"),
                log_lines,
            }
        })
        .collect();

    let total_probes = logs.len() as i32;

    Ok(Json(ScanLogsResponse {
        scan_id,
        logs,
        summary: ScanLogSummary {
            total_probes,
            probes_passed,
            probes_failed,
            probes_errored,
            total_prompts_sent,
            total_duration_ms,
        },
    }))
}

pub async fn list_probes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ProbeListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let _user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let mut client = state.get_ml_client().await.map_err(|e| {
        tracing::error!("ML sidecar unavailable: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse::new(
                "Scanning service is currently unavailable",
                "ML_SERVICE_UNAVAILABLE",
            )),
        )
    })?;

    let result = client.list_garak_probes().await.map_err(|e| {
        tracing::error!("Failed to list Garak probes: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to list available probes", "PROBE_LIST_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?;

    Ok(Json(ProbeListResponse {
        categories: result
            .categories
            .into_iter()
            .map(|c| ProbeCategoryItem {
                id: c.id,
                name: c.name,
                description: c.description,
                icon: c.icon,
                probe_ids: c.probe_ids,
            })
            .collect(),
        probes: result
            .probes
            .into_iter()
            .map(|p| ProbeInfoItem {
                id: p.id,
                name: p.name,
                description: p.description,
                category: p.category,
                severity_range: p.severity_range,
                default_enabled: p.default_enabled,
                tags: p.tags,
                class_paths: p.class_paths,
                available: p.available,
            })
            .collect(),
    }))
}

pub async fn scan_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(scan_id): Path<Uuid>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let scan_row = sqlx::query("SELECT id, status FROM scan WHERE id = $1 AND created_by = $2")
        .bind(scan_id)
        .bind(&user.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Database error", "DB_ERROR").with_details(e.to_string())),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse::new("Scan not found", "SCAN_NOT_FOUND")),
            )
        })?;

    let current_status: String = scan_row.get("status");

    let (tx, rx) = mpsc::channel::<Event>(64);

    let _ = tx
        .send(
            Event::default().event("connected").data(
                serde_json::json!({
                    "scan_id": scan_id,
                    "status": current_status,
                })
                .to_string(),
            ),
        )
        .await;

    if current_status == "completed" || current_status == "failed" || current_status == "cancelled"
    {
        let _ = tx
            .send(Event::default().event(&current_status).data(
                serde_json::json!({ "scan_id": scan_id, "status": current_status }).to_string(),
            ))
            .await;
    } else {
        let state_clone = state.clone();
        tokio::spawn(async move {
            poll_and_stream_events(state_clone, scan_id, tx).await;
        });
    }

    let stream = ScanEventStream { rx };
    let sse = Sse::new(stream).keep_alive(KeepAlive::default());

    Ok(sse.into_response())
}
async fn poll_and_stream_events(state: AppState, scan_id: Uuid, tx: mpsc::Sender<Event>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
    let mut last_vuln_count = 0u32;
    let mut last_progress = 0i32;
    let max_iterations = 1500;
    let mut iteration = 0;

    loop {
        interval.tick().await;
        iteration += 1;

        if iteration > max_iterations || tx.is_closed() {
            break;
        }

        let row = match sqlx::query(
            r#"
            SELECT status, progress, probes_completed, probes_total, vulnerabilities_found
            FROM scan WHERE id = $1
            "#,
        )
        .bind(scan_id)
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some(r)) => r,
            _ => break,
        };

        let status: String = row.get("status");
        let progress: i32 = row.get("progress");
        let probes_completed: i32 = row.get("probes_completed");
        let probes_total: i32 = row.get("probes_total");
        let vuln_count: i32 = row.get("vulnerabilities_found");

        if progress != last_progress {
            last_progress = progress;
            let event_data = serde_json::json!({
                "scan_id": scan_id,
                "status": status,
                "progress": progress,
                "probes_completed": probes_completed,
                "probes_total": probes_total,
                "vulnerabilities_found": vuln_count,
            });

            if tx
                .send(
                    Event::default()
                        .event("progress")
                        .data(event_data.to_string()),
                )
                .await
                .is_err()
            {
                break;
            }
        }

        if (vuln_count as u32) > last_vuln_count {
            let new_vulns = sqlx::query(
                r#"
                SELECT id, probe_name, category, severity, description, success_rate, detector_name
                FROM scan_result
                WHERE scan_id = $1
                ORDER BY created_at DESC
                LIMIT $2
                "#,
            )
            .bind(scan_id)
            .bind((vuln_count as u32 - last_vuln_count) as i64)
            .fetch_all(&state.db)
            .await;

            if let Ok(rows) = new_vulns {
                for vrow in rows {
                    let vuln_event = serde_json::json!({
                        "id": vrow.get::<Uuid, _>("id").to_string(),
                        "probe_name": vrow.get::<String, _>("probe_name"),
                        "category": vrow.get::<String, _>("category"),
                        "severity": vrow.get::<String, _>("severity"),
                        "description": vrow.get::<String, _>("description"),
                        "success_rate": vrow.get::<Option<f32>, _>("success_rate"),
                        "detector_name": vrow.get::<Option<String>, _>("detector_name"),
                    });

                    if tx
                        .send(
                            Event::default()
                                .event("vulnerability")
                                .data(vuln_event.to_string()),
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            last_vuln_count = vuln_count as u32;
        }

        match status.as_str() {
            "completed" => {
                let _ = tx
                    .send(
                        Event::default().event("completed").data(
                            serde_json::json!({
                                "scan_id": scan_id,
                                "vulnerabilities_found": vuln_count,
                            })
                            .to_string(),
                        ),
                    )
                    .await;
                break;
            }
            "failed" => {
                let _ = tx
                    .send(
                        Event::default()
                            .event("failed")
                            .data(serde_json::json!({ "scan_id": scan_id }).to_string()),
                    )
                    .await;
                break;
            }
            "cancelled" => {
                let _ = tx
                    .send(
                        Event::default()
                            .event("cancelled")
                            .data(serde_json::json!({ "scan_id": scan_id }).to_string()),
                    )
                    .await;
                break;
            }
            _ => {}
        }
    }
}
