use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Utc};
use futures::future::join_all;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::collections::HashMap;

use super::AppState;
use crate::db::write_buffer::GuardLogEntry;
use crate::grpc::ml_client::{
    AdvancedScanOptions as GrpcAdvancedScanOptions, ScanMode as GrpcScanMode,
    ScanOptions as GrpcScanOptions, ScannerConfigEntry as GrpcScannerConfigEntry,
    ScannerResultInfo,
};
use crate::middleware::auth::{ApiKeyInfo, GuardScannerEntry};
use crate::middleware::rate_limit::{
    MONTHLY_QUOTA_BASIC, MONTHLY_QUOTA_FREE_TRIAL, RATE_LIMIT_WINDOW_SECONDS, check_monthly_quota,
    check_monthly_quota_remaining, check_rate_limit, check_rate_limit_with_cost,
    increment_monthly_quota, monthly_quota_for_plan, rate_limit_key,
};
use crate::middleware::{ErrorResponse, require_api_key_from_headers};
use crate::utils::hash_prompt;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiScanMode {
    PromptOnly,
    OutputOnly,
    Both,
}

impl Default for ApiScanMode {
    fn default() -> Self {
        ApiScanMode::PromptOnly
    }
}

impl From<ApiScanMode> for GrpcScanMode {
    fn from(m: ApiScanMode) -> Self {
        match m {
            ApiScanMode::PromptOnly => GrpcScanMode::PromptOnly,
            ApiScanMode::OutputOnly => GrpcScanMode::OutputOnly,
            ApiScanMode::Both => GrpcScanMode::Both,
        }
    }
}

impl From<GrpcScanMode> for ApiScanMode {
    fn from(m: GrpcScanMode) -> Self {
        match m {
            GrpcScanMode::PromptOnly => ApiScanMode::PromptOnly,
            GrpcScanMode::OutputOnly => ApiScanMode::OutputOnly,
            GrpcScanMode::Both => ApiScanMode::Both,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_threshold")]
    pub threshold: f32,
    #[serde(default)]
    pub settings_json: String,
}

fn default_threshold() -> f32 {
    0.5
}

impl From<ApiScannerConfig> for GrpcScannerConfigEntry {
    fn from(c: ApiScannerConfig) -> Self {
        GrpcScannerConfigEntry {
            enabled: c.enabled,
            threshold: c.threshold,
            settings_json: c.settings_json,
        }
    }
}


#[derive(Debug, Deserialize)]
pub struct ScanPromptRequest {
    #[serde(deserialize_with = "validate_prompt")]
    pub prompt: String,
    #[serde(default)]
    pub options: ScanOptions,
}

fn validate_prompt<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let prompt = String::deserialize(deserializer)?;

    const MAX_PROMPT_LENGTH: usize = 32 * 1024;
    if prompt.len() > MAX_PROMPT_LENGTH {
        return Err(serde::de::Error::custom(format!(
            "Prompt exceeds maximum length of {} bytes",
            MAX_PROMPT_LENGTH
        )));
    }
    if prompt.trim().is_empty() {
        return Err(serde::de::Error::custom("Prompt cannot be empty"));
    }

    Ok(prompt)
}

#[derive(Debug, Deserialize)]
pub struct ScanOptions {
    #[serde(default = "default_true")]
    pub check_injection: bool,
    #[serde(default = "default_true")]
    pub check_toxicity: bool,
    #[serde(default = "default_true")]
    pub check_pii: bool,
    #[serde(default)]
    pub sanitize: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            check_injection: true,
            check_toxicity: true,
            check_pii: true,
            sanitize: false,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanPromptResponse {
    pub id: Uuid,
    pub safe: bool,
    pub sanitized_prompt: Option<String>,
    pub threats: Vec<ThreatDetection>,
    pub risk_score: f32,
    pub latency_ms: u64,
    pub cached: bool,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_categories: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatDetection {
    pub threat_type: String,
    pub confidence: f32,
    pub description: String,
    pub severity: String,
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[derive(Debug, Deserialize)]
pub struct ValidateOutputRequest {
    #[serde(deserialize_with = "validate_output_content")]
    pub output: String,
    pub original_prompt: Option<String>,
}

fn validate_output_content<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let output = String::deserialize(deserializer)?;

    const MAX_OUTPUT_LENGTH: usize = 64 * 1024;
    if output.len() > MAX_OUTPUT_LENGTH {
        return Err(serde::de::Error::custom(format!(
            "Output exceeds maximum length of {} bytes",
            MAX_OUTPUT_LENGTH
        )));
    }

    if output.trim().is_empty() {
        return Err(serde::de::Error::custom("Output cannot be empty"));
    }

    Ok(output)
}

#[derive(Debug, Serialize)]
pub struct ValidateOutputResponse {
    pub id: Uuid,
    pub safe: bool,
    pub sanitized_output: Option<String>,
    pub issues: Vec<OutputIssue>,
    pub latency_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct OutputIssue {
    pub issue_type: String,
    pub description: String,
    pub severity: String,
}

const MAX_BATCH_SIZE: usize = 50;

#[derive(Debug, Deserialize)]
pub struct BatchScanRequest {
    pub prompts: Vec<BatchPromptItem>,
    #[serde(default)]
    pub options: ScanOptions,
}

#[derive(Debug, Deserialize)]
pub struct BatchPromptItem {
    pub id: Option<String>,
    pub prompt: String,
}

#[derive(Debug, Serialize)]
pub struct BatchScanResponse {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub results: Vec<BatchScanResultItem>,
    pub total_latency_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct BatchScanResultItem {
    pub id: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ScanPromptResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}


const CACHE_TTL_SECONDS: u64 = 300; // 5 minutes
pub async fn scan_prompt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ScanPromptRequest>,
) -> Result<Json<ScanPromptResponse>, (StatusCode, Json<ErrorResponse>)> {
    let api_key = require_api_key_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    tracing::debug!("Guard scan request from org: {}", api_key.organization_id);

    let rl_key = rate_limit_key(Some(&format!("{}", api_key.id)), None);
    let mut redis_conn = state.redis.clone();
    match check_rate_limit(
        &mut redis_conn,
        &rl_key,
        api_key.rate_limit_rpm as u32,
        RATE_LIMIT_WINDOW_SECONDS,
    )
    .await
    {
        Ok((allowed, remaining, retry_after)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(
                        ErrorResponse::new(
                            format!(
                                "Rate limit exceeded. {} requests per minute allowed. Retry after {} seconds.",
                                api_key.rate_limit_rpm, retry_after
                            ),
                            "RATE_LIMITED",
                        )
                        .with_details(format!("remaining: {}, retry_after: {}s", remaining, retry_after)),
                    ),
                ));
            }
            tracing::debug!(
                "Rate limit OK: {} remaining for key {}",
                remaining,
                api_key.id
            );
        }
        Err(e) => {
            tracing::error!("Rate limit check failed: {}", e);
            return Err(billing_enforcement_unavailable_error(format!(
                "rate_limit_check_failed: {}",
                e
            )));
        }
    }

    let org_quota_subject = format!("{}", api_key.organization_id);
    let monthly_limit = lookup_api_key_quota(&state.db, api_key.id).await;
    match check_monthly_quota(&mut redis_conn, &org_quota_subject, monthly_limit).await {
        Ok((allowed, used, limit, days_left)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(
                        ErrorResponse::new(
                            format!(
                                "Monthly quota exceeded. {}/{} requests used. Resets in {} days. {}",
                                used,
                                limit,
                                days_left,
                                quota_upgrade_hint()
                            ),
                            "QUOTA_EXCEEDED",
                        )
                        .with_details(format!(
                            "used: {}, limit: {}, resets_in_days: {}",
                            used, limit, days_left
                        )),
                    ),
                ));
            }
            tracing::debug!(
                "Monthly quota OK: {}/{} used for org {}",
                used,
                limit,
                api_key.organization_id
            );
        }
        Err(e) => {
            tracing::error!("Monthly quota check failed: {}", e);
            return Err(billing_enforcement_unavailable_error(format!(
                "monthly_quota_check_failed: {}",
                e
            )));
        }
    }

    let start = std::time::Instant::now();
    let prompt_hash = hash_prompt(&req.prompt);
    let cache_key = format!("guard:scan:{}", prompt_hash);
    let user_agent = extract_user_agent(&headers);

    let scan_options_json = serde_json::json!({
        "check_injection": req.options.check_injection,
        "check_toxicity": req.options.check_toxicity,
        "check_pii": req.options.check_pii,
        "sanitize": req.options.sanitize,
    });

    match redis_conn.get::<_, Option<String>>(&cache_key).await {
        Ok(Some(cached_json)) => {
            match serde_json::from_str::<ScanPromptResponse>(&cached_json) {
                Ok(mut cached_response) => {
                    let response_id = Uuid::new_v4();
                    cached_response.id = response_id;
                    cached_response.cached = true;
                    cached_response.timestamp = Utc::now();

                    tracing::debug!("Cache hit for prompt hash: {}", prompt_hash);
                    let threat_categories: Vec<String> = cached_response
                        .threats
                        .iter()
                        .map(|t| t.threat_type.clone())
                        .collect();

                    let threats_json =
                        serde_json::to_value(&cached_response.threats).unwrap_or_default();
                    let entry = GuardLogEntry::new_scan(
                        Some(api_key.organization_id),
                        Some(api_key.id),
                        prompt_hash.clone(),
                        cached_response.safe,
                        cached_response.risk_score,
                        threats_json,
                        cached_response.latency_ms as i32,
                        true,
                        extract_ip(&headers).map(|s| s.to_string()),
                        Some(req.prompt.clone()),
                        threat_categories,
                        scan_options_json,
                        user_agent,
                        cached_response.sanitized_prompt.clone(),
                        Some(response_id),
                    );
                    state.write_buffer.queue(entry).await;

                    return Ok(Json(cached_response));
                }
                Err(e) => {
                    tracing::warn!("Failed to deserialize cached response: {}", e);
                    let _: Result<(), _> = redis_conn.del(&cache_key).await;
                }
            }
        }
        Ok(None) => {
        }
        Err(e) => {
            tracing::warn!("Redis cache read failed: {}", e);
        }
    }

    let mut client = state.get_ml_client().await.map_err(|e| {
        tracing::error!("ML sidecar connection failed: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "ML scanning service is currently unavailable",
                    "ML_SERVICE_UNAVAILABLE",
                )
                .with_details(e),
            ),
        )
    })?;

    let (threats, risk_score, sanitized_prompt) = if api_key.guard_config.is_some() {
        tracing::info!(
            "API key {} has guard_config — upgrading simple scan to advanced scan path",
            api_key.id
        );

        let synthetic_req = AdvancedScanRequest {
            prompt: req.prompt.clone(),
            output: String::new(),
            scan_mode: ApiScanMode::PromptOnly,
            input_scanners: HashMap::new(),
            output_scanners: HashMap::new(),
            sanitize: req.options.sanitize,
            fail_fast: false,
        };

        let resolved = resolve_scan_config(&api_key, &headers, &synthetic_req)?;

        let grpc_input_scanners: HashMap<String, GrpcScannerConfigEntry> = resolved
            .input_scanners
            .into_iter()
            .map(|(k, v)| (k, v.into()))
            .collect();

        let grpc_output_scanners: HashMap<String, GrpcScannerConfigEntry> = resolved
            .output_scanners
            .into_iter()
            .map(|(k, v)| (k, v.into()))
            .collect();

        let grpc_opts = GrpcAdvancedScanOptions {
            prompt: req.prompt.clone(),
            output: String::new(),
            scan_mode: GrpcScanMode::PromptOnly,
            input_scanners: grpc_input_scanners,
            output_scanners: grpc_output_scanners,
            sanitize: resolved.sanitize,
            fail_fast: resolved.fail_fast,
        };

        let result = client.advanced_scan(grpc_opts).await.map_err(|e| {
            let error_msg = e.to_string();
            tracing::error!(
                "ML advanced scan (via simple endpoint) failed: {}",
                error_msg
            );

            let (status, code) = match e.code() {
                tonic::Code::DeadlineExceeded => (StatusCode::GATEWAY_TIMEOUT, "SCAN_TIMEOUT"),
                tonic::Code::ResourceExhausted => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
                tonic::Code::InvalidArgument => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
                tonic::Code::Unavailable => {
                    (StatusCode::SERVICE_UNAVAILABLE, "ML_SERVICE_UNAVAILABLE")
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "SCAN_FAILED"),
            };

            (
                status,
                Json(ErrorResponse::new("Failed to scan prompt", code).with_details(error_msg)),
            )
        })?;

        let threats: Vec<ThreatDetection> = result
            .input_results
            .into_iter()
            .filter(|r| !r.is_valid)
            .map(|r| ThreatDetection {
                threat_type: r.scanner_name.clone(),
                confidence: r.score,
                description: if r.description.is_empty() {
                    format!("Detected potential {} issue", r.scanner_name)
                } else {
                    r.description
                },
                severity: r.severity,
            })
            .collect();

        (threats, result.risk_score, result.sanitized_prompt)
    } else {
        let options = GrpcScanOptions {
            check_injection: req.options.check_injection,
            check_toxicity: req.options.check_toxicity,
            check_pii: req.options.check_pii,
            sanitize: req.options.sanitize,
        };

        let result = client
            .scan_prompt(&req.prompt, options)
            .await
            .map_err(|e| {
                let error_msg = e.to_string();
                tracing::error!("ML scan failed: {}", error_msg);

                let (status, code) = match e.code() {
                    tonic::Code::DeadlineExceeded => (StatusCode::GATEWAY_TIMEOUT, "SCAN_TIMEOUT"),
                    tonic::Code::ResourceExhausted => {
                        (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED")
                    }
                    tonic::Code::InvalidArgument => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
                    tonic::Code::Unavailable => {
                        (StatusCode::SERVICE_UNAVAILABLE, "ML_SERVICE_UNAVAILABLE")
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "SCAN_FAILED"),
                };

                (
                    status,
                    Json(ErrorResponse::new("Failed to scan prompt", code).with_details(error_msg)),
                )
            })?;

        let threats: Vec<ThreatDetection> = result
            .threats
            .into_iter()
            .map(|t| ThreatDetection {
                threat_type: t.threat_type,
                confidence: t.confidence,
                description: t.description,
                severity: t.severity,
            })
            .collect();

        (threats, result.risk_score, result.sanitized_prompt)
    };

    let latency_ms = start.elapsed().as_millis() as u64;

    let threat_categories: Vec<String> = threats.iter().map(|t| t.threat_type.clone()).collect();

    let response_id = Uuid::new_v4();
    let response = ScanPromptResponse {
        id: response_id,
        safe: threats.is_empty(),
        sanitized_prompt: sanitized_prompt,
        threats,
        risk_score,
        latency_ms,
        cached: false,
        timestamp: Utc::now(),
        threat_categories: if threat_categories.is_empty() {
            None
        } else {
            Some(threat_categories.clone())
        },
    };

    if let Ok(json) = serde_json::to_string(&response) {
        if let Err(e) = redis_conn
            .set_ex::<_, _, ()>(&cache_key, &json, CACHE_TTL_SECONDS)
            .await
        {
            tracing::warn!("Failed to cache scan result: {}", e);
        }
    }

    let threats_json = serde_json::to_value(&response.threats).unwrap_or_default();
    let entry = GuardLogEntry::new_scan(
        Some(api_key.organization_id),
        Some(api_key.id),
        prompt_hash,
        response.safe,
        response.risk_score,
        threats_json,
        response.latency_ms as i32,
        false,
        extract_ip(&headers).map(|s| s.to_string()),
        Some(req.prompt.clone()),
        threat_categories,
        scan_options_json,
        user_agent,
        response.sanitized_prompt.clone(),
        Some(response_id),
    );
    state.write_buffer.queue(entry).await;

    Ok(Json(response))
}

fn extract_ip(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim())
}

fn quota_upgrade_hint() -> &'static str {
    "Upgrade your plan or add billing add-ons to continue."
}

fn billing_enforcement_unavailable_error(
    details: impl Into<String>,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(
            ErrorResponse::new(
                "Billing enforcement is temporarily unavailable. Requests are blocked to prevent quota bypass.",
                "BILLING_ENFORCEMENT_UNAVAILABLE",
            )
            .with_details(details),
        ),
    )
}

async fn lookup_organization_plan_quota(db: &sqlx::PgPool, organization_id: Uuid) -> u32 {
    use sqlx::Row;

    match sqlx::query(
        r#"
        SELECT s.plan_id
        FROM subscription s
        JOIN organization_member om ON om.user_id = s.user_id
        WHERE om.organization_id = $1
          AND s.status = 'active'
          AND s.current_period_end > NOW()
        ORDER BY s.current_period_end DESC
        LIMIT 1
        "#,
    )
    .bind(organization_id)
    .fetch_optional(db)
    .await
    {
        Ok(Some(row)) => {
            let quota: Option<i32> = row.get("monthly_quota");
            let plan: Option<String> = row.get("plan");

            let plan_str = plan.as_deref().unwrap_or("basic");
            if plan_str != "basic" {
                if let Some(q) = quota {
                    return q as u32;
                }
                return monthly_quota_for_plan(plan_str);
            }
            if let Some(q) = quota {
                let default_basic_quota = MONTHLY_QUOTA_BASIC as i32;
                if q != default_basic_quota {
                    return q as u32;
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to read api_key plan for {}: {}", api_key_id, e);
            return MONTHLY_QUOTA_BASIC;
        }
        _ => return MONTHLY_QUOTA_BASIC,
    }

    match sqlx::query(
        r#"
        SELECT s.plan_id, s.status, s.current_period_end
        FROM subscription s
        JOIN organization_member om ON om.user_id = s.user_id
        JOIN api_key ak ON ak.organization_id = om.organization_id
        WHERE ak.id = $1
          AND s.status = 'active'
          AND s.current_period_end > NOW()
        LIMIT 1
        "#,
    )
    .bind(api_key_id)
    .fetch_optional(db)
    .await
    {
        Ok(Some(row)) => {
            let plan: String = row.get("plan_id");
            return monthly_quota_for_plan(plan.trim().to_lowercase().as_str());
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(
                "Failed to resolve subscription quota for org {}: {}",
                organization_id,
                e
            );
        }
    }

    match sqlx::query("SELECT plan FROM organization WHERE id = $1")
        .bind(organization_id)
        .fetch_optional(db)
        .await
    {
        Ok(Some(row)) => {
            let plan: Option<String> = row.get("plan");
            monthly_quota_for_plan(plan.as_deref().unwrap_or("free_trial"))
        }
        Ok(None) => MONTHLY_QUOTA_FREE_TRIAL,
        Err(e) => {
            tracing::warn!(
                "Failed to resolve organization plan quota for org {}: {}",
                organization_id,
                e
            );
            MONTHLY_QUOTA_FREE_TRIAL
        }
    }
}

async fn lookup_api_key_quota(db: &sqlx::PgPool, api_key_id: Uuid) -> u32 {
    use sqlx::Row;

    let key_row =
        match sqlx::query("SELECT organization_id, plan, monthly_quota FROM api_key WHERE id = $1")
            .bind(api_key_id)
            .fetch_optional(db)
            .await
        {
            Ok(Some(row)) => row,
            Ok(None) => return MONTHLY_QUOTA_FREE_TRIAL,
            Err(e) => {
                tracing::warn!(
                    "Failed to read api_key quota metadata for {}: {}",
                    api_key_id,
                    e
                );
                return MONTHLY_QUOTA_FREE_TRIAL;
            }
        };

    let organization_id: Uuid = key_row.get("organization_id");
    let key_plan: Option<String> = key_row.get("plan");
    let key_quota: Option<i32> = key_row.get("monthly_quota");

    let org_limit = lookup_organization_plan_quota(db, organization_id).await;

    let mut key_cap: Option<u32> = None;

    if let Some(plan) = key_plan.as_deref() {
        let normalized = plan.trim().to_lowercase();
        if !normalized.is_empty() && normalized != "basic" {
            key_cap = Some(monthly_quota_for_plan(&normalized));
        }
    }

    if let Some(q) = key_quota {
        if q > 0 {
            let q = q as u32;
            if q != MONTHLY_QUOTA_BASIC {
                key_cap = Some(match key_cap {
                    Some(existing) => existing.min(q),
                    None => q,
                });
            }
        }
    }

    key_cap.map(|cap| cap.min(org_limit)).unwrap_or(org_limit)
}

pub async fn validate_output(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ValidateOutputRequest>,
) -> Result<Json<ValidateOutputResponse>, (StatusCode, Json<ErrorResponse>)> {
    let api_key = require_api_key_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    tracing::debug!(
        "Guard validate request from org: {}",
        api_key.organization_id
    );

    let rl_key = rate_limit_key(Some(&format!("{}", api_key.id)), None);
    let mut redis_conn = state.redis.clone();
    match check_rate_limit(
        &mut redis_conn,
        &rl_key,
        api_key.rate_limit_rpm as u32,
        RATE_LIMIT_WINDOW_SECONDS,
    )
    .await
    {
        Ok((allowed, remaining, retry_after)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(
                        ErrorResponse::new(
                            format!(
                                "Rate limit exceeded. {} requests per minute allowed. Retry after {} seconds.",
                                api_key.rate_limit_rpm, retry_after
                            ),
                            "RATE_LIMITED",
                        )
                        .with_details(format!(
                            "remaining: {}, retry_after: {}s",
                            remaining, retry_after
                        )),
                    ),
                ));
            }
            tracing::debug!(
                "Rate limit OK: {} remaining for key {}",
                remaining,
                api_key.id
            );
        }
        Err(e) => {
            tracing::error!("Rate limit check failed: {}", e);
            return Err(billing_enforcement_unavailable_error(format!(
                "rate_limit_check_failed: {}",
                e
            )));
        }
    }

    let org_quota_subject = format!("{}", api_key.organization_id);
    let monthly_limit = lookup_api_key_quota(&state.db, api_key.id).await;
    match check_monthly_quota(&mut redis_conn, &org_quota_subject, monthly_limit).await {
        Ok((allowed, used, limit, days_left)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(
                        ErrorResponse::new(
                            format!(
                                "Monthly quota exceeded. {}/{} requests used. Resets in {} days. {}",
                                used,
                                limit,
                                days_left,
                                quota_upgrade_hint()
                            ),
                            "QUOTA_EXCEEDED",
                        )
                        .with_details(format!(
                            "used: {}, limit: {}, resets_in_days: {}",
                            used, limit, days_left
                        )),
                    ),
                ));
            }
        }
        Err(e) => {
            tracing::error!("Monthly quota check failed: {}", e);
            return Err(billing_enforcement_unavailable_error(format!(
                "monthly_quota_check_failed: {}",
                e
            )));
        }
    }

    let start = std::time::Instant::now();
    let user_agent = extract_user_agent(&headers);

    let mut client = state.get_ml_client().await.map_err(|e| {
        tracing::error!("ML sidecar connection failed: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "ML validation service is currently unavailable",
                    "ML_SERVICE_UNAVAILABLE",
                )
                .with_details(e),
            ),
        )
    })?;

    let result = client
        .scan_output(&req.output, req.original_prompt.as_deref())
        .await
        .map_err(|e| {
            let error_msg = e.to_string();
            tracing::error!("ML output validation failed: {}", error_msg);

            let (status, code) = match e.code() {
                tonic::Code::DeadlineExceeded => {
                    (StatusCode::GATEWAY_TIMEOUT, "VALIDATION_TIMEOUT")
                }
                tonic::Code::ResourceExhausted => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
                tonic::Code::InvalidArgument => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
                tonic::Code::Unavailable => {
                    (StatusCode::SERVICE_UNAVAILABLE, "ML_SERVICE_UNAVAILABLE")
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "VALIDATION_FAILED"),
            };

            (
                status,
                Json(ErrorResponse::new("Failed to validate output", code).with_details(error_msg)),
            )
        })?;

    let latency_ms = start.elapsed().as_millis() as u64;

    let issues: Vec<OutputIssue> = result
        .issues
        .into_iter()
        .map(|i| OutputIssue {
            issue_type: i.issue_type,
            description: i.description,
            severity: i.severity,
        })
        .collect();

    let response_id = Uuid::new_v4();
    let is_safe = result.safe;
    let response = ValidateOutputResponse {
        id: response_id,
        safe: is_safe,
        sanitized_output: result.sanitized_output,
        issues,
        latency_ms,
    };

    let issue_categories: Vec<String> = response
        .issues
        .iter()
        .map(|i| i.issue_type.clone())
        .collect();
    let issues_json = serde_json::to_value(&response.issues).unwrap_or_default();
    let output_hash = hash_prompt(&req.output);

    let mut entry = GuardLogEntry::new_scan(
        Some(api_key.organization_id),
        Some(api_key.id),
        output_hash,
        is_safe,
        0.0,
        issues_json,
        latency_ms as i32,
        false,
        extract_ip(&headers).map(|s| s.to_string()),
        if !is_safe {
            Some(req.output.clone())
        } else {
            None
        },
        issue_categories,
        serde_json::json!({"type": "validate"}),
        user_agent,
        response.sanitized_output.clone(),
        Some(response_id),
    );
    entry.request_type = "validate".to_string();
    state.write_buffer.queue(entry).await;

    Ok(Json(response))
}

pub async fn batch_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BatchScanRequest>,
) -> Result<Json<BatchScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    let api_key = require_api_key_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    if req.prompts.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "At least one prompt is required",
                "EMPTY_BATCH",
            )),
        ));
    }

    if req.prompts.len() > MAX_BATCH_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                format!("Batch size exceeds maximum of {} prompts", MAX_BATCH_SIZE),
                "BATCH_TOO_LARGE",
            )),
        ));
    }

    let rl_key = rate_limit_key(Some(&format!("{}", api_key.id)), None);
    let mut redis_conn = state.redis.clone();
    let batch_size = req.prompts.len() as u32;

    match check_rate_limit_with_cost(
        &mut redis_conn,
        &rl_key,
        api_key.rate_limit_rpm as u32,
        RATE_LIMIT_WINDOW_SECONDS,
        batch_size,
    )
    .await
    {
        Ok((allowed, remaining, retry_after)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse::new(
                        format!(
                            "Rate limit exceeded. {} requests remaining, batch requires {}. Retry after {} seconds.",
                            remaining, batch_size, retry_after
                        ),
                        "RATE_LIMITED",
                    )),
                ));
            }
        }
        Err(e) => {
            tracing::error!("Rate limit check failed: {}", e);
            return Err(billing_enforcement_unavailable_error(format!(
                "rate_limit_check_failed: {}",
                e
            )));
        }
    }

    let org_quota_subject = format!("{}", api_key.organization_id);
    let monthly_limit = lookup_api_key_quota(&state.db, api_key.id).await;
    match check_monthly_quota_remaining(&mut redis_conn, &org_quota_subject, monthly_limit).await {
        Ok(remaining) => {
            if remaining < batch_size {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse::new(
                        format!(
                            "Monthly quota insufficient. {} requests remaining, batch requires {}.",
                            remaining, batch_size
                        ),
                        "QUOTA_EXCEEDED",
                    )
                    .with_details(quota_upgrade_hint()),
                    ),
                ));
            }
        }
        Err(e) => {
            tracing::error!("Monthly quota check failed: {}", e);
            return Err(billing_enforcement_unavailable_error(format!(
                "monthly_quota_check_failed: {}",
                e
            )));
        }
    }

    if let Err(e) = increment_monthly_quota(&mut redis_conn, &org_quota_subject, batch_size).await {
        tracing::error!("Monthly quota increment failed: {}", e);
        return Err(billing_enforcement_unavailable_error(format!(
            "monthly_quota_increment_failed: {}",
            e
        )));
    }

    let start = std::time::Instant::now();
    let user_agent = extract_user_agent(&headers);
    let client_ip = extract_ip(&headers).map(|s| s.to_string());

    let client = state.get_ml_client().await.map_err(|e| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "ML scanning service is currently unavailable",
                    "ML_SERVICE_UNAVAILABLE",
                )
                .with_details(e),
            ),
        )
    })?;


    let options = GrpcScanOptions {
        check_injection: req.options.check_injection,
        check_toxicity: req.options.check_toxicity,
        check_pii: req.options.check_pii,
        sanitize: req.options.sanitize,
    };

    let scan_options_json = serde_json::json!({
        "check_injection": req.options.check_injection,
        "check_toxicity": req.options.check_toxicity,
        "check_pii": req.options.check_pii,
        "sanitize": req.options.sanitize,
        "batch": true,
    });

    let scan_futures: Vec<_> = req
        .prompts
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let prompt = item.prompt.clone();
            let id = item.id.clone().unwrap_or_else(|| idx.to_string());
            let opts = options.clone();
            let mut client_clone = client.clone();

            async move {
                if prompt.trim().is_empty() {
                    return (
                        prompt,
                        BatchScanResultItem {
                            id,
                            success: false,
                            result: None,
                            error: Some("Prompt cannot be empty".to_string()),
                        },
                    );
                }

                if prompt.len() > 32 * 1024 {
                    return (
                        prompt,
                        BatchScanResultItem {
                            id,
                            success: false,
                            result: None,
                            error: Some("Prompt exceeds maximum length of 32KB".to_string()),
                        },
                    );
                }

                match client_clone.scan_prompt(&prompt, opts).await {
                    Ok(result) => {
                        let threats: Vec<ThreatDetection> = result
                            .threats
                            .into_iter()
                            .map(|t| ThreatDetection {
                                threat_type: t.threat_type,
                                confidence: t.confidence,
                                description: t.description,
                                severity: t.severity,
                            })
                            .collect();

                        let threat_cats: Vec<String> =
                            threats.iter().map(|t| t.threat_type.clone()).collect();

                        (
                            prompt,
                            BatchScanResultItem {
                                id,
                                success: true,
                                result: Some(ScanPromptResponse {
                                    id: Uuid::new_v4(),
                                    safe: result.safe,
                                    sanitized_prompt: result.sanitized_prompt,
                                    threats,
                                    risk_score: result.risk_score,
                                    latency_ms: 0,
                                    cached: false,
                                    timestamp: Utc::now(),
                                    threat_categories: if threat_cats.is_empty() {
                                        None
                                    } else {
                                        Some(threat_cats)
                                    },
                                }),
                                error: None,
                            },
                        )
                    }
                    Err(e) => (
                        prompt,
                        BatchScanResultItem {
                            id,
                            success: false,
                            result: None,
                            error: Some(e.message().to_string()),
                        },
                    ),
                }
            }
        })
        .collect();

    let results_with_prompts = join_all(scan_futures).await;

    let total_latency_ms = start.elapsed().as_millis() as u64;

    for (prompt, item) in &results_with_prompts {
        if let Some(ref scan_result) = item.result {
            let threats_json = serde_json::to_value(&scan_result.threats).unwrap_or_default();
            let threat_cats: Vec<String> = scan_result
                .threats
                .iter()
                .map(|t| t.threat_type.clone())
                .collect();
            let prompt_hash = hash_prompt(prompt);

            let mut entry = GuardLogEntry::new_scan(
                Some(api_key.organization_id),
                Some(api_key.id),
                prompt_hash,
                scan_result.safe,
                scan_result.risk_score,
                threats_json,
                total_latency_ms as i32, // batch total
                false,
                client_ip.clone(),
                Some(prompt.clone()),
                threat_cats,
                scan_options_json.clone(),
                user_agent.clone(),
                scan_result.sanitized_prompt.clone(),
                Some(scan_result.id),
            );
            entry.request_type = "batch".to_string();
            state.write_buffer.queue(entry).await;
        }
    }

    let results: Vec<BatchScanResultItem> = results_with_prompts
        .into_iter()
        .map(|(_, item)| item)
        .collect();

    let total = results.len();
    let successful = results.iter().filter(|r| r.success).count();
    let failed = total - successful;

    tracing::info!(
        "Batch scan completed: {} total, {} successful, {} failed, {}ms",
        total,
        successful,
        failed,
        total_latency_ms
    );

    Ok(Json(BatchScanResponse {
        total,
        successful,
        failed,
        results,
        total_latency_ms,
    }))
}

#[derive(Debug, Deserialize)]
pub struct AdvancedScanRequest {
    #[serde(default)]
    pub prompt: String,
    #[serde(default)]
    pub output: String,
    #[serde(default)]
    pub scan_mode: ApiScanMode,
    #[serde(default)]
    pub input_scanners: HashMap<String, ApiScannerConfig>,
    #[serde(default)]
    pub output_scanners: HashMap<String, ApiScannerConfig>,
    #[serde(default)]
    pub sanitize: bool,
    #[serde(default)]
    pub fail_fast: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdvancedScannerResult {
    pub scanner_name: String,
    pub is_valid: bool,
    pub score: f32,
    pub description: String,
    pub severity: String,
    pub scanner_latency_ms: i32,
}

impl From<ScannerResultInfo> for AdvancedScannerResult {
    fn from(r: ScannerResultInfo) -> Self {
        Self {
            scanner_name: r.scanner_name,
            is_valid: r.is_valid,
            score: r.score,
            description: r.description,
            severity: r.severity,
            scanner_latency_ms: r.scanner_latency_ms,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AdvancedScanResponse {
    pub id: Uuid,
    pub safe: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitized_prompt: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitized_output: Option<String>,

    pub risk_score: f32,

    pub scan_mode: ApiScanMode,

    pub input_results: Vec<AdvancedScannerResult>,

    pub output_results: Vec<AdvancedScannerResult>,

    pub latency_ms: u64,

    pub input_scanners_run: i32,
    pub output_scanners_run: i32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_categories: Option<Vec<String>>,

    pub cached: bool,
    pub timestamp: DateTime<Utc>,
}

impl From<GuardScannerEntry> for ApiScannerConfig {
    fn from(e: GuardScannerEntry) -> Self {
        Self {
            enabled: e.enabled,
            threshold: e.threshold,
            settings_json: e.settings_json,
        }
    }
}

fn parse_scan_mode(s: &str) -> Option<ApiScanMode> {
    match s {
        "prompt_only" => Some(ApiScanMode::PromptOnly),
        "output_only" => Some(ApiScanMode::OutputOnly),
        "both" => Some(ApiScanMode::Both),
        _ => None,
    }
}

struct ResolvedScanConfig {
    scan_mode: ApiScanMode,
    input_scanners: HashMap<String, ApiScannerConfig>,
    output_scanners: HashMap<String, ApiScannerConfig>,
    sanitize: bool,
    fail_fast: bool,
}

fn resolve_scan_config(
    api_key: &ApiKeyInfo,
    headers: &HeaderMap,
    req: &AdvancedScanRequest,
) -> Result<ResolvedScanConfig, (StatusCode, Json<ErrorResponse>)> {
    let req_has_input_scanners = !req.input_scanners.is_empty();
    let req_has_output_scanners = !req.output_scanners.is_empty();

    let body_has_explicit_config = req_has_input_scanners || req_has_output_scanners;

    match (&api_key.guard_config, body_has_explicit_config) {
        (Some(gc), false) => {
            let key_mode = parse_scan_mode(&gc.scan_mode).unwrap_or(ApiScanMode::PromptOnly);
            let effective_mode = if key_mode == ApiScanMode::Both {
                headers
                    .get("X-Scan-Type")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| parse_scan_mode(s))
                    .unwrap_or(key_mode)
            } else {
                key_mode
            };

            let input_scanners: HashMap<String, ApiScannerConfig> = gc
                .input_scanners
                .iter()
                .map(|(k, v)| (k.clone(), ApiScannerConfig::from(v.clone())))
                .collect();
            let output_scanners: HashMap<String, ApiScannerConfig> = gc
                .output_scanners
                .iter()
                .map(|(k, v)| (k.clone(), ApiScannerConfig::from(v.clone())))
                .collect();

            Ok(ResolvedScanConfig {
                scan_mode: effective_mode,
                input_scanners,
                output_scanners,
                sanitize: gc.sanitize,
                fail_fast: gc.fail_fast,
            })
        }
        _ => {
            let input_scanners: HashMap<String, ApiScannerConfig> = req
                .input_scanners
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let output_scanners: HashMap<String, ApiScannerConfig> = req
                .output_scanners
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            Ok(ResolvedScanConfig {
                scan_mode: req.scan_mode,
                input_scanners,
                output_scanners,
                sanitize: req.sanitize,
                fail_fast: req.fail_fast,
            })
        }
    }
}

pub async fn advanced_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdvancedScanRequest>,
) -> Result<Json<AdvancedScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    let api_key = require_api_key_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let resolved = resolve_scan_config(&api_key, &headers, &req)?;

    tracing::debug!(
        "Advanced scan request from org: {}, mode: {:?}, key_config: {}",
        api_key.organization_id,
        resolved.scan_mode,
        if api_key.guard_config.is_some() {
            "per-key"
        } else {
            "per-request"
        }
    );

    match resolved.scan_mode {
        ApiScanMode::PromptOnly | ApiScanMode::Both => {
            if req.prompt.trim().is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new(
                        "Prompt is required for prompt_only or both scan modes",
                        "MISSING_PROMPT",
                    )),
                ));
            }
        }
        _ => {}
    }

    match resolved.scan_mode {
        ApiScanMode::OutputOnly | ApiScanMode::Both => {
            if req.output.trim().is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new(
                        "Output is required for output_only or both scan modes",
                        "MISSING_OUTPUT",
                    )),
                ));
            }
        }
        _ => {}
    }

    const MAX_TEXT_LEN: usize = 64 * 1024;
    if req.prompt.len() > MAX_TEXT_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Prompt exceeds maximum length of 64KB",
                "PROMPT_TOO_LONG",
            )),
        ));
    }
    if req.output.len() > MAX_TEXT_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Output exceeds maximum length of 64KB",
                "OUTPUT_TOO_LONG",
            )),
        ));
    }

    let rl_key = rate_limit_key(Some(&format!("{}", api_key.id)), None);
    let mut redis_conn = state.redis.clone();
    match check_rate_limit(
        &mut redis_conn,
        &rl_key,
        api_key.rate_limit_rpm as u32,
        RATE_LIMIT_WINDOW_SECONDS,
    )
    .await
    {
        Ok((allowed, remaining, retry_after)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse::new(
                        format!(
                            "Rate limit exceeded. {} RPM allowed. Retry after {}s.",
                            api_key.rate_limit_rpm, retry_after
                        ),
                        "RATE_LIMITED",
                    )),
                ));
            }
            tracing::debug!(
                "Rate limit OK: {} remaining for key {}",
                remaining,
                api_key.id
            );
        }
        Err(e) => {
            tracing::error!("Rate limit check failed: {}", e);
            return Err(billing_enforcement_unavailable_error(format!(
                "rate_limit_check_failed: {}",
                e
            )));
        }
    }

    let org_quota_subject = format!("{}", api_key.organization_id);
    let monthly_limit = lookup_api_key_quota(&state.db, api_key.id).await;
    match check_monthly_quota(&mut redis_conn, &org_quota_subject, monthly_limit).await {
        Ok((allowed, used, limit, days_left)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse::new(
                        format!(
                            "Monthly quota exceeded. {}/{} used. Resets in {} days. {}",
                            used,
                            limit,
                            days_left,
                            quota_upgrade_hint()
                        ),
                        "QUOTA_EXCEEDED",
                    )),
                ));
            }
        }
        Err(e) => {
            tracing::error!("Monthly quota check failed: {}", e);
            return Err(billing_enforcement_unavailable_error(format!(
                "monthly_quota_check_failed: {}",
                e
            )));
        }
    }

    let start = std::time::Instant::now();
    let user_agent = extract_user_agent(&headers);

    let grpc_input_scanners: HashMap<String, GrpcScannerConfigEntry> = resolved
        .input_scanners
        .into_iter()
        .map(|(k, v)| (k, v.into()))
        .collect();

    let grpc_output_scanners: HashMap<String, GrpcScannerConfigEntry> = resolved
        .output_scanners
        .into_iter()
        .map(|(k, v)| (k, v.into()))
        .collect();

    let grpc_opts = GrpcAdvancedScanOptions {
        prompt: req.prompt.clone(),
        output: req.output.clone(),
        scan_mode: resolved.scan_mode.into(),
        input_scanners: grpc_input_scanners,
        output_scanners: grpc_output_scanners,
        sanitize: resolved.sanitize,
        fail_fast: resolved.fail_fast,
    };

    let mut client = state.get_ml_client().await.map_err(|e| {
        tracing::error!("ML sidecar connection failed: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "ML scanning service is currently unavailable",
                    "ML_SERVICE_UNAVAILABLE",
                )
                .with_details(e),
            ),
        )
    })?;

    let result = client.advanced_scan(grpc_opts).await.map_err(|e| {
        let error_msg = e.to_string();
        tracing::error!("ML advanced scan failed: {}", error_msg);

        let (status, code) = match e.code() {
            tonic::Code::DeadlineExceeded => (StatusCode::GATEWAY_TIMEOUT, "SCAN_TIMEOUT"),
            tonic::Code::ResourceExhausted => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
            tonic::Code::InvalidArgument => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
            tonic::Code::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "ML_SERVICE_UNAVAILABLE"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "SCAN_FAILED"),
        };

        (
            status,
            Json(ErrorResponse::new("Advanced scan failed", code).with_details(error_msg)),
        )
    })?;

    let latency_ms = start.elapsed().as_millis() as u64;

    // ── Build threat categories from all failing scanners ──────
    let mut threat_categories: Vec<String> = Vec::new();
    for r in &result.input_results {
        if !r.is_valid {
            threat_categories.push(r.scanner_name.clone());
        }
    }
    for r in &result.output_results {
        if !r.is_valid {
            threat_categories.push(r.scanner_name.clone());
        }
    }

    let response_id = Uuid::new_v4();
    let response = AdvancedScanResponse {
        id: response_id,
        safe: result.safe,
        sanitized_prompt: result.sanitized_prompt,
        sanitized_output: result.sanitized_output,
        risk_score: result.risk_score,
        scan_mode: result.scan_mode.into(),
        input_results: result
            .input_results
            .into_iter()
            .map(AdvancedScannerResult::from)
            .collect(),
        output_results: result
            .output_results
            .into_iter()
            .map(AdvancedScannerResult::from)
            .collect(),
        latency_ms,
        input_scanners_run: result.input_scanners_run,
        output_scanners_run: result.output_scanners_run,
        threat_categories: if threat_categories.is_empty() {
            None
        } else {
            Some(threat_categories.clone())
        },
        cached: false,
        timestamp: Utc::now(),
    };

    let scan_mode_str = match resolved.scan_mode {
        ApiScanMode::PromptOnly => "advanced_prompt",
        ApiScanMode::OutputOnly => "advanced_output",
        ApiScanMode::Both => "advanced_both",
    };

    let hash_input = if !req.prompt.is_empty() {
        &req.prompt
    } else {
        &req.output
    };
    let prompt_hash = hash_prompt(hash_input);

    let threats_json = serde_json::json!({
        "input_results": &response.input_results,
        "output_results": &response.output_results,
    });

    let scan_options_json = serde_json::json!({
        "scan_mode": scan_mode_str,
        "sanitize": resolved.sanitize,
        "fail_fast": resolved.fail_fast,
        "input_scanners_run": response.input_scanners_run,
        "output_scanners_run": response.output_scanners_run,
        "config_source": if api_key.guard_config.is_some() { "per_key" } else { "per_request" },
    });

    let mut entry = GuardLogEntry::new_scan(
        Some(api_key.organization_id),
        Some(api_key.id),
        prompt_hash,
        response.safe,
        response.risk_score,
        threats_json,
        latency_ms as i32,
        false,
        extract_ip(&headers).map(|s| s.to_string()),
        if !response.safe {
            Some(req.prompt.clone())
        } else {
            None
        },
        threat_categories,
        scan_options_json,
        user_agent,
        response.sanitized_prompt.clone(),
        Some(response_id),
    );
    entry.request_type = scan_mode_str.to_string();
    state.write_buffer.queue(entry).await;

    Ok(Json(response))
}
