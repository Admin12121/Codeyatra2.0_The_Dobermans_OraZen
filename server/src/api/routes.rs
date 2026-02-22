use axum::{
    Router,
    routing::{delete, get, post, put},
};

use super::AppState;
use super::{api_keys, auth, events, guard, guard_logs, models, organization, scan};


pub fn v1_routes() -> Router<AppState> {
    Router::new()
        // ========================================
        // Public: Auth verification endpoints
        // ========================================
        .route("/auth/verify", post(auth::verify_session))
        .route("/auth/api-key/verify", post(auth::verify_api_key))
        // ========================================
        // LLM Guard: API Key auth (external apps)
        // ========================================
        .route("/guard/scan", post(guard::scan_prompt))
        .route("/guard/batch", post(guard::batch_scan))
        .route("/guard/validate", post(guard::validate_output))
        .route("/guard/advanced-scan", post(guard::advanced_scan))
        // ========================================
        // Guard Logs: Session auth (dashboard)
        // ========================================
        .route("/guard/logs", get(guard_logs::list_guard_logs))
        .route("/guard/stats", get(guard_logs::get_guard_stats))
        // ========================================
        // Guard Events: SSE real-time stream
        // ========================================
        .route("/guard/events/ticket", post(events::create_sse_ticket))
        .route("/guard/events", get(events::guard_events))
        // ========================================
        // Garak Scanner: Session auth (users)
        // ========================================
        .route("/scan/start", post(scan::start_scan))
        .route("/scan/list", get(scan::list_scans))
        .route("/scan/probes", get(scan::list_probes))
        .route("/scan/retest", post(scan::retest_vulnerability))
        .route("/scan/{scan_id}", get(scan::get_scan_status))
        .route("/scan/{scan_id}/cancel", post(scan::cancel_scan))
        .route("/scan/{scan_id}/results", get(scan::get_scan_results))
        .route("/scan/{scan_id}/logs", get(scan::get_scan_logs))
        .route("/scan/{scan_id}/events", get(scan::scan_events))
        // ========================================
        // API Key Management: Session auth
        // ========================================
        .route("/api-keys", post(api_keys::create_api_key))
        .route("/api-keys", get(api_keys::list_api_keys))
        .route("/api-keys/{key_id}", delete(api_keys::revoke_api_key))
        .route(
            "/api-keys/{key_id}/guard-config",
            get(api_keys::get_guard_config),
        )
        .route(
            "/api-keys/{key_id}/guard-config",
            put(api_keys::update_guard_config),
        )
        // ========================================
        // Model Configuration: Session auth
        // ========================================
        .route("/models", post(models::create_model_config))
        .route("/models", get(models::list_model_configs))
        .route("/models/{model_id}", put(models::update_model_config))
        .route("/models/{model_id}", delete(models::delete_model_config))
        .route("/models/{model_id}/default", put(models::set_default_model))
        // ========================================
        // Organization: Session auth
        // ========================================
        .route(
            "/organization",
            post(organization::get_or_create_organization),
        )
        .route("/organization", get(organization::get_current_organization))
        .route(
            "/organization/usage",
            get(organization::get_organization_usage),
        )
}
