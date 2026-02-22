use axum::{Json, extract::State};
use serde::Serialize;

use super::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub services: ServiceStatus,
}

#[derive(Serialize)]
pub struct ServiceStatus {
    pub database: bool,
    pub redis: bool,
    pub ml_sidecar: MlSidecarStatus,
}

#[derive(Serialize)]
pub struct MlSidecarStatus {
    pub healthy: bool,
    pub version: Option<String>,
}

#[derive(Serialize)]
pub struct PingResponse {
    pub status: &'static str,
}

pub async fn ping() -> Json<PingResponse> {
    Json(PingResponse { status: "ok" })
}

pub async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    let db_healthy = sqlx::query("SELECT 1").fetch_one(&state.db).await.is_ok();

    let mut redis_conn = state.redis.clone();
    let redis_healthy = redis::cmd("PING")
        .query_async::<String>(&mut redis_conn)
        .await
        .is_ok();

    let ml_status = match state.get_ml_client().await {
        Ok(mut client) => match client.health_check().await {
            Ok(info) => MlSidecarStatus {
                healthy: info.healthy,
                version: Some(info.version),
            },
            Err(_) => MlSidecarStatus {
                healthy: false,
                version: None,
            },
        },
        Err(_) => MlSidecarStatus {
            healthy: false,
            version: None,
        },
    };

    let all_healthy = db_healthy && redis_healthy && ml_status.healthy;

    Json(HealthResponse {
        status: if all_healthy {
            "healthy".to_string()
        } else {
            "degraded".to_string()
        },
        version: env!("CARGO_PKG_VERSION").to_string(),
        services: ServiceStatus {
            database: db_healthy,
            redis: redis_healthy,
            ml_sidecar: ml_status,
        },
    })
}
