use sqlx::{PgPool, Row};
use uuid::Uuid;

#[allow(dead_code)]
pub async fn log_guard_scan(
    pool: &PgPool,
    org_id: Option<Uuid>,
    api_key_id: Option<Uuid>,
    prompt_hash: &str,
    is_safe: bool,
    risk_score: f32,
    threats: &serde_json::Value,
    latency_ms: i32,
    cached: bool,
    ip_address: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    let row = sqlx::query(
        r#"
        INSERT INTO guard_log (
            organization_id, api_key_id, prompt_hash, is_safe,
            risk_score, threats_detected, latency_ms, cached, ip_address
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
    )
    .bind(org_id)
    .bind(api_key_id)
    .bind(prompt_hash)
    .bind(is_safe)
    .bind(risk_score)
    .bind(threats)
    .bind(latency_ms)
    .bind(cached)
    .bind(ip_address)
    .fetch_one(pool)
    .await?;

    Ok(row.get("id"))
}
