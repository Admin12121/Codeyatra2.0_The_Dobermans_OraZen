use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub async fn append_scan_chain_block(
    db: &PgPool,
    organization_id: Uuid,
    scan_id: Uuid,
    record_type: &str,
    record_id: Option<Uuid>,
    payload: &Value,
) -> Result<String, sqlx::Error> {
    let stream_key = format!("garak:scan:{}", scan_id);
    let canonical_payload = canonicalize_json(payload);
    let payload_str =
        serde_json::to_string(&canonical_payload).unwrap_or_else(|_| "{}".to_string());
    let payload_hash = sha256_hex(payload_str.as_bytes());
    let created_at = Utc::now();

    let mut tx = db.begin().await?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(&stream_key)
        .execute(&mut *tx)
        .await?;

    let previous = sqlx::query(
        r#"
        SELECT block_index, block_hash
        FROM immutable_audit_chain
        WHERE stream_key = $1
        ORDER BY block_index DESC
        LIMIT 1
        "#,
    )
    .bind(&stream_key)
    .fetch_optional(&mut *tx)
    .await?;

    let (block_index, previous_hash) = match previous {
        Some(row) => {
            let idx: i64 = row.get("block_index");
            let prev_hash: String = row.get("block_hash");
            (idx + 1, prev_hash)
        }
        None => (0, GENESIS_HASH.to_string()),
    };

    let block_material = format!(
        "{}|{}|{}|{}|{}",
        stream_key,
        block_index,
        previous_hash,
        payload_hash,
        created_at.timestamp_millis()
    );
    let block_hash = sha256_hex(block_material.as_bytes());

    sqlx::query(
        r#"
        INSERT INTO immutable_audit_chain (
            organization_id,
            scan_id,
            stream_key,
            block_index,
            record_type,
            record_id,
            payload,
            payload_hash,
            previous_hash,
            block_hash,
            created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(organization_id)
    .bind(scan_id)
    .bind(&stream_key)
    .bind(block_index)
    .bind(record_type)
    .bind(record_id)
    .bind(&canonical_payload)
    .bind(&payload_hash)
    .bind(&previous_hash)
    .bind(&block_hash)
    .bind(created_at.naive_utc())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(block_hash)
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort_unstable();

            let mut canonical = serde_json::Map::new();
            for key in keys {
                if let Some(v) = map.get(&key) {
                    canonical.insert(key, canonicalize_json(v));
                }
            }
            Value::Object(canonical)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}
