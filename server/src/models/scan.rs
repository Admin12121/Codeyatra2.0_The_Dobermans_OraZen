use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Scan {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub model_config_id: Option<Uuid>,
    pub scan_type: String,
    pub status: ScanStatus,
    pub progress: i32,
    pub probes_total: i32,
    pub probes_completed: i32,
    pub vulnerabilities_found: i32,
    pub risk_score: Option<f32>,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub probe_name: String,
    pub category: String,
    pub severity: Severity,
    pub description: String,
    pub attack_prompt: Option<String>,
    pub model_response: Option<String>,
    pub recommendation: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}
