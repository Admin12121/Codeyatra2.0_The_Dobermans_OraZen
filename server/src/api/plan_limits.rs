use uuid::Uuid;

pub fn normalize_plan_id(plan: &str) -> &'static str {
    match plan.trim().to_lowercase().as_str() {
        "free" | "free_trial" => "free_trial",
        "starter" | "basic" => "starter",
        "pro" | "team" => "pro",
        "enterprise" => "enterprise",
        _ => "free_trial",
    }
}

pub fn plan_display_name(plan: &str) -> &'static str {
    match normalize_plan_id(plan) {
        "free_trial" => "Free Trial",
        "starter" => "Starter",
        "pro" => "Pro",
        "enterprise" => "Enterprise",
        _ => "Free Trial",
    }
}

pub fn api_key_limit_for_plan(plan: &str) -> Option<i64> {
    match normalize_plan_id(plan) {
        "free_trial" => Some(1),
        "starter" => Some(3),
        "pro" => Some(10),
        "enterprise" => None,
        _ => Some(1),
    }
}

pub fn model_config_limit_for_plan(plan: &str) -> Option<i64> {
    match normalize_plan_id(plan) {
        "free_trial" => Some(3),
        "starter" => Some(5),
        "pro" => Some(20),
        "enterprise" => None,
        _ => Some(3),
    }
}

pub async fn resolve_effective_plan(
    db: &sqlx::PgPool,
    organization_id: Uuid,
) -> Result<String, sqlx::Error> {
    let plan = sqlx::query_scalar::<_, String>(
        r#"
        SELECT COALESCE(
            (
                SELECT s.plan_id
                FROM subscription s
                WHERE s.user_id = o.owner_id
                  AND s.status = 'active'
                  AND s.current_period_end > NOW()
                ORDER BY s.updated_at DESC
                LIMIT 1
            ),
            o.plan,
            'free_trial'
        ) AS effective_plan
        FROM organization o
        WHERE o.id = $1
        "#,
    )
    .bind(organization_id)
    .fetch_optional(db)
    .await?;

    Ok(normalize_plan_id(
        plan.as_deref().unwrap_or("free_trial"),
    )
    .to_string())
}
