-- PostgreSQL

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE payment_status AS ENUM ('pending', 'completed', 'failed', 'refunded', 'expired');
CREATE TYPE subscription_status AS ENUM ('active', 'expired', 'cancelled', 'past_due');

CREATE TABLE IF NOT EXISTS "user" (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    image TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    two_factor_enabled BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS session (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_session_token ON session(token);
CREATE INDEX IF NOT EXISTS idx_session_user_id ON session(user_id);
CREATE INDEX IF NOT EXISTS idx_session_expires ON session(expires_at);

CREATE TABLE IF NOT EXISTS account (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    access_token_expires_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    scope TEXT,
    id_token TEXT,
    password TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(provider_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_account_user_id ON account(user_id);

CREATE TABLE IF NOT EXISTS verification (
    id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,
    value TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verification_identifier ON verification(identifier);

CREATE TABLE IF NOT EXISTS two_factor (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    secret TEXT,
    backup_codes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_two_factor_user_id ON two_factor(user_id);

CREATE TABLE IF NOT EXISTS passkey (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    name TEXT,
    public_key TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    device_type TEXT,
    backed_up BOOLEAN DEFAULT FALSE,
    transports TEXT,
    aaguid TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_passkey_user_id ON passkey(user_id);
CREATE INDEX IF NOT EXISTS idx_passkey_credential_id ON passkey(credential_id);

CREATE TABLE IF NOT EXISTS organization (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    owner_id TEXT NOT NULL REFERENCES "user"(id),
    plan TEXT DEFAULT 'free',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_organization_owner ON organization(owner_id);
CREATE INDEX IF NOT EXISTS idx_organization_slug ON organization(slug);

CREATE TABLE IF NOT EXISTS organization_member (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_member_org ON organization_member(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_member_user ON organization_member(user_id);

CREATE TABLE IF NOT EXISTS api_key (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    scopes TEXT[] DEFAULT '{}',
    rate_limit_rpm INTEGER DEFAULT 1000,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    created_by TEXT NOT NULL REFERENCES "user"(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    plan TEXT DEFAULT 'basic',
    monthly_quota INTEGER DEFAULT 100000,
    guard_config JSONB DEFAULT NULL,
    CONSTRAINT chk_guard_config_scan_mode CHECK (
        guard_config IS NULL
        OR guard_config->>'scan_mode' IN ('prompt_only', 'output_only', 'both')
    )
);

CREATE INDEX IF NOT EXISTS idx_api_key_org ON api_key(organization_id);
CREATE INDEX IF NOT EXISTS idx_api_key_hash ON api_key(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_key_guard_config
    ON api_key USING GIN (guard_config)
    WHERE guard_config IS NOT NULL;

CREATE TABLE IF NOT EXISTS model_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    api_key_encrypted TEXT,
    base_url TEXT,
    settings JSONB DEFAULT '{}',
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_config_org ON model_config(organization_id);

CREATE TABLE IF NOT EXISTS scan (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organization(id) ON DELETE SET NULL,
    model_config_id UUID REFERENCES model_config(id),
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    progress INTEGER DEFAULT 0,
    probes_total INTEGER DEFAULT 0,
    probes_completed INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    risk_score REAL,
    error_message TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_by TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    provider TEXT,
    model TEXT,
    base_url TEXT,
    remote_scan_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_org ON scan(organization_id);
CREATE INDEX IF NOT EXISTS idx_scan_status ON scan(status);
CREATE INDEX IF NOT EXISTS idx_scan_remote_id ON scan(remote_scan_id) WHERE remote_scan_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS scan_result (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    probe_name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    attack_prompt TEXT,
    model_response TEXT,
    recommendation TEXT,
    raw_data JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    success_rate REAL,
    detector_name TEXT,
    attempts_count INTEGER DEFAULT 1,
    retest_count INTEGER DEFAULT 0,
    retest_confirmed INTEGER DEFAULT 0,
    confirmed BOOLEAN,
    probe_class TEXT,
    probe_duration_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scan_result_scan ON scan_result(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_result_severity ON scan_result(severity);
CREATE INDEX IF NOT EXISTS idx_scan_result_confirmed ON scan_result(confirmed) WHERE confirmed IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_result_success_rate ON scan_result(success_rate DESC NULLS LAST);

CREATE TABLE IF NOT EXISTS guard_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    api_key_id UUID REFERENCES api_key(id),
    prompt_hash TEXT NOT NULL,
    is_safe BOOLEAN NOT NULL,
    risk_score REAL,
    threats_detected JSONB DEFAULT '[]',
    latency_ms INTEGER,
    cached BOOLEAN DEFAULT FALSE,
    ip_address TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    prompt_text TEXT,
    threat_categories TEXT[] DEFAULT '{}',
    scan_options JSONB DEFAULT '{}',
    user_agent TEXT,
    request_type TEXT DEFAULT 'scan',
    sanitized_prompt TEXT,
    response_id UUID
);

CREATE INDEX IF NOT EXISTS idx_guard_log_org ON guard_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_guard_log_created ON guard_log(created_at);
CREATE INDEX IF NOT EXISTS idx_guard_log_safe ON guard_log(is_safe);
CREATE INDEX IF NOT EXISTS idx_guard_log_org_created ON guard_log(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_guard_log_org_safe ON guard_log(organization_id, is_safe, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_guard_log_request_type ON guard_log(request_type);
CREATE INDEX IF NOT EXISTS idx_guard_log_threat_categories ON guard_log USING GIN(threat_categories);

CREATE TABLE IF NOT EXISTS usage_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    guard_scans INTEGER DEFAULT 0,
    vulnerability_scans INTEGER DEFAULT 0,
    api_requests INTEGER DEFAULT 0,
    UNIQUE(organization_id, date)
);

CREATE INDEX IF NOT EXISTS idx_usage_log_org_date ON usage_log(organization_id, date);

CREATE TABLE IF NOT EXISTS scan_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    probe_name TEXT NOT NULL,
    probe_class TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    duration_ms INTEGER,
    prompts_sent INTEGER DEFAULT 0,
    prompts_passed INTEGER DEFAULT 0,
    prompts_failed INTEGER DEFAULT 0,
    detector_name TEXT,
    detector_scores JSONB DEFAULT '[]',
    error_message TEXT,
    log_entries JSONB DEFAULT '[]',
    raw_config JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_log_scan ON scan_log(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_log_status ON scan_log(status);
CREATE INDEX IF NOT EXISTS idx_scan_log_probe ON scan_log(probe_name);

CREATE TABLE IF NOT EXISTS scan_retest (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_result_id UUID NOT NULL REFERENCES scan_result(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    probe_name TEXT NOT NULL,
    attempt_number INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending',
    attack_prompt TEXT,
    model_response TEXT,
    detector_score REAL,
    is_vulnerable BOOLEAN,
    duration_ms INTEGER,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_retest_original ON scan_retest(original_result_id);
CREATE INDEX IF NOT EXISTS idx_scan_retest_scan ON scan_retest(scan_id);

CREATE TABLE IF NOT EXISTS payment (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    transaction_uuid TEXT UNIQUE NOT NULL,
    product_code TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    tax_amount INTEGER NOT NULL DEFAULT 0,
    total_amount INTEGER NOT NULL,
    status payment_status NOT NULL DEFAULT 'pending',
    esewa_ref_id TEXT,
    esewa_response_raw TEXT,
    period_start TIMESTAMP,
    period_end TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payment_user_id ON payment(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_transaction_uuid ON payment(transaction_uuid);
CREATE INDEX IF NOT EXISTS idx_payment_status ON payment(status);
CREATE INDEX IF NOT EXISTS idx_payment_created_at ON payment(created_at);

CREATE TABLE IF NOT EXISTS subscription (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE REFERENCES "user"(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL DEFAULT 'free_trial',
    status subscription_status NOT NULL DEFAULT 'active',
    current_payment_id TEXT REFERENCES payment(id),
    current_period_start TIMESTAMP NOT NULL DEFAULT NOW(),
    current_period_end TIMESTAMP NOT NULL,
    auto_renew BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subscription_user_id ON subscription(user_id);
CREATE INDEX IF NOT EXISTS idx_subscription_status ON subscription(status);
CREATE INDEX IF NOT EXISTS idx_subscription_period_end ON subscription(current_period_end);
