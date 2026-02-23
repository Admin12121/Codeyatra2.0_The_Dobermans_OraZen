"use server";

import {
  guardApi,
  apiClientWithKey,
  type ScanPromptResponse,
  type ListGuardLogsParams,
  type ApiScanMode,
  type ApiScannerConfig,
} from "@/lib/api";

// ============================================
// Guard Log Types (camelCase for frontend use)
// ============================================

export interface GuardLog {
  id: string;
  organizationId: string;
  apiKeyId: string | null;
  promptHash: string;
  isSafe: boolean;
  riskScore: number | null;
  threatsDetected: unknown;
  threatCategories: string[] | null;
  latencyMs: number | null;
  cached: boolean | null;
  ipAddress: string | null;
  requestType: string | null;
  userAgent: string | null;
  scanOptions: unknown | null;
  responseId: string | null;
  /** Full prompt text — only populated for threats (null for safe prompts) */
  promptText: string | null;
  sanitizedPrompt: string | null;
  createdAt: string;
}

export interface PaginationInfo {
  page: number;
  perPage: number;
  totalItems: number;
  totalPages: number;
  nextCursor: string | null;
  hasNext: boolean;
  hasPrev: boolean;
}

export interface GuardLogsResult {
  logs: GuardLog[];
  pagination: PaginationInfo;
}

// ============================================
// Scan Prompt Types
// ============================================

export interface ScanPromptInput {
  prompt: string;
  apiKey: string;
  options?: {
    checkInjection?: boolean;
    checkToxicity?: boolean;
    checkPii?: boolean;
    sanitize?: boolean;
  };
}

export interface ScanPromptResult {
  id: string;
  safe: boolean;
  sanitizedPrompt?: string;
  threats: Array<{
    threatType: string;
    confidence: number;
    description: string;
    severity: string;
  }>;
  threatCategories?: string[];
  riskScore: number;
  latencyMs: number;
  cached: boolean;
}

// ============================================
// Advanced Scan Types
// ============================================

export type ScanMode = "prompt_only" | "output_only" | "both";

export interface ScannerConfigInput {
  enabled: boolean;
  threshold: number;
  settingsJson: string;
}

export interface AdvancedScanInput {
  prompt?: string;
  output?: string;
  apiKey: string;
  scanMode: ScanMode;
  inputScanners: Record<string, ScannerConfigInput>;
  outputScanners: Record<string, ScannerConfigInput>;
  sanitize?: boolean;
  failFast?: boolean;
}

export interface AdvancedScannerResultItem {
  scannerName: string;
  isValid: boolean;
  score: number;
  description: string;
  severity: string;
  scannerLatencyMs: number;
}

export interface AdvancedScanResult {
  id: string;
  safe: boolean;
  sanitizedPrompt?: string;
  sanitizedOutput?: string;
  riskScore: number;
  scanMode: ScanMode;
  inputResults: AdvancedScannerResultItem[];
  outputResults: AdvancedScannerResultItem[];
  latencyMs: number;
  inputScannersRun: number;
  outputScannersRun: number;
  threatCategories?: string[];
  cached: boolean;
}

// ============================================
// Stats Types
// ============================================

export interface TypeBreakdownItem {
  requestType: string;
  count: number;
}

export interface CategoryCountItem {
  category: string;
  count: number;
}

export interface GuardStats {
  totalScans: number;
  threatsBlocked: number;
  safePrompts: number;
  avgLatency: number;
  byType?: TypeBreakdownItem[];
  topCategories?: CategoryCountItem[];
}

// ============================================
// Actions
// ============================================

/**
 * Scan a prompt using the Guard API (for testing in dashboard)
 * Calls Rust API: POST /v1/guard/scan (with API key auth)
 */
export async function scanPrompt(
  input: ScanPromptInput,
): Promise<ScanPromptResult | { error: string }> {
  const { data, error } = await apiClientWithKey<ScanPromptResponse>(
    "/v1/guard/scan",
    input.apiKey,
    {
      method: "POST",
      body: JSON.stringify({
        prompt: input.prompt,
        options: {
          check_injection: input.options?.checkInjection ?? true,
          check_toxicity: input.options?.checkToxicity ?? true,
          check_pii: input.options?.checkPii ?? true,
          sanitize: input.options?.sanitize ?? false,
        },
      }),
    },
  );

  if (error) {
    return { error: error.message };
  }

  return {
    id: data.id,
    safe: data.safe,
    sanitizedPrompt: data.sanitized_prompt,
    threats: data.threats.map((t) => ({
      threatType: t.threat_type,
      confidence: t.confidence,
      description: t.description,
      severity: t.severity,
    })),
    threatCategories: data.threat_categories ?? undefined,
    riskScore: data.risk_score,
    latencyMs: data.latency_ms,
    cached: data.cached,
  };
}

/**
 * Advanced scan with full per-scanner configuration.
 * Calls Rust API: POST /v1/guard/advanced-scan (with API key auth)
 *
 * Supports all LLM Guard input and output scanners with per-scanner
 * enable/disable, thresholds, and scanner-specific settings.
 * The scan_mode field controls prompt-only, output-only, or both.
 */
export async function advancedScan(
  input: AdvancedScanInput,
): Promise<AdvancedScanResult | { error: string }> {
  // Convert frontend camelCase scanner configs to API snake_case
  const inputScanners: Record<string, ApiScannerConfig> = {};
  for (const [name, cfg] of Object.entries(input.inputScanners)) {
    inputScanners[name] = {
      enabled: cfg.enabled,
      threshold: cfg.threshold,
      settings_json: cfg.settingsJson,
    };
  }

  const outputScanners: Record<string, ApiScannerConfig> = {};
  for (const [name, cfg] of Object.entries(input.outputScanners)) {
    outputScanners[name] = {
      enabled: cfg.enabled,
      threshold: cfg.threshold,
      settings_json: cfg.settingsJson,
    };
  }

  const apiScanMode: ApiScanMode = input.scanMode;

  const { data, error } = await guardApi.advancedScan(input.apiKey, {
    prompt: input.prompt,
    output: input.output,
    scan_mode: apiScanMode,
    input_scanners: inputScanners,
    output_scanners: outputScanners,
    sanitize: input.sanitize ?? false,
    fail_fast: input.failFast ?? false,
  });

  if (error) {
    return { error: error.message };
  }

  return {
    id: data.id,
    safe: data.safe,
    sanitizedPrompt: data.sanitized_prompt ?? undefined,
    sanitizedOutput: data.sanitized_output ?? undefined,
    riskScore: data.risk_score,
    scanMode: data.scan_mode as ScanMode,
    inputResults: data.input_results.map((r) => ({
      scannerName: r.scanner_name,
      isValid: r.is_valid,
      score: r.score,
      description: r.description,
      severity: r.severity,
      scannerLatencyMs: r.scanner_latency_ms,
    })),
    outputResults: data.output_results.map((r) => ({
      scannerName: r.scanner_name,
      isValid: r.is_valid,
      score: r.score,
      description: r.description,
      severity: r.severity,
      scannerLatencyMs: r.scanner_latency_ms,
    })),
    latencyMs: data.latency_ms,
    inputScannersRun: data.input_scanners_run,
    outputScannersRun: data.output_scanners_run,
    threatCategories: data.threat_categories ?? undefined,
    cached: data.cached,
  };
}

/**
 * List guard logs for the current organization with pagination and filters
 * Calls Rust API: GET /v1/guard/logs
 *
 * @param params - Query parameters for filtering and pagination
 */
export async function listGuardLogs(
  params: {
    page?: number;
    perPage?: number;
    status?: "safe" | "threat";
    requestType?: "scan" | "validate" | "batch";
    category?: string;
    ip?: string;
    cursor?: string;
    from?: string;
    to?: string;
  } = {},
): Promise<GuardLogsResult> {
  const apiParams: ListGuardLogsParams = {
    page: params.page,
    per_page: params.perPage,
    status: params.status,
    request_type: params.requestType,
    category: params.category,
    ip: params.ip,
    cursor: params.cursor,
    from: params.from,
    to: params.to,
  };

  const { data, error } = await guardApi.listLogs(apiParams);

  if (error) {
    console.error("Failed to list guard logs:", error.message);
    return {
      logs: [],
      pagination: {
        page: 1,
        perPage: params.perPage ?? 50,
        totalItems: 0,
        totalPages: 1,
        nextCursor: null,
        hasNext: false,
        hasPrev: false,
      },
    };
  }

  return {
    logs: data.logs.map((log) => ({
      id: log.id,
      organizationId: log.organization_id,
      apiKeyId: log.api_key_id,
      promptHash: log.prompt_hash,
      isSafe: log.is_safe,
      riskScore: log.risk_score,
      threatsDetected: log.threats_detected,
      threatCategories: log.threat_categories,
      latencyMs: log.latency_ms,
      cached: log.cached,
      ipAddress: log.ip_address,
      requestType: log.request_type,
      userAgent: log.user_agent,
      scanOptions: log.scan_options,
      responseId: log.response_id,
      promptText: log.prompt_text,
      sanitizedPrompt: log.sanitized_prompt,
      createdAt: log.created_at,
    })),
    pagination: {
      page: data.pagination.page,
      perPage: data.pagination.per_page,
      totalItems: data.pagination.total_items,
      totalPages: data.pagination.total_pages,
      nextCursor: data.pagination.next_cursor,
      hasNext: data.pagination.has_next,
      hasPrev: data.pagination.has_prev,
    },
  };
}

/**
 * Get guard statistics with optional time period filter
 * Calls Rust API: GET /v1/guard/stats
 *
 * @param period - Optional time filter: "today", "24h", "48h", "3d", "7d", "30d"
 */
export async function getGuardStats(period?: string): Promise<GuardStats> {
  const { data, error } = await guardApi.getStats(period);

  if (error) {
    console.error("Failed to get guard stats:", error.message);
    return {
      totalScans: 0,
      threatsBlocked: 0,
      safePrompts: 0,
      avgLatency: 0,
    };
  }

  return {
    totalScans: data.total_scans,
    threatsBlocked: data.threats_blocked,
    safePrompts: data.safe_prompts,
    avgLatency: data.avg_latency,
    byType: data.by_type?.map((t) => ({
      requestType: t.request_type,
      count: t.count,
    })),
    topCategories: data.top_categories?.map((c) => ({
      category: c.category,
      count: c.count,
    })),
  };
}
