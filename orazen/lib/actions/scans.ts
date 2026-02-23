"use server";

import type {
  CustomEndpointConfig,
  GarakProbeInfo,
  GarakProbeCategory,
} from "@/lib/api";
import { scanApi } from "@/lib/api";

export interface Scan {
  id: string;
  organizationId: string | null;
  modelConfigId: string | null;
  scanType: string;
  status: string;
  progress: number;
  probesTotal: number;
  probesCompleted: number;
  vulnerabilitiesFound: number;
  riskScore: number | null;
  errorMessage: string | null;
  startedAt: string | null;
  completedAt: string | null;
  createdBy: string | null;
  createdAt: string;
}

export interface ScanResult {
  id: string;
  probeName: string;
  category: string;
  severity: string;
  description: string;
  attackPrompt: string;
  modelResponse: string;
  recommendation: string;
  successRate?: number | null;
  detectorName?: string | null;
  probeClass?: string | null;
  probeDurationMs?: number | null;
  confirmed?: boolean | null;
  retestCount?: number;
  retestConfirmed?: number;
}

export interface RetestInput {
  vulnerabilityId: string;
  provider: string;
  model: string;
  apiKey?: string;
  baseUrl?: string;
  numAttempts?: number;
}

export interface RetestResult {
  vulnerabilityId: string;
  probeName: string;
  totalAttempts: number;
  vulnerableCount: number;
  safeCount: number;
  confirmationRate: number;
  confirmed: boolean | null;
  results: Array<{
    attemptNumber: number;
    isVulnerable: boolean;
    modelResponse: string;
    detectorScore: number;
    durationMs: number;
    errorMessage?: string;
  }>;
  status: string;
  errorMessage?: string;
}

export interface ProbeLog {
  id: string;
  probeName: string;
  probeClass: string | null;
  status: string;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  promptsSent: number;
  promptsPassed: number;
  promptsFailed: number;
  detectorName: string | null;
  errorMessage: string | null;
  logLines: string[];
}

export interface ScanLogSummary {
  totalProbes: number;
  probesPassed: number;
  probesFailed: number;
  probesErrored: number;
  totalPromptsSent: number;
  totalDurationMs: number;
}

export interface ScanLogsResult {
  scanId: string;
  logs: ProbeLog[];
  summary: ScanLogSummary;
}

export interface StartScanInput {
  modelConfigId?: string;
  scanType: "quick" | "standard" | "comprehensive" | "custom";
  provider: string;
  model: string;
  apiKey?: string;
  baseUrl?: string;
  probes?: string[];
  customEndpoint?: CustomEndpointConfig;
  maxPromptsPerProbe?: number;
}

export interface ProbeListResult {
  categories: GarakProbeCategory[];
  probes: GarakProbeInfo[];
}

/**
 * Start a new vulnerability scan via Rust API
 * Calls Rust API: POST /v1/scan/start
 */
export async function startScan(input: StartScanInput): Promise<
  | {
      scanId: string;
      status: string;
      estimatedDuration: number;
    }
  | { error: string }
> {
  const { data, error } = await scanApi.startScan({
    model_config: {
      provider: input.provider,
      model: input.model,
      api_key: input.apiKey,
      base_url: input.baseUrl,
    },
    scan_type: input.scanType,
    probes: input.probes ?? [],
    custom_endpoint: input.customEndpoint,
    max_prompts_per_probe: input.maxPromptsPerProbe,
  });

  if (error) {
    return { error: error.message };
  }

  return {
    scanId: data.scan_id,
    status: data.status,
    estimatedDuration: data.estimated_duration_seconds,
  };
}

/**
 * Cancel a running scan via Rust API
 * Calls Rust API: POST /v1/scan/{scanId}/cancel
 */
export async function cancelScan(
  scanId: string,
): Promise<{ status: string; message: string } | { error: string }> {
  const { data, error } = await scanApi.cancelScan(scanId);

  if (error) {
    return { error: error.message };
  }

  return {
    status: data.status,
    message: data.message,
  };
}

/**
 * Get scan status via Rust API
 * Calls Rust API: GET /v1/scan/{scanId}
 */
export async function getScanStatus(scanId: string): Promise<
  | {
      scanId: string;
      status: string;
      progress: number;
      probesCompleted: number;
      probesTotal: number;
      vulnerabilitiesFound: number;
      errorMessage?: string;
    }
  | { error: string }
> {
  const { data, error } = await scanApi.getScanStatus(scanId);

  if (error) {
    return { error: error.message };
  }

  return {
    scanId: data.scan_id,
    status: data.status,
    progress: data.progress,
    probesCompleted: data.probes_completed,
    probesTotal: data.probes_total,
    vulnerabilitiesFound: data.vulnerabilities_found,
    errorMessage: data.error_message ?? undefined,
  };
}

/**
 * List recent scans for the current user
 * Calls Rust API: GET /v1/scan/list
 */
export async function listScans(limit = 20): Promise<Scan[]> {
  const { data, error } = await scanApi.listScans(limit);
  if (error) {
    console.error("Failed to list scans:", error.message);
    return [];
  }
  return data.scans.map((s) => ({
    id: s.id,
    organizationId: s.organization_id,
    modelConfigId: s.model_config_id,
    scanType: s.scan_type,
    status: s.status,
    progress: s.progress,
    probesTotal: s.probes_total,
    probesCompleted: s.probes_completed,
    vulnerabilitiesFound: s.vulnerabilities_found,
    riskScore: s.risk_score,
    errorMessage: s.error_message,
    startedAt: s.started_at,
    completedAt: s.completed_at,
    createdBy: s.created_by,
    createdAt: s.created_at,
  }));
}

/**
 * Get scan results
 * Calls Rust API: GET /v1/scan/{scanId}/results
 */
export async function getScanResults(scanId: string): Promise<ScanResult[]> {
  const { data, error } = await scanApi.getScanResults(scanId);
  if (error) {
    console.error("Failed to get scan results:", error.message);
    return [];
  }
  return data.vulnerabilities.map((v) => ({
    id: v.id,
    probeName: v.probe_name,
    category: v.category,
    severity: v.severity,
    description: v.description,
    attackPrompt: v.attack_prompt,
    modelResponse: v.model_response,
    recommendation: v.recommendation,
    successRate: v.success_rate,
    detectorName: v.detector_name,
    probeClass: v.probe_class,
    probeDurationMs: v.probe_duration_ms,
    confirmed: v.confirmed,
    retestCount: v.retest_count,
    retestConfirmed: v.retest_confirmed,
  }));
}

/**
 * Retest a specific vulnerability by re-running the same attack prompt multiple times
 * Calls Rust API: POST /v1/scan/retest
 */
export async function retestVulnerability(
  input: RetestInput,
): Promise<RetestResult | { error: string }> {
  const { data, error } = await scanApi.retestVulnerability({
    vulnerability_id: input.vulnerabilityId,
    model_config: {
      provider: input.provider,
      model: input.model,
      api_key: input.apiKey,
      base_url: input.baseUrl,
    },
    num_attempts: input.numAttempts ?? 3,
  });

  if (error) {
    return { error: error.message };
  }

  return {
    vulnerabilityId: data.vulnerability_id,
    probeName: data.probe_name,
    totalAttempts: data.total_attempts,
    vulnerableCount: data.vulnerable_count,
    safeCount: data.safe_count,
    confirmationRate: data.confirmation_rate,
    confirmed: data.confirmed,
    results: data.results.map((r) => ({
      attemptNumber: r.attempt_number,
      isVulnerable: r.is_vulnerable,
      modelResponse: r.model_response,
      detectorScore: r.detector_score,
      durationMs: r.duration_ms,
      errorMessage: r.error_message,
    })),
    status: data.status,
    errorMessage: data.error_message,
  };
}

/**
 * Get detailed per-probe execution logs for a scan
 * Calls Rust API: GET /v1/scan/{scanId}/logs
 */
/**
 * List all available Garak probes with metadata for the probe picker UI
 * Calls Rust API: GET /v1/scan/probes
 */
export async function listProbes(): Promise<ProbeListResult> {
  const { data, error } = await scanApi.listProbes();
  if (error) {
    console.error("Failed to list probes:", error.message);
    return { categories: [], probes: [] };
  }
  return {
    categories: data.categories,
    probes: data.probes,
  };
}

export async function getScanLogs(
  scanId: string,
): Promise<ScanLogsResult | { error: string }> {
  const { data, error } = await scanApi.getScanLogs(scanId);

  if (error) {
    return { error: error.message };
  }

  return {
    scanId: data.scan_id,
    logs: data.logs.map((l) => ({
      id: l.id,
      probeName: l.probe_name,
      probeClass: l.probe_class,
      status: l.status,
      startedAt: l.started_at,
      completedAt: l.completed_at,
      durationMs: l.duration_ms,
      promptsSent: l.prompts_sent,
      promptsPassed: l.prompts_passed,
      promptsFailed: l.prompts_failed,
      detectorName: l.detector_name,
      errorMessage: l.error_message,
      logLines: l.log_lines,
    })),
    summary: {
      totalProbes: data.summary.total_probes,
      probesPassed: data.summary.probes_passed,
      probesFailed: data.summary.probes_failed,
      probesErrored: data.summary.probes_errored,
      totalPromptsSent: data.summary.total_prompts_sent,
      totalDurationMs: data.summary.total_duration_ms,
    },
  };
}
