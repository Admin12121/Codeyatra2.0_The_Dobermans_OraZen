"use server";

import { organizationApi, type OrganizationResponse } from "@/lib/api";

export type Organization = OrganizationResponse;

export interface OrganizationUsage {
  organizationId: string;
  plan: string | null;
  /** Total LLM Guard scans in the current billing period */
  guardScansUsed: number;
  /** Total Garak vulnerability scans in the current billing period */
  garakScansUsed: number;
  /** Number of active (non-revoked) API keys */
  apiKeysUsed: number;
  /** Number of model configurations */
  modelConfigsUsed: number;
  /** Total threats blocked in the current billing period */
  threatsBlocked: number;
  /** Average guard scan latency in ms */
  avgLatencyMs: number;
  /** Billing period start (ISO 8601) */
  billingPeriodStart: string;
  /** Billing period end (ISO 8601) */
  billingPeriodEnd: string;
}

/**
 * Get or create organization for current user
 * Calls Rust API: POST /v1/organization
 */
export async function getOrCreateOrganization(): Promise<Organization | null> {
  const { data, error } = await organizationApi.getOrCreate();
  if (error) {
    console.error("Failed to get/create organization:", error.message);
    return null;
  }
  return data;
}

/**
 * Get current user's organization
 * Calls Rust API: GET /v1/organization
 */
export async function getCurrentOrganization(): Promise<Organization | null> {
  const { data, error } = await organizationApi.getCurrent();
  if (error) {
    if (error.status === 404) return null;
    throw new Error(error.message);
  }
  return data;
}

/**
 * Get organization usage statistics for the current billing period.
 * Returns guard scan counts, Garak scan counts, API key counts,
 * model config counts, threats blocked, and average latency.
 *
 * Calls Rust API: GET /v1/organization/usage
 */
export async function getOrganizationUsage(): Promise<OrganizationUsage | null> {
  const { data, error } = await organizationApi.getUsage();
  if (error) {
    if (error.status === 404) return null;
    console.error("Failed to get organization usage:", error.message);
    return null;
  }
  return {
    organizationId: data.organization_id,
    plan: data.plan,
    guardScansUsed: data.guard_scans_used,
    garakScansUsed: data.garak_scans_used,
    apiKeysUsed: data.api_keys_used,
    modelConfigsUsed: data.model_configs_used,
    threatsBlocked: data.threats_blocked,
    avgLatencyMs: data.avg_latency_ms,
    billingPeriodStart: data.billing_period_start,
    billingPeriodEnd: data.billing_period_end,
  };
}
