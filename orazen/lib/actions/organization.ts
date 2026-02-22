"use server";

import { organizationApi, type OrganizationResponse } from "@/lib/api";

export type Organization = OrganizationResponse;

export interface OrganizationUsage {
  organizationId: string;
  plan: string | null;
  guardScansUsed: number;
  garakScansUsed: number;
  apiKeysUsed: number;
  modelConfigsUsed: number;
  threatsBlocked: number;
  avgLatencyMs: number;
  billingPeriodStart: string;
  billingPeriodEnd: string;
}

export async function getOrCreateOrganization(): Promise<Organization | null> {
  const { data, error } = await organizationApi.getOrCreate();
  if (error) {
    console.error("Failed to get/create organization:", error.message);
    return null;
  }
  return data;
}

export async function getCurrentOrganization(): Promise<Organization | null> {
  const { data, error } = await organizationApi.getCurrent();
  if (error) {
    if (error.status === 404) return null;
    throw new Error(error.message);
  }
  return data;
}

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
