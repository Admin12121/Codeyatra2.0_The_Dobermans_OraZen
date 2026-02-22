"use server";

import { apiKeysApi } from "@/lib/api";
import type { GuardConfig } from "@/lib/api";

export interface ApiKey {
  id: string;
  organizationId: string;
  name: string;
  keyPrefix: string;
  scopes: string[] | null;
  rateLimitRpm: number | null;
  lastUsedAt: string | null;
  expiresAt: string | null;
  revokedAt: string | null;
  createdBy: string;
  createdAt: string;
  guardConfig: GuardConfig | null;
}

export interface GuardConfigResult {
  keyId: string;
  keyName: string;
  guardConfig: GuardConfig | null;
}

export async function createApiKey(
  name: string,
  scopes: string[] = [],
  guardConfig?: GuardConfig | null,
): Promise<{ key: string; id: string }> {
  const { data, error } = await apiKeysApi.create({
    name,
    scopes,
    guard_config: guardConfig ?? undefined,
  });
  if (error) {
    throw new Error(error.message);
  }
  return { key: data.key, id: data.id };
}

export async function listApiKeys(): Promise<ApiKey[]> {
  const { data, error } = await apiKeysApi.list();
  if (error) {
    console.error("Failed to list API keys:", error.message);
    return [];
  }
  return data.keys.map((k) => ({
    id: k.id,
    organizationId: k.organization_id,
    name: k.name,
    keyPrefix: k.key_prefix,
    scopes: k.scopes,
    rateLimitRpm: k.rate_limit_rpm,
    lastUsedAt: k.last_used_at,
    expiresAt: k.expires_at,
    revokedAt: k.revoked_at,
    createdBy: k.created_by,
    createdAt: k.created_at,
    guardConfig: k.guard_config ?? null,
  }));
}

export async function revokeApiKey(keyId: string): Promise<boolean> {
  const { data, error } = await apiKeysApi.revoke(keyId);
  if (error) {
    throw new Error(error.message);
  }
  return data.success;
}

export async function getGuardConfig(
  keyId: string,
): Promise<GuardConfigResult> {
  const { data, error } = await apiKeysApi.getGuardConfig(keyId);
  if (error) {
    throw new Error(error.message);
  }
  return {
    keyId: data.key_id,
    keyName: data.key_name,
    guardConfig: data.guard_config ?? null,
  };
}

export async function updateGuardConfig(
  keyId: string,
  guardConfig: GuardConfig | null,
): Promise<{ success: boolean; guardConfig: GuardConfig | null }> {
  const { data, error } = await apiKeysApi.updateGuardConfig(keyId, {
    guard_config: guardConfig,
  });
  if (error) {
    throw new Error(error.message);
  }
  return {
    success: data.success,
    guardConfig: data.guard_config ?? null,
  };
}
