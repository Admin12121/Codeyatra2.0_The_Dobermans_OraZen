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

// NOTE: Do NOT export types from "use server" modules.
// Next.js transforms all exports into server-action RPC stubs,
// which causes `ReferenceError: GuardConfig is not defined` at runtime.
// Import GuardConfig / GuardScannerEntry directly from "@/lib/api" instead.

export interface GuardConfigResult {
  keyId: string;
  keyName: string;
  guardConfig: GuardConfig | null;
}

export type CreateApiKeyResult =
  | {
      ok: true;
      key: string;
      id: string;
    }
  | {
      ok: false;
      error: string;
      code?: string;
    };

/**
 * Create a new API key
 * Calls Rust API: POST /v1/api-keys
 */
export async function createApiKey(
  name: string,
  scopes: string[] = [],
  guardConfig?: GuardConfig | null,
): Promise<CreateApiKeyResult> {
  const { data, error } = await apiKeysApi.create({
    name,
    scopes,
    guard_config: guardConfig ?? undefined,
  });
  if (error) {
    return {
      ok: false,
      error: error.message,
      code: error.code,
    };
  }
  return {
    ok: true,
    key: data.key,
    id: data.id,
  };
}

/**
 * List all API keys for the current organization
 * Calls Rust API: GET /v1/api-keys
 */
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

/**
 * Revoke an API key
 * Calls Rust API: DELETE /v1/api-keys/{keyId}
 */
export async function revokeApiKey(keyId: string): Promise<boolean> {
  const { data, error } = await apiKeysApi.revoke(keyId);
  if (error) {
    throw new Error(error.message);
  }
  return data.success;
}

/**
 * Get the guard configuration for a specific API key
 * Calls Rust API: GET /v1/api-keys/{keyId}/guard-config
 */
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

/**
 * Update the guard configuration for a specific API key.
 * Pass `null` as guardConfig to remove the config (revert to legacy
 * per-request behaviour where the caller must specify scanners each time).
 *
 * Calls Rust API: PUT /v1/api-keys/{keyId}/guard-config
 */
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
