"use server";

import { modelsApi } from "@/lib/api";
import type { UpdateModelConfigRequest } from "@/lib/api";

export interface ModelConfig {
  id: string;
  organizationId: string;
  name: string;
  provider: string;
  model: string;
  baseUrl: string | null;
  settings: unknown;
  isDefault: boolean | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateModelInput {
  name: string;
  provider: string;
  model: string;
  apiKey?: string;
  baseUrl?: string;
  settings?: Record<string, unknown>;
  isDefault?: boolean;
}

export interface UpdateModelInput {
  name?: string;
  provider?: string;
  model?: string;
  apiKey?: string;
  baseUrl?: string;
  settings?: Record<string, unknown>;
  clearApiKey?: boolean;
  clearBaseUrl?: boolean;
}

function mapModelConfig(m: {
  id: string;
  organization_id: string;
  name: string;
  provider: string;
  model: string;
  base_url: string | null;
  settings: unknown;
  is_default: boolean | null;
  created_at: string;
  updated_at: string;
}): ModelConfig {
  return {
    id: m.id,
    organizationId: m.organization_id,
    name: m.name,
    provider: m.provider,
    model: m.model,
    baseUrl: m.base_url,
    settings: m.settings,
    isDefault: m.is_default,
    createdAt: m.created_at,
    updatedAt: m.updated_at,
  };
}

export async function createModelConfig(
  input: CreateModelInput,
): Promise<ModelConfig> {
  const { data, error } = await modelsApi.create({
    name: input.name,
    provider: input.provider,
    model: input.model,
    api_key: input.apiKey,
    base_url: input.baseUrl,
    settings: input.settings,
    is_default: input.isDefault,
  });
  if (error) {
    throw new Error(error.message);
  }
  return mapModelConfig(data);
}

export async function updateModelConfig(
  modelId: string,
  input: UpdateModelInput,
): Promise<ModelConfig> {
  const payload: UpdateModelConfigRequest = {};
  if (input.name !== undefined) payload.name = input.name;
  if (input.provider !== undefined) payload.provider = input.provider;
  if (input.model !== undefined) payload.model = input.model;
  if (input.apiKey !== undefined) payload.api_key = input.apiKey;
  if (input.baseUrl !== undefined) payload.base_url = input.baseUrl;
  if (input.settings !== undefined) payload.settings = input.settings;
  if (input.clearApiKey) payload.clear_api_key = true;
  if (input.clearBaseUrl) payload.clear_base_url = true;

  const { data, error } = await modelsApi.update(modelId, payload);
  if (error) {
    throw new Error(error.message);
  }
  return mapModelConfig(data);
}

export async function listModelConfigs(): Promise<ModelConfig[]> {
  const { data, error } = await modelsApi.list();
  if (error) {
    console.error("Failed to list model configs:", error.message);
    return [];
  }
  return data.models.map(mapModelConfig);
}

export async function deleteModelConfig(modelId: string): Promise<boolean> {
  const { data, error } = await modelsApi.delete(modelId);
  if (error) {
    throw new Error(error.message);
  }
  return data.success;
}


export async function setDefaultModel(modelId: string): Promise<boolean> {
  const { data, error } = await modelsApi.setDefault(modelId);
  if (error) {
    throw new Error(error.message);
  }
  return data.success;
}
