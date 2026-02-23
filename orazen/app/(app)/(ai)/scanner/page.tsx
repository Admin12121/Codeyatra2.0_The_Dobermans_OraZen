"use client";

import { useState, useEffect, useCallback } from "react";
import {
  IconRadar,
  IconPlayerPlay,
  IconLoader2,
  IconCheck,
  IconX,
  IconAlertTriangle,
  IconInfoCircle,
  IconRefresh,
  IconEye,
  IconEyeOff,
  IconChevronDown,
  IconChevronRight,
  IconShieldCheck,
  IconBug,
  IconLock,
  IconAlertOctagon,
  IconDatabase,
  IconGhost,
  IconFilter,
  IconSettings,
  IconAdjustments,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  startScan,
  listScans,
  getScanStatus,
  listProbes,
  cancelScan,
} from "@/lib/actions/scans";
import { IconPlayerStop } from "@tabler/icons-react";
import type { ProbeListResult } from "@/lib/actions/scans";
import { listModelConfigs, type ModelConfig } from "@/lib/actions/models";
import type {
  GarakProbeInfo,
  GarakProbeCategory,
  CustomEndpointConfig,
} from "@/lib/api";
import Link from "next/link";
import LiveScanMonitor from "./_components/live-scan-monitor";

interface ScanDisplay {
  id: string;
  scanType: string;
  status: string;
  progress: number;
  vulnerabilitiesFound: number;
  riskScore: number | null;
  createdAt: string;
}

const SCAN_PRESETS = [
  {
    value: "quick",
    label: "Quick Scan",
    desc: "Fast check — injection + jailbreak basics",
  },
  {
    value: "standard",
    label: "Standard Scan",
    desc: "Covers injection, encoding, leakage, toxicity, hallucination",
  },
  {
    value: "comprehensive",
    label: "Comprehensive",
    desc: "All available probe categories",
  },
  {
    value: "custom",
    label: "Custom Selection",
    desc: "Choose exactly which probes to run",
  },
];

const PROVIDERS = [
  { value: "openai", label: "OpenAI", placeholder: "gpt-4o, gpt-4-turbo" },
  {
    value: "anthropic",
    label: "Anthropic",
    placeholder: "claude-3-opus-20240229",
  },
  {
    value: "huggingface",
    label: "Hugging Face",
    placeholder: "meta-llama/Llama-2-70b-chat-hf",
  },
  { value: "ollama", label: "Ollama (Local)", placeholder: "llama2, mistral" },
  { value: "groq", label: "Groq", placeholder: "llama-3.1-70b-versatile" },
  {
    value: "together",
    label: "Together AI",
    placeholder: "meta-llama/Llama-3-70b-chat-hf",
  },
  {
    value: "openrouter",
    label: "OpenRouter",
    placeholder: "anthropic/claude-3-opus",
  },
  {
    value: "custom",
    label: "Custom REST API",
    placeholder: "your-model-name",
  },
];

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  injection: <IconAlertOctagon className="w-4 h-4" />,
  jailbreak: <IconLock className="w-4 h-4" />,
  toxicity: <IconAlertTriangle className="w-4 h-4" />,
  data_leakage: <IconDatabase className="w-4 h-4" />,
  hallucination: <IconGhost className="w-4 h-4" />,
  malware: <IconBug className="w-4 h-4" />,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
  "high-critical": "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  "medium-high": "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-lime-400 bg-lime-500/10 border-lime-500/30",
};

function getSeverityColor(severity: string): string {
  return (
    SEVERITY_COLORS[severity] ||
    "text-stone-400 bg-stone-500/10 border-stone-500/30"
  );
}

export default function ScannerPage() {
  const [scans, setScans] = useState<ScanDisplay[]>([]);
  const [models, setModels] = useState<ModelConfig[]>([]);
  const [isStarting, setIsStarting] = useState(false);
  const [isCancelling, setIsCancelling] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [monitoringScanId, setMonitoringScanId] = useState<string | null>(null);

  // Input mode: "saved" = use saved model config, "manual" = enter details manually
  const [inputMode, setInputMode] = useState<"saved" | "manual">("saved");

  // Probe data from backend
  const [probeData, setProbeData] = useState<ProbeListResult>({
    categories: [],
    probes: [],
  });
  const [probesLoaded, setProbesLoaded] = useState(false);

  // Selected probes (probe_id -> enabled)
  const [selectedProbes, setSelectedProbes] = useState<Record<string, boolean>>(
    {},
  );
  // Expanded categories in the probe picker
  const [expandedCategories, setExpandedCategories] = useState<
    Record<string, boolean>
  >({});

  // Form state
  const [form, setForm] = useState({
    modelId: "",
    scanType: "standard",
    provider: "openai",
    model: "",
    apiKey: "",
    baseUrl: "",
  });

  // Custom endpoint config
  const [customEndpoint, setCustomEndpoint] = useState<CustomEndpointConfig>({
    url: "",
    method: "POST",
    request_template: '{"prompt": "{{prompt}}"}',
    response_path: "response",
  });

  // Advanced settings
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [maxPromptsPerProbe, setMaxPromptsPerProbe] = useState(25);

  const selectedProvider = PROVIDERS.find((p) => p.value === form.provider);

  // Load data on mount
  useEffect(() => {
    loadData();
    loadProbes();
  }, []);

  // Poll running scans for status updates (skip the one the live monitor handles)
  useEffect(() => {
    const runningScans = scans.filter(
      (s) =>
        (s.status === "running" || s.status === "pending") &&
        s.id !== monitoringScanId,
    );
    if (runningScans.length === 0) return;

    const interval = setInterval(async () => {
      for (const scan of runningScans) {
        const result = await getScanStatus(scan.id);
        if (!("error" in result)) {
          setScans((prev) =>
            prev.map((s) =>
              s.id === scan.id
                ? {
                    ...s,
                    status: result.status,
                    progress: result.progress,
                    vulnerabilitiesFound: result.vulnerabilitiesFound,
                  }
                : s,
            ),
          );
        }
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [scans, monitoringScanId]);

  // Callback: live monitor feeds its real-time data back into the scan history row
  const handleLiveProgress = useCallback(
    (liveProgress: {
      status: string;
      progress: number;
      probesCompleted: number;
      probesTotal: number;
      vulnerabilitiesFound: number;
    }) => {
      if (!monitoringScanId) return;
      setScans((prev) =>
        prev.map((s) =>
          s.id === monitoringScanId
            ? {
                ...s,
                status: liveProgress.status,
                progress: liveProgress.progress,
                vulnerabilitiesFound: liveProgress.vulnerabilitiesFound,
              }
            : s,
        ),
      );
    },
    [monitoringScanId],
  );

  // When scan type changes, update selected probes
  useEffect(() => {
    if (!probesLoaded) return;

    if (form.scanType === "custom") {
      // Don't auto-change — let user pick
      return;
    }

    // For presets, select probes based on the preset
    const newSelected: Record<string, boolean> = {};
    for (const probe of probeData.probes) {
      if (form.scanType === "comprehensive") {
        newSelected[probe.id] = true;
      } else if (form.scanType === "quick") {
        newSelected[probe.id] =
          probe.id === "promptinject" || probe.id === "dan";
      } else {
        // standard
        newSelected[probe.id] = probe.default_enabled;
      }
    }
    setSelectedProbes(newSelected);
  }, [form.scanType, probesLoaded, probeData.probes]);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [scanResults, modelResults] = await Promise.all([
        listScans(),
        listModelConfigs(),
      ]);
      setScans(
        scanResults.map((s) => ({
          id: s.id,
          scanType: s.scanType,
          status: s.status,
          progress: s.progress,
          vulnerabilitiesFound: s.vulnerabilitiesFound,
          riskScore: s.riskScore,
          createdAt: s.createdAt,
        })),
      );
      setModels(modelResults);

      if (modelResults.length > 0) {
        setForm((f) => ({ ...f, modelId: modelResults[0].id }));
        setInputMode("saved");
      } else {
        setInputMode("manual");
      }
    } catch (err) {
      console.error("Failed to load data:", err);
    } finally {
      setIsLoading(false);
    }
  };

  const loadProbes = async () => {
    try {
      const result = await listProbes();
      setProbeData(result);

      // Initialize selected probes based on default_enabled
      const initial: Record<string, boolean> = {};
      for (const probe of result.probes) {
        initial[probe.id] = probe.default_enabled;
      }
      setSelectedProbes(initial);
      setProbesLoaded(true);
    } catch (err) {
      console.error("Failed to load probes:", err);
      setProbesLoaded(true);
    }
  };

  const selectedProbeCount =
    Object.values(selectedProbes).filter(Boolean).length;
  const totalProbeCount = probeData.probes.length;

  const toggleCategory = (categoryId: string) => {
    setExpandedCategories((prev) => ({
      ...prev,
      [categoryId]: !prev[categoryId],
    }));
  };

  const toggleProbe = (probeId: string) => {
    setSelectedProbes((prev) => ({
      ...prev,
      [probeId]: !prev[probeId],
    }));
    // Switch to custom mode when user manually toggles probes
    if (form.scanType !== "custom") {
      setForm((f) => ({ ...f, scanType: "custom" }));
    }
  };

  const toggleAllInCategory = (category: GarakProbeCategory) => {
    const probesInCat = category.probe_ids;
    const allEnabled = probesInCat.every((id) => selectedProbes[id]);

    const newSelected = { ...selectedProbes };
    for (const id of probesInCat) {
      newSelected[id] = !allEnabled;
    }
    setSelectedProbes(newSelected);
    if (form.scanType !== "custom") {
      setForm((f) => ({ ...f, scanType: "custom" }));
    }
  };

  const selectAll = () => {
    const newSelected: Record<string, boolean> = {};
    for (const probe of probeData.probes) {
      newSelected[probe.id] = true;
    }
    setSelectedProbes(newSelected);
    setForm((f) => ({ ...f, scanType: "custom" }));
  };

  const selectNone = () => {
    const newSelected: Record<string, boolean> = {};
    for (const probe of probeData.probes) {
      newSelected[probe.id] = false;
    }
    setSelectedProbes(newSelected);
    setForm((f) => ({ ...f, scanType: "custom" }));
  };

  const handleStartScan = async () => {
    setIsStarting(true);
    setError(null);

    try {
      // Build the list of selected probe IDs
      const probeIds =
        form.scanType === "custom"
          ? Object.entries(selectedProbes)
              .filter(([, enabled]) => enabled)
              .map(([id]) => id)
          : [];

      if (form.scanType === "custom" && probeIds.length === 0) {
        setError("Please select at least one probe to run");
        setIsStarting(false);
        return;
      }

      // Build scan config
      let scanConfig: Parameters<typeof startScan>[0];

      if (inputMode === "saved" && form.modelId) {
        const selectedModel = models.find((m) => m.id === form.modelId);
        if (!selectedModel) {
          setError("Please select a model");
          setIsStarting(false);
          return;
        }

        // Auto-construct customEndpoint for saved models with "custom" provider
        let savedCustomEndpoint: CustomEndpointConfig | undefined;
        if (
          selectedModel.provider === "custom" ||
          selectedModel.provider === "custom/ollama"
        ) {
          const settings = selectedModel.settings as Record<
            string,
            unknown
          > | null;
          const endpointUrl = selectedModel.baseUrl || customEndpoint.url;
          if (!endpointUrl) {
            setError(
              "This custom model has no base URL configured. Please edit the model in Model Registry and add the endpoint URL.",
            );
            setIsStarting(false);
            return;
          }
          savedCustomEndpoint = {
            url: endpointUrl,
            method:
              (settings?.method as string) || customEndpoint.method || "POST",
            request_template:
              (settings?.request_template as string) ||
              customEndpoint.request_template ||
              '{"prompt": "{{prompt}}"}',
            response_path:
              (settings?.response_path as string) ||
              customEndpoint.response_path ||
              "response",
          };
        }

        scanConfig = {
          modelConfigId: form.modelId,
          scanType: form.scanType as
            | "quick"
            | "standard"
            | "comprehensive"
            | "custom",
          provider: selectedModel.provider,
          model: selectedModel.model,
          baseUrl: selectedModel.baseUrl || undefined,
          probes: probeIds,
          customEndpoint: savedCustomEndpoint,
          maxPromptsPerProbe:
            maxPromptsPerProbe !== 25 ? maxPromptsPerProbe : undefined,
        };
      } else {
        if (!form.model.trim() && form.provider !== "custom") {
          setError("Please enter a model identifier");
          setIsStarting(false);
          return;
        }

        // Validate custom endpoint
        if (form.provider === "custom" && !customEndpoint.url.trim()) {
          setError(
            "Please enter the API endpoint URL for your custom REST API",
          );
          setIsStarting(false);
          return;
        }

        scanConfig = {
          scanType: form.scanType as
            | "quick"
            | "standard"
            | "comprehensive"
            | "custom",
          provider: form.provider,
          model: form.model || "custom",
          apiKey: form.apiKey || undefined,
          baseUrl: form.baseUrl || undefined,
          probes: probeIds,
          customEndpoint:
            form.provider === "custom" ? customEndpoint : undefined,
          maxPromptsPerProbe:
            maxPromptsPerProbe !== 25 ? maxPromptsPerProbe : undefined,
        };
      }

      const result = await startScan(scanConfig);

      if ("error" in result) {
        setError(result.error);
      } else {
        setScans((prev) => [
          {
            id: result.scanId,
            scanType: form.scanType,
            status: result.status,
            progress: 0,
            vulnerabilitiesFound: 0,
            riskScore: null,
            createdAt: new Date().toISOString(),
          },
          ...prev,
        ]);
        setMonitoringScanId(result.scanId);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
    } finally {
      setIsStarting(false);
    }
  };

  const handleCancelScan = async (scanId: string) => {
    setIsCancelling(scanId);
    try {
      const result = await cancelScan(scanId);
      if ("error" in result) {
        setError(result.error);
      } else {
        // Update local state to reflect cancellation
        setScans((prev) =>
          prev.map((s) =>
            s.id === scanId
              ? { ...s, status: "cancelled", progress: s.progress }
              : s,
          ),
        );
        if (monitoringScanId === scanId) {
          setMonitoringScanId(null);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to cancel scan");
    } finally {
      setIsCancelling(null);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <IconCheck className="w-4 h-4 text-lime-500" />;
      case "failed":
        return <IconX className="w-4 h-4 text-red-500" />;
      case "cancelled":
        return <IconPlayerStop className="w-4 h-4 text-orange-400" />;
      case "running":
        return <IconLoader2 className="w-4 h-4 text-blue-500 animate-spin" />;
      case "pending":
        return (
          <IconLoader2 className="w-4 h-4 text-yellow-500 animate-pulse" />
        );
      default:
        return <IconRadar className="w-4 h-4 text-stone-500" />;
    }
  };

  const getRiskColor = (score: number | null) => {
    if (score === null) return "text-stone-500";
    if (score >= 0.7) return "text-red-500";
    if (score >= 0.4) return "text-orange-500";
    return "text-lime-500";
  };

  const getStatusBadge = (status: string) => {
    const colors: Record<string, string> = {
      completed: "bg-lime-500/20 text-lime-400",
      failed: "bg-red-500/20 text-red-400",
      cancelled: "bg-orange-500/20 text-orange-400",
      running: "bg-blue-500/20 text-blue-400",
      pending: "bg-yellow-500/20 text-yellow-400",
      queued: "bg-stone-500/20 text-stone-400",
    };
    return colors[status] || "bg-stone-500/20 text-stone-400";
  };

  const getProbeById = (id: string): GarakProbeInfo | undefined => {
    return probeData.probes.find((p) => p.id === id);
  };

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-10">
      <div>
        <h1 className="text-xl font-bold">Garak Scanner</h1>
        <p className="text-sm text-stone-500">
          Run vulnerability scans against your LLM models using Garak probes
        </p>
      </div>

      <div className="flex flex-col gap-6">
        {/* ─── Start New Scan ─── */}
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconRadar className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              New Scan
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200"></span>
        </div>

        <div className="bg-stone-50 border border-stone-200 rounded-2xl p-6">
          {/* Model Source Toggle */}
          <div className="flex gap-2 mb-6">
            <Button
              variant={inputMode === "saved" ? "default" : "outline"}
              size="sm"
              onClick={() => setInputMode("saved")}
              disabled={models.length === 0}
            >
              Use Saved Model
              {models.length > 0 && (
                <span className="ml-2 text-xs bg-white/20 px-1.5 rounded">
                  {models.length}
                </span>
              )}
            </Button>
            <Button
              variant={inputMode === "manual" ? "default" : "outline"}
              size="sm"
              onClick={() => setInputMode("manual")}
            >
              Enter Manually
            </Button>
            {models.length === 0 && (
              <Link href="/models" className="ml-auto">
                <Button variant="link" size="sm" className="text-stone-400">
                  + Add Model Config
                </Button>
              </Link>
            )}
          </div>

          {/* Model Configuration */}
          {inputMode === "saved" ? (
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Select Model Configuration</Label>
                <Select
                  value={form.modelId}
                  onValueChange={(v) => setForm({ ...form, modelId: v })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Choose a saved model" />
                  </SelectTrigger>
                  <SelectContent>
                    {models.map((m) => (
                      <SelectItem key={m.id} value={m.id}>
                        <div className="flex items-center gap-2">
                          <span>{m.name}</span>
                          <span className="text-xs text-stone-500">
                            ({m.provider}/{m.model})
                          </span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-stone-500">
                  Uses API key stored in model configuration
                </p>
                {(() => {
                  const sel = models.find((m) => m.id === form.modelId);
                  if (
                    sel &&
                    (sel.provider === "custom" ||
                      sel.provider === "custom/ollama")
                  ) {
                    const s = sel.settings as Record<string, unknown> | null;
                    return (
                      <div className="mt-2 p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg text-xs space-y-1">
                        <p className="font-semibold text-blue-400">
                          Custom Endpoint Details
                        </p>
                        <p className="text-stone-400">
                          <span className="text-stone-500">URL:</span>{" "}
                          <code className="text-blue-300">
                            {sel.baseUrl ||
                              "Not set — will use custom endpoint fields below"}
                          </code>
                        </p>
                        <p className="text-stone-400">
                          <span className="text-stone-500">Method:</span>{" "}
                          {(s?.method as string) || "POST"}
                          {" • "}
                          <span className="text-stone-500">
                            Response path:
                          </span>{" "}
                          {(s?.response_path as string) || "response"}
                        </p>
                        <p className="text-stone-400">
                          <span className="text-stone-500">Template:</span>{" "}
                          <code className="text-stone-700">
                            {(s?.request_template as string) ||
                              '{"prompt": "{{prompt}}"}'}
                          </code>
                        </p>
                        {!sel.baseUrl && (
                          <p className="text-orange-400 mt-1">
                            ⚠ No base URL configured. Please edit this model in{" "}
                            <Link
                              href="/models"
                              className="underline text-orange-300"
                            >
                              Model Registry
                            </Link>{" "}
                            and add an endpoint URL.
                          </p>
                        )}
                      </div>
                    );
                  }
                  return null;
                })()}
              </div>
              <div className="space-y-2">
                <Label>Scan Preset</Label>
                <Select
                  value={form.scanType}
                  onValueChange={(v) => setForm({ ...form, scanType: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SCAN_PRESETS.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        <span>{t.label}</span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-stone-500">
                  {SCAN_PRESETS.find((t) => t.value === form.scanType)?.desc}
                </p>
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Provider</Label>
                  <Select
                    value={form.provider}
                    onValueChange={(v) =>
                      setForm({ ...form, provider: v, model: "" })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {PROVIDERS.map((p) => (
                        <SelectItem key={p.value} value={p.value}>
                          {p.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                {form.provider !== "custom" && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Label>Model Identifier</Label>
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger>
                            <IconInfoCircle className="w-4 h-4 text-stone-500" />
                          </TooltipTrigger>
                          <TooltipContent>
                            <p>Enter the exact model name from the provider</p>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </div>
                    <Input
                      value={form.model}
                      onChange={(e) =>
                        setForm({ ...form, model: e.target.value })
                      }
                      placeholder={
                        selectedProvider?.placeholder || "Enter model name"
                      }
                    />
                  </div>
                )}
                {form.provider === "custom" && (
                  <div className="space-y-2">
                    <Label>Model Name (label only)</Label>
                    <Input
                      value={form.model}
                      onChange={(e) =>
                        setForm({ ...form, model: e.target.value })
                      }
                      placeholder="my-llm-service"
                    />
                  </div>
                )}
              </div>
              <div className="grid grid-cols-2 gap-4">
                {form.provider !== "custom" && (
                  <div className="space-y-2">
                    <Label>
                      API Key{" "}
                      {form.provider === "ollama" && (
                        <span className="text-stone-500">(optional)</span>
                      )}
                    </Label>
                    <Input
                      type="password"
                      value={form.apiKey}
                      onChange={(e) =>
                        setForm({ ...form, apiKey: e.target.value })
                      }
                      placeholder={
                        form.provider === "ollama"
                          ? "Not required for local"
                          : "Required"
                      }
                    />
                  </div>
                )}
                <div className="space-y-2">
                  <Label>Scan Preset</Label>
                  <Select
                    value={form.scanType}
                    onValueChange={(v) => setForm({ ...form, scanType: v })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {SCAN_PRESETS.map((t) => (
                        <SelectItem key={t.value} value={t.value}>
                          <span>{t.label}</span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-stone-500">
                    {SCAN_PRESETS.find((t) => t.value === form.scanType)?.desc}
                  </p>
                </div>
              </div>
              {(form.provider === "ollama" ||
                (form.provider !== "custom" &&
                  form.provider !== "openai" &&
                  form.provider !== "anthropic")) && (
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>
                      Base URL{" "}
                      <span className="text-stone-500">(optional)</span>
                    </Label>
                    <Input
                      value={form.baseUrl}
                      onChange={(e) =>
                        setForm({ ...form, baseUrl: e.target.value })
                      }
                      placeholder={
                        form.provider === "ollama"
                          ? "http://localhost:11434"
                          : "https://api.example.com"
                      }
                    />
                  </div>
                </div>
              )}

              {/* Custom Endpoint Configuration */}
              {form.provider === "custom" && (
                <div className="mt-2 p-4 bg-stone-100 border border-stone-300 rounded-xl space-y-4">
                  <div className="flex items-center gap-2 mb-1">
                    <IconSettings className="w-4 h-4 text-blue-400" />
                    <span className="text-sm font-semibold text-blue-400">
                      Custom REST API Configuration
                    </span>
                  </div>
                  <p className="text-xs text-stone-500 -mt-2">
                    Configure how Garak sends prompts to your API and reads
                    responses. Use{" "}
                    <code className="text-blue-300">{"{{prompt}}"}</code> as the
                    placeholder in the request template.
                  </p>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>
                        API Endpoint URL <span className="text-red-400">*</span>
                      </Label>
                      <Input
                        value={customEndpoint.url}
                        onChange={(e) =>
                          setCustomEndpoint({
                            ...customEndpoint,
                            url: e.target.value,
                          })
                        }
                        placeholder="http://localhost:8000/ai"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>HTTP Method</Label>
                      <Select
                        value={customEndpoint.method || "POST"}
                        onValueChange={(v) =>
                          setCustomEndpoint({ ...customEndpoint, method: v })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="POST">POST</SelectItem>
                          <SelectItem value="GET">GET</SelectItem>
                          <SelectItem value="PUT">PUT</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Request Body Template</Label>
                      <Input
                        value={customEndpoint.request_template || ""}
                        onChange={(e) =>
                          setCustomEndpoint({
                            ...customEndpoint,
                            request_template: e.target.value,
                          })
                        }
                        placeholder='{"prompt": "{{prompt}}"}'
                        className="font-mono text-xs"
                      />
                      <p className="text-[10px] text-stone-600">
                        JSON body with {"{{prompt}}"} placeholder. Example for
                        OpenAI-compatible:{" "}
                        <code>
                          {
                            '{"messages":[{"role":"user","content":"{{prompt}}"}],"model":"llama3"}'
                          }
                        </code>
                      </p>
                    </div>
                    <div className="space-y-2">
                      <Label>Response Path</Label>
                      <Input
                        value={customEndpoint.response_path || ""}
                        onChange={(e) =>
                          setCustomEndpoint({
                            ...customEndpoint,
                            response_path: e.target.value,
                          })
                        }
                        placeholder="response"
                        className="font-mono text-xs"
                      />
                      <p className="text-[10px] text-stone-600">
                        Dot-path to extract response text. Examples:{" "}
                        <code>response</code>,{" "}
                        <code>choices.0.message.content</code>,{" "}
                        <code>data.text</code>
                      </p>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label>
                      API Key <span className="text-stone-500">(optional)</span>
                    </Label>
                    <Input
                      type="password"
                      value={form.apiKey}
                      onChange={(e) =>
                        setForm({ ...form, apiKey: e.target.value })
                      }
                      placeholder="Bearer token (sent as Authorization header)"
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ─── Probe Picker ─── */}
          <div className="mt-6 border-t border-stone-200 pt-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <IconFilter className="w-4 h-4 text-stone-400" />
                <span className="text-sm font-semibold">
                  Vulnerability Probes
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-400 font-mono">
                  {selectedProbeCount}/{totalProbeCount} selected
                </span>
              </div>
              <div className="flex gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 text-xs text-stone-500"
                  onClick={selectAll}
                >
                  Select All
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 text-xs text-stone-500"
                  onClick={selectNone}
                >
                  Clear All
                </Button>
              </div>
            </div>

            {probeData.categories.length === 0 && probesLoaded && (
              <div className="text-center text-stone-500 py-4 text-sm">
                <p>
                  Could not load probe list from the scanner service. Using
                  preset-based selection.
                </p>
              </div>
            )}

            <div className="space-y-2">
              {probeData.categories.map((category) => {
                const catProbes = category.probe_ids
                  .map((id) => getProbeById(id))
                  .filter(Boolean) as GarakProbeInfo[];
                const enabledCount = catProbes.filter(
                  (p) => selectedProbes[p.id],
                ).length;
                const isExpanded = expandedCategories[category.id] ?? false;

                return (
                  <div
                    key={category.id}
                    className="bg-stone-100 border border-stone-300 rounded-xl overflow-hidden"
                  >
                    {/* Category Header */}
                    <div className="w-full flex items-center gap-3 px-4 py-3 hover:bg-stone-200/30 transition-colors">
                      <button
                        type="button"
                        onClick={() => toggleCategory(category.id)}
                        className="flex-1 flex items-center gap-3 text-left"
                      >
                        <span className="text-stone-400">
                          {CATEGORY_ICONS[category.id] || (
                            <IconShieldCheck className="w-4 h-4" />
                          )}
                        </span>
                        <div className="flex-1 min-w-0">
                          <span className="text-sm font-medium">
                            {category.name}
                          </span>
                          <span className="text-xs text-stone-500 ml-2">
                            {category.description}
                          </span>
                        </div>
                        <span
                          className={`text-xs px-2 py-0.5 rounded font-mono ${
                            enabledCount > 0
                              ? "bg-blue-500/20 text-blue-400"
                              : "bg-stone-200 text-stone-500"
                          }`}
                        >
                          {enabledCount}/{catProbes.length}
                        </span>
                        {isExpanded ? (
                          <IconChevronDown className="w-4 h-4 text-stone-500" />
                        ) : (
                          <IconChevronRight className="w-4 h-4 text-stone-500" />
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() => toggleAllInCategory(category)}
                        className={`text-xs px-2 py-0.5 rounded border shrink-0 ${
                          enabledCount === catProbes.length
                            ? "border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
                            : "border-stone-300 text-stone-500 hover:bg-stone-200"
                        }`}
                      >
                        {enabledCount === catProbes.length
                          ? "Disable All"
                          : "Enable All"}
                      </button>
                    </div>

                    {/* Probe List (expanded) */}
                    {isExpanded && (
                      <div className="border-t border-stone-300">
                        {catProbes.map((probe) => (
                          <div
                            key={probe.id}
                            className={`flex items-start gap-3 px-4 py-3 border-b border-stone-200 last:border-0 hover:bg-stone-200/20 transition-colors ${
                              !probe.available ? "opacity-50" : ""
                            }`}
                          >
                            {/* Toggle */}
                            <button
                              onClick={() => toggleProbe(probe.id)}
                              disabled={!probe.available}
                              className={`mt-0.5 w-5 h-5 rounded border flex items-center justify-center shrink-0 transition-colors ${
                                selectedProbes[probe.id]
                                  ? "bg-blue-500 border-blue-500"
                                  : "border-stone-300 hover:border-stone-400"
                              } ${!probe.available ? "cursor-not-allowed" : "cursor-pointer"}`}
                            >
                              {selectedProbes[probe.id] && (
                                <IconCheck className="w-3 h-3 text-white" />
                              )}
                            </button>

                            {/* Probe Info */}
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-sm font-medium">
                                  {probe.name}
                                </span>
                                <span
                                  className={`text-[10px] px-1.5 py-0.5 rounded border ${getSeverityColor(probe.severity_range)}`}
                                >
                                  {probe.severity_range}
                                </span>
                                {!probe.available && (
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-stone-800 text-stone-500 border border-stone-700">
                                    not installed
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-stone-500 mt-1 leading-relaxed">
                                {probe.description}
                              </p>
                              <div className="flex flex-wrap gap-1 mt-1.5">
                                {probe.tags.map((tag) => (
                                  <span
                                    key={tag}
                                    className="text-[10px] px-1.5 py-0.5 rounded bg-stone-100 text-stone-600 font-mono"
                                  >
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* ─── Advanced Settings ─── */}
          <div className="mt-4">
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center gap-2 text-xs text-stone-500 hover:text-stone-400"
            >
              <IconAdjustments className="w-3.5 h-3.5" />
              Advanced Settings
              {showAdvanced ? (
                <IconChevronDown className="w-3 h-3" />
              ) : (
                <IconChevronRight className="w-3 h-3" />
              )}
            </button>

            {showAdvanced && (
              <div className="mt-3 p-4 bg-stone-100 border border-stone-300 rounded-xl">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>Max Prompts per Probe</Label>
                    <Input
                      type="number"
                      min={1}
                      max={200}
                      value={maxPromptsPerProbe}
                      onChange={(e) =>
                        setMaxPromptsPerProbe(
                          Math.max(
                            1,
                            Math.min(200, parseInt(e.target.value) || 25),
                          ),
                        )
                      }
                    />
                    <p className="text-[10px] text-stone-600">
                      Limits how many attack prompts are sent per probe class.
                      Lower = faster but less thorough. Default: 25.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Error Display */}
          {error && (
            <div className="mt-4 p-3 bg-red-900/20 border border-red-700 rounded-lg text-red-400 text-sm flex items-center gap-2">
              <IconAlertTriangle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          {/* Start Button */}
          <div className="mt-6 flex items-center gap-4">
            <Button
              onClick={handleStartScan}
              disabled={
                isStarting ||
                (inputMode === "saved" && !form.modelId) ||
                (inputMode === "manual" &&
                  !form.model &&
                  form.provider !== "custom") ||
                (inputMode === "manual" &&
                  form.provider === "custom" &&
                  !customEndpoint.url)
              }
            >
              {isStarting ? (
                <>
                  <IconLoader2 className="w-4 h-4 mr-2 animate-spin" />
                  Starting Scan...
                </>
              ) : (
                <>
                  <IconPlayerPlay className="w-4 h-4 mr-2" />
                  Start Vulnerability Scan
                </>
              )}
            </Button>
            {selectedProbeCount > 0 && (
              <span className="text-xs text-stone-500">
                {selectedProbeCount} probe
                {selectedProbeCount !== 1 ? "s" : ""} selected
              </span>
            )}
          </div>
        </div>

        {/* ─── Live Scan Monitor ─── */}
        {monitoringScanId && (
          <>
            <div className="flex gap-4 items-center">
              <div className="flex gap-2 items-center">
                <IconRadar className="w-4 h-4 text-blue-400 animate-pulse" />
                <span className="text-blue-400 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
                  Live Scan Monitor
                </span>
              </div>
              <span className="flex-1 h-px bg-blue-500/20"></span>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10"
                onClick={() => handleCancelScan(monitoringScanId)}
                disabled={isCancelling === monitoringScanId}
              >
                {isCancelling === monitoringScanId ? (
                  <>
                    <IconLoader2 className="w-3 h-3 mr-1 animate-spin" />
                    Cancelling...
                  </>
                ) : (
                  <>
                    <IconPlayerStop className="w-3 h-3 mr-1" />
                    Stop Scan
                  </>
                )}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 text-xs text-stone-500"
                onClick={() => setMonitoringScanId(null)}
              >
                <IconEyeOff className="w-3 h-3 mr-1" />
                Close Monitor
              </Button>
            </div>
            <LiveScanMonitor
              scanId={monitoringScanId}
              onProgress={handleLiveProgress}
              onComplete={() => {
                loadData();
              }}
            />
          </>
        )}

        {/* ─── Scan History ─── */}
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconRadar className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              Scan History
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200"></span>
          <Button variant="ghost" size="sm" onClick={loadData} className="h-6">
            <IconRefresh className="w-3 h-3 mr-1" />
            Refresh
          </Button>
        </div>

        <div className="bg-stone-50 border border-stone-200 rounded-2xl overflow-hidden">
          {isLoading ? (
            <div className="p-8 text-center text-stone-500">
              <IconLoader2 className="w-8 h-8 mx-auto mb-4 animate-spin" />
              <p>Loading scan history...</p>
            </div>
          ) : scans.length === 0 ? (
            <div className="p-8 text-center text-stone-500">
              <IconRadar className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No scans yet</p>
              <p className="text-xs mt-1">
                Start a scan to test your LLM for vulnerabilities
              </p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="border-b border-stone-200">
                <tr className="text-left text-xs font-mono uppercase text-stone-500">
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Progress</th>
                  <th className="px-4 py-3">Vulnerabilities</th>
                  <th className="px-4 py-3">Risk Score</th>
                  <th className="px-4 py-3">Started</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-stone-200 last:border-0 hover:bg-stone-100"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(scan.status)}
                        <span
                          className={`text-xs px-2 py-0.5 rounded capitalize ${getStatusBadge(scan.status)}`}
                        >
                          {scan.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 capitalize">{scan.scanType}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-24 h-2 bg-stone-100 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-blue-500 transition-all duration-300"
                            style={{ width: `${scan.progress}%` }}
                          />
                        </div>
                        <span className="text-xs text-stone-500">
                          {scan.progress}%
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {scan.vulnerabilitiesFound > 0 ? (
                        <span className="text-orange-400 font-semibold">
                          {scan.vulnerabilitiesFound}
                        </span>
                      ) : (
                        <span className="text-stone-500">0</span>
                      )}
                    </td>
                    <td
                      className={`px-4 py-3 font-semibold ${getRiskColor(scan.riskScore)}`}
                    >
                      {scan.riskScore !== null
                        ? `${(scan.riskScore * 100).toFixed(0)}%`
                        : "-"}
                    </td>
                    <td className="px-4 py-3 text-stone-500 text-sm">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        {(scan.status === "running" ||
                          scan.status === "pending" ||
                          scan.status === "queued") && (
                          <>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-blue-400 h-7 text-xs"
                              onClick={() =>
                                setMonitoringScanId(
                                  monitoringScanId === scan.id ? null : scan.id,
                                )
                              }
                            >
                              {monitoringScanId === scan.id ? (
                                <>
                                  <IconEyeOff className="w-3 h-3 mr-1" />
                                  Hide
                                </>
                              ) : (
                                <>
                                  <IconEye className="w-3 h-3 mr-1" />
                                  Monitor
                                </>
                              )}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-red-400 hover:text-red-300 hover:bg-red-500/10 h-7 text-xs"
                              onClick={() => handleCancelScan(scan.id)}
                              disabled={isCancelling === scan.id}
                            >
                              {isCancelling === scan.id ? (
                                <IconLoader2 className="w-3 h-3 animate-spin" />
                              ) : (
                                <>
                                  <IconPlayerStop className="w-3 h-3 mr-1" />
                                  Stop
                                </>
                              )}
                            </Button>
                          </>
                        )}
                        {scan.status === "completed" && (
                          <Link href={`/reports?scan=${scan.id}`}>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 text-xs"
                            >
                              View Report
                            </Button>
                          </Link>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* ─── Info Section ─── */}
        <div className="bg-stone-50 border border-stone-200 rounded-2xl p-6">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <IconInfoCircle className="w-4 h-4" />
            About Garak Vulnerability Scanner
          </h3>
          <p className="text-sm text-stone-400 mb-4">
            Powered by{" "}
            <a
              href="https://github.com/NVIDIA/garak"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 underline underline-offset-2"
            >
              NVIDIA Garak
            </a>
            , an open-source framework for automated red-teaming and
            vulnerability testing of large language models.
          </p>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div className="p-3 bg-stone-100 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <IconAlertOctagon className="w-4 h-4 text-red-400" />
                <p className="font-medium text-stone-800">Prompt Injection</p>
              </div>
              <p className="text-xs text-stone-500">
                Tests for attempts to override system instructions
              </p>
            </div>
            <div className="p-3 bg-stone-100 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <IconLock className="w-4 h-4 text-orange-400" />
                <p className="font-medium text-stone-800">Jailbreaking</p>
              </div>
              <p className="text-xs text-stone-500">
                Detects attempts to bypass safety guardrails
              </p>
            </div>
            <div className="p-3 bg-stone-100 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <IconDatabase className="w-4 h-4 text-yellow-400" />
                <p className="font-medium text-stone-800">Data Leakage</p>
              </div>
              <p className="text-xs text-stone-500">
                Checks for training data extraction vulnerabilities
              </p>
            </div>
            <div className="p-3 bg-stone-100 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <IconAlertTriangle className="w-4 h-4 text-orange-300" />
                <p className="font-medium text-stone-800">Toxicity</p>
              </div>
              <p className="text-xs text-stone-500">
                Tests for harmful, toxic, and policy-violating output
              </p>
            </div>
            <div className="p-3 bg-stone-100 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <IconGhost className="w-4 h-4 text-purple-400" />
                <p className="font-medium text-stone-800">Hallucination</p>
              </div>
              <p className="text-xs text-stone-500">
                Checks for fabricated facts and false claims
              </p>
            </div>
            <div className="p-3 bg-stone-100 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <IconBug className="w-4 h-4 text-red-300" />
                <p className="font-medium text-stone-800">Malware</p>
              </div>
              <p className="text-xs text-stone-500">
                Tests for malicious code generation
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
