"use client";

import { useState, useEffect, useCallback } from "react";
import {
  IconKey,
  IconPlus,
  IconTrash,
  IconCopy,
  IconCheck,
  IconSettings,
  IconShieldBolt,
  IconChevronDown,
  IconChevronRight,
  IconArrowRight,
  IconArrowLeft,
  IconLoader2,
  IconX,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  createApiKey,
  listApiKeys,
  revokeApiKey,
  updateGuardConfig,
} from "@/lib/actions/api-keys";
import type { GuardConfig, GuardScannerEntry } from "@/lib/api";
import {
  ALL_INPUT_SCANNERS,
  ALL_OUTPUT_SCANNERS,
  SCANNER_META,
  type InputScannerName,
  type OutputScannerName,
} from "@/lib/scanner-meta";

interface ApiKeyDisplay {
  id: string;
  name: string;
  keyPrefix: string;
  createdAt: Date;
  lastUsedAt: Date | null;
  guardConfig: GuardConfig | null;
}

type ScanMode = "prompt_only" | "output_only" | "both";
type GuardPresetId =
  | "health"
  | "financial"
  | "education"
  | "government"
  | "custom";

interface ScannerEntry {
  enabled: boolean;
  threshold: number;
  settingsJson: string;
}

interface LocalGuardConfigState {
  scanMode: ScanMode;
  inputScanners: Record<string, ScannerEntry>;
  outputScanners: Record<string, ScannerEntry>;
  sanitize: boolean;
  failFast: boolean;
}

interface GuardPresetDefinition {
  id: Exclude<GuardPresetId, "custom">;
  label: string;
  description: string;
  scanMode: ScanMode;
  sanitize: boolean;
  failFast: boolean;
  inputScanners: InputScannerName[];
  outputScanners: OutputScannerName[];
  inputThresholds?: Partial<Record<InputScannerName, number>>;
  outputThresholds?: Partial<Record<OutputScannerName, number>>;
  inputSettings?: Partial<Record<InputScannerName, string>>;
  outputSettings?: Partial<Record<OutputScannerName, string>>;
}

const CATEGORY_COLORS: Record<string, string> = {
  Security: "bg-red-500/15 text-red-400 border-red-500/30",
  Safety: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  Privacy: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  Content: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  Quality: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  Business: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  Custom: "bg-pink-500/15 text-pink-400 border-pink-500/30",
};

function buildCodeSnippets(baseUrl: string) {
  const endpoint = `${baseUrl}/v1/guard/scan`;
  return {
    curl: `curl --location '${endpoint}' \\
--header 'X-API-Key: YOUR_API_KEY' \\
--header 'Content-Type: application/json' \\
--data '{
  "prompt": "Your prompt to scan for threats",
  "options": {
    "check_injection": true,
    "check_toxicity": true,
    "check_pii": true,
    "sanitize": false
  }
}'`,
    nodejs: `const response = await fetch('${endpoint}', {
  method: 'POST',
  headers: {
    'X-API-Key': 'YOUR_API_KEY',
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    prompt: 'Your prompt to scan for threats',
    options: {
      check_injection: true,
      check_toxicity: true,
      check_pii: true,
      sanitize: false,
    },
  }),
});

const result = await response.json();
console.log(result.safe ? 'Safe!' : 'Threats detected:', result.threats);`,
    python: `import requests

response = requests.post(
    '${endpoint}',
    headers={
        'X-API-Key': 'YOUR_API_KEY',
        'Content-Type': 'application/json',
    },
    json={
        'prompt': 'Your prompt to scan for threats',
        'options': {
            'check_injection': True,
            'check_toxicity': True,
            'check_pii': True,
            'sanitize': False,
        },
    },
)

result = response.json()
print('Safe!' if result['safe'] else f"Threats: {result['threats']}")`,
    rust: `use reqwest::Client;
use serde_json::json;

let client = Client::new();
let response = client
    .post("${endpoint}")
    .header("X-API-Key", "YOUR_API_KEY")
    .header("Content-Type", "application/json")
    .json(&json!({
        "prompt": "Your prompt to scan for threats",
        "options": {
            "check_injection": true,
            "check_toxicity": true,
            "check_pii": true,
            "sanitize": false
        }
    }))
    .send()
    .await?;

let result: serde_json::Value = response.json().await?;
println!("{:?}", result);`,
    go: `package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

func main() {
    payload := map[string]interface{}{
        "prompt": "Your prompt to scan for threats",
        "options": map[string]bool{
            "check_injection": true,
            "check_toxicity":  true,
            "check_pii":       true,
            "sanitize":        false,
        },
    }

    body, _ := json.Marshal(payload)
    req, _ := http.NewRequest("POST", "${endpoint}", bytes.NewBuffer(body))
    req.Header.Set("X-API-Key", "YOUR_API_KEY")
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, _ := client.Do(req)
    defer resp.Body.Close()
}`,
    php: `<?php
$ch = curl_init();

curl_setopt_array($ch, [
    CURLOPT_URL => '${endpoint}',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => [
        'X-API-Key: YOUR_API_KEY',
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => json_encode([
        'prompt' => 'Your prompt to scan for threats',
        'options' => [
            'check_injection' => true,
            'check_toxicity' => true,
            'check_pii' => true,
            'sanitize' => false,
        ],
    ]),
]);

$response = curl_exec($ch);
$result = json_decode($response, true);
curl_close($ch);

echo $result['safe'] ? 'Safe!' : 'Threats detected';`,
    csharp: `using System.Net.Http;
using System.Text;
using System.Text.Json;

var client = new HttpClient();
var request = new HttpRequestMessage(HttpMethod.Post, "${endpoint}");
request.Headers.Add("X-API-Key", "YOUR_API_KEY");

var payload = new {
    prompt = "Your prompt to scan for threats",
    options = new {
        check_injection = true,
        check_toxicity = true,
        check_pii = true,
        sanitize = false
    }
};

request.Content = new StringContent(
    JsonSerializer.Serialize(payload),
    Encoding.UTF8,
    "application/json"
);

var response = await client.SendAsync(request);
var result = await response.Content.ReadAsStringAsync();
Console.WriteLine(result);`,
    java: `import java.net.http.*;
import java.net.URI;

HttpClient client = HttpClient.newHttpClient();

String json = """
    {
      "prompt": "Your prompt to scan for threats",
      "options": {
        "check_injection": true,
        "check_toxicity": true,
        "check_pii": true,
        "sanitize": false
      }
    }
    """;

HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("${endpoint}"))
    .header("X-API-Key", "YOUR_API_KEY")
    .header("Content-Type", "application/json")
    .POST(HttpRequest.BodyPublishers.ofString(json))
    .build();

HttpResponse<String> response = client.send(request,
    HttpResponse.BodyHandlers.ofString());
System.out.println(response.body());`,
  };
}

const LANGUAGES = [
  {
    id: "curl",
    name: "cURL",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/bash.svg",
  },
  {
    id: "nodejs",
    name: "NodeJS",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/nodejs.svg",
  },
  {
    id: "python",
    name: "Python",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/python.svg",
  },
  {
    id: "rust",
    name: "Rust",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/rust.svg",
    darkInvert: true,
  },
  {
    id: "go",
    name: "Go",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/go.svg",
  },
  {
    id: "php",
    name: "PHP",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/php.svg",
  },
  {
    id: "csharp",
    name: "C#",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/csharp.svg",
  },
  {
    id: "java",
    name: "Java",
    icon: "https://d26c7l40gvbbg2.cloudfront.net/tool_icons/java.svg",
  },
];

const INPUT_SCANNER_THRESHOLDS: Partial<Record<InputScannerName, number>> = {
  prompt_injection: 0.5,
  toxicity: 0.7,
  anonymize: 0.6,
  gibberish: 0.7,
  sentiment: 0.5,
};

const OUTPUT_SCANNER_THRESHOLDS: Partial<Record<OutputScannerName, number>> = {
  toxicity: 0.7,
  bias: 0.7,
  gibberish: 0.7,
  sentiment: 0.5,
};

function buildInputScanners(
  enabledScanners: InputScannerName[],
  thresholds: Partial<Record<InputScannerName, number>> = {},
  settings: Partial<Record<InputScannerName, string>> = {},
): Record<string, ScannerEntry> {
  const enabled = new Set(enabledScanners);
  const entries: Record<string, ScannerEntry> = {};
  for (const name of ALL_INPUT_SCANNERS) {
    entries[name] = {
      enabled: enabled.has(name),
      threshold: thresholds[name] ?? INPUT_SCANNER_THRESHOLDS[name] ?? 0.5,
      settingsJson: settings[name] ?? "",
    };
  }
  return entries;
}

function buildOutputScanners(
  enabledScanners: OutputScannerName[],
  thresholds: Partial<Record<OutputScannerName, number>> = {},
  settings: Partial<Record<OutputScannerName, string>> = {},
): Record<string, ScannerEntry> {
  const enabled = new Set(enabledScanners);
  const entries: Record<string, ScannerEntry> = {};
  for (const name of ALL_OUTPUT_SCANNERS) {
    entries[name] = {
      enabled: enabled.has(name),
      threshold: thresholds[name] ?? OUTPUT_SCANNER_THRESHOLDS[name] ?? 0.5,
      settingsJson: settings[name] ?? "",
    };
  }
  return entries;
}

const GUARD_PRESETS: Record<Exclude<GuardPresetId, "custom">, GuardPresetDefinition> = {
  health: {
    id: "health",
    label: "Health",
    description: "PII, injection, and harmful output controls for patient safety.",
    scanMode: "both",
    sanitize: true,
    failFast: true,
    inputScanners: [
      "anonymize",
      "prompt_injection",
      "secrets",
      "toxicity",
      "invisible_text",
      "token_limit",
      "gibberish",
    ],
    outputScanners: [
      "sensitive",
      "toxicity",
      "bias",
      "malicious_urls",
      "factual_consistency",
      "relevance",
    ],
    inputThresholds: {
      anonymize: 0.4,
      prompt_injection: 0.45,
      secrets: 0.4,
      toxicity: 0.55,
      token_limit: 0.5,
    },
    outputThresholds: {
      sensitive: 0.45,
      toxicity: 0.55,
      bias: 0.6,
      malicious_urls: 0.45,
      factual_consistency: 0.6,
      relevance: 0.55,
    },
  },
  financial: {
    id: "financial",
    label: "Financial",
    description: "Stricter fraud and data-leak posture for regulated transactions.",
    scanMode: "both",
    sanitize: true,
    failFast: true,
    inputScanners: [
      "prompt_injection",
      "secrets",
      "anonymize",
      "invisible_text",
      "token_limit",
      "toxicity",
      "language",
    ],
    outputScanners: [
      "sensitive",
      "malicious_urls",
      "json",
      "factual_consistency",
      "relevance",
      "toxicity",
    ],
    inputThresholds: {
      prompt_injection: 0.4,
      secrets: 0.35,
      anonymize: 0.4,
      token_limit: 0.5,
      language: 0.55,
    },
    outputThresholds: {
      sensitive: 0.4,
      malicious_urls: 0.4,
      json: 0.6,
      factual_consistency: 0.65,
      relevance: 0.6,
    },
  },
  education: {
    id: "education",
    label: "Education",
    description: "Balanced classroom-safe defaults with quality-focused output checks.",
    scanMode: "both",
    sanitize: false,
    failFast: false,
    inputScanners: [
      "prompt_injection",
      "toxicity",
      "gibberish",
      "language",
      "invisible_text",
    ],
    outputScanners: [
      "toxicity",
      "bias",
      "relevance",
      "factual_consistency",
      "language_same",
      "reading_time",
    ],
    inputThresholds: {
      prompt_injection: 0.5,
      toxicity: 0.65,
      language: 0.6,
    },
    outputThresholds: {
      toxicity: 0.65,
      bias: 0.7,
      relevance: 0.6,
      factual_consistency: 0.65,
      reading_time: 0.6,
    },
  },
  government: {
    id: "government",
    label: "Government",
    description: "High-assurance baseline for public-sector security and compliance.",
    scanMode: "both",
    sanitize: true,
    failFast: true,
    inputScanners: [
      "prompt_injection",
      "secrets",
      "anonymize",
      "invisible_text",
      "token_limit",
      "toxicity",
      "language",
      "gibberish",
    ],
    outputScanners: [
      "sensitive",
      "malicious_urls",
      "json",
      "factual_consistency",
      "relevance",
      "toxicity",
      "url_reachability",
      "bias",
    ],
    inputThresholds: {
      prompt_injection: 0.4,
      secrets: 0.35,
      anonymize: 0.4,
      toxicity: 0.55,
      token_limit: 0.45,
    },
    outputThresholds: {
      sensitive: 0.4,
      malicious_urls: 0.4,
      json: 0.65,
      factual_consistency: 0.7,
      relevance: 0.65,
      toxicity: 0.6,
      url_reachability: 0.6,
      bias: 0.65,
    },
  },
};

const PRESET_BUTTON_ORDER: GuardPresetId[] = [
  "health",
  "financial",
  "education",
  "government",
  "custom",
];

function buildPresetLocalState(
  presetId: Exclude<GuardPresetId, "custom">,
): LocalGuardConfigState {
  const preset = GUARD_PRESETS[presetId];
  return {
    scanMode: preset.scanMode,
    inputScanners: buildInputScanners(
      preset.inputScanners,
      preset.inputThresholds,
      preset.inputSettings,
    ),
    outputScanners: buildOutputScanners(
      preset.outputScanners,
      preset.outputThresholds,
      preset.outputSettings,
    ),
    sanitize: preset.sanitize,
    failFast: preset.failFast,
  };
}

function guardConfigToLocal(gc: GuardConfig): LocalGuardConfigState {
  const inputScanners: Record<string, ScannerEntry> = {};
  for (const name of ALL_INPUT_SCANNERS) {
    const remote = gc.input_scanners[name];
    inputScanners[name] = remote
      ? {
          enabled: remote.enabled,
          threshold: remote.threshold,
          settingsJson: remote.settings_json,
        }
      : { enabled: false, threshold: 0.5, settingsJson: "" };
  }

  const outputScanners: Record<string, ScannerEntry> = {};
  for (const name of ALL_OUTPUT_SCANNERS) {
    const remote = gc.output_scanners[name];
    outputScanners[name] = remote
      ? {
          enabled: remote.enabled,
          threshold: remote.threshold,
          settingsJson: remote.settings_json,
        }
      : { enabled: false, threshold: 0.5, settingsJson: "" };
  }

  return {
    scanMode: gc.scan_mode,
    inputScanners,
    outputScanners,
    sanitize: gc.sanitize,
    failFast: gc.fail_fast,
  };
}

function clampThreshold(v: number): number {
  return Math.min(1, Math.max(0, v));
}

function localToGuardConfig(
  scanMode: ScanMode,
  inputScanners: Record<string, ScannerEntry>,
  outputScanners: Record<string, ScannerEntry>,
  sanitize: boolean,
  failFast: boolean,
): GuardConfig {
  const input_scanners: Record<string, GuardScannerEntry> = {};
  for (const [name, entry] of Object.entries(inputScanners)) {
    input_scanners[name] = {
      enabled: entry.enabled,
      threshold: clampThreshold(entry.threshold),
      settings_json: entry.settingsJson,
    };
  }

  const output_scanners: Record<string, GuardScannerEntry> = {};
  for (const [name, entry] of Object.entries(outputScanners)) {
    output_scanners[name] = {
      enabled: entry.enabled,
      threshold: clampThreshold(entry.threshold),
      settings_json: entry.settingsJson,
    };
  }

  return {
    scan_mode: scanMode,
    input_scanners,
    output_scanners,
    sanitize,
    fail_fast: failFast,
  };
}

function countEnabled(scanners: Record<string, ScannerEntry>): number {
  return Object.values(scanners).filter((s) => s.enabled).length;
}

function ScannerToggleRow({
  name,
  entry,
  onToggle,
  onThresholdChange,
  onSettingsChange,
}: {
  name: string;
  entry: ScannerEntry;
  onToggle: () => void;
  onThresholdChange: (v: number) => void;
  onSettingsChange: (v: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const meta = SCANNER_META[name] || {
    label: name,
    description: "No description available",
    category: "Custom",
  };
  const catColor =
    CATEGORY_COLORS[meta.category] ||
    "bg-stone-500/15 text-stone-400 border-stone-500/30";

  return (
    <div
      className={`border rounded-lg transition-all duration-150 ${
        entry.enabled
          ? "border-stone-300 bg-stone-50"
          : "border-stone-200 bg-stone-50 opacity-50"
      }`}
    >
      <div className="flex items-center gap-2.5 px-3 py-2">
        <button
          onClick={onToggle}
          className={`relative w-8 h-[18px] rounded-full transition-colors flex-shrink-0 ${
            entry.enabled ? "bg-lime-600" : "bg-stone-200"
          }`}
          aria-label={`Toggle ${meta.label}`}
        >
          <span
            className={`absolute top-[2px] left-[2px] w-[14px] h-[14px] rounded-full bg-white transition-transform ${
              entry.enabled ? "translate-x-[14px]" : "translate-x-0"
            }`}
          />
        </button>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-semibold text-stone-800 truncate">
              {meta.label}
            </span>
            <span
              className={`text-[9px] font-mono uppercase px-1 py-0.5 rounded border leading-none ${catColor}`}
            >
              {meta.category}
            </span>
          </div>
        </div>

        <button
          onClick={() => setExpanded(!expanded)}
          className="text-stone-600 hover:text-stone-400 transition-colors p-0.5"
          aria-label="Settings"
        >
          {expanded ? (
            <IconChevronDown className="w-3.5 h-3.5" />
          ) : (
            <IconChevronRight className="w-3.5 h-3.5" />
          )}
        </button>
      </div>

      {expanded && (
        <div className="border-t border-stone-200 px-3 py-2 space-y-2">
          <div className="flex items-center gap-2">
            <label className="text-[10px] text-stone-500 font-mono uppercase w-16">
              Threshold
            </label>
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={entry.threshold}
              onChange={(e) => onThresholdChange(parseFloat(e.target.value))}
              className="flex-1 accent-lime-500 h-1"
            />
            <span className="text-[10px] font-mono text-stone-400 w-8 text-right">
              {entry.threshold.toFixed(2)}
            </span>
          </div>

          {(meta.requiresSettings || meta.settingsHint) && (
            <div className="space-y-1">
              <label className="text-[10px] text-stone-500 font-mono uppercase">
                Settings (JSON)
              </label>
              <textarea
                className="w-full bg-stone-100 border border-stone-300 rounded px-2 py-1.5 text-[11px] font-mono text-stone-700 min-h-[40px] focus:outline-none focus:border-stone-300 resize-y"
                placeholder={meta.settingsHint || "{}"}
                value={entry.settingsJson}
                onChange={(e) => onSettingsChange(e.target.value)}
              />
              {meta.requiresSettings && !entry.settingsJson && (
                <p className="text-[9px] text-yellow-500">
                  ⚠ This scanner requires settings
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}



function GuardConfigPanel({
  keyId,
  keyName,
  initialConfig,
  onClose,
  onSaved,
}: {
  keyId: string;
  keyName: string;
  initialConfig: GuardConfig | null;
  onClose: () => void;
  onSaved: (config: GuardConfig | null) => void;
}) {
  const hasExisting = initialConfig !== null;
  const defaults = hasExisting
    ? guardConfigToLocal(initialConfig)
    : buildPresetLocalState("health");

  const [scanMode, setScanMode] = useState<ScanMode>(defaults.scanMode);
  const [inputScanners, setInputScanners] = useState(defaults.inputScanners);
  const [outputScanners, setOutputScanners] = useState(defaults.outputScanners);
  const [sanitize, setSanitize] = useState(defaults.sanitize);
  const [failFast, setFailFast] = useState(defaults.failFast);
  const [selectedPreset, setSelectedPreset] = useState<GuardPresetId>(
    hasExisting ? "custom" : "health",
  );
  const [isSaving, setIsSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [inputFilter, setInputFilter] = useState("");
  const [outputFilter, setOutputFilter] = useState("");

  const applyPreset = useCallback((presetId: GuardPresetId) => {
    setSelectedPreset(presetId);
    if (presetId === "custom") {
      return;
    }

    const next = buildPresetLocalState(presetId);
    setScanMode(next.scanMode);
    setInputScanners(next.inputScanners);
    setOutputScanners(next.outputScanners);
    setSanitize(next.sanitize);
    setFailFast(next.failFast);
  }, []);

  const updateInput = useCallback(
    (name: string, patch: Partial<ScannerEntry>) => {
      setSelectedPreset("custom");
      setInputScanners((prev) => ({
        ...prev,
        [name]: { ...prev[name], ...patch },
      }));
    },
    [],
  );

  const updateOutput = useCallback(
    (name: string, patch: Partial<ScannerEntry>) => {
      setSelectedPreset("custom");
      setOutputScanners((prev) => ({
        ...prev,
        [name]: { ...prev[name], ...patch },
      }));
    },
    [],
  );

  const toggleAllInput = useCallback((enabled: boolean) => {
    setSelectedPreset("custom");
    setInputScanners((prev) => {
      const next = { ...prev };
      for (const key of Object.keys(next)) {
        next[key] = { ...next[key], enabled };
      }
      return next;
    });
  }, []);

  const toggleAllOutput = useCallback((enabled: boolean) => {
    setSelectedPreset("custom");
    setOutputScanners((prev) => {
      const next = { ...prev };
      for (const key of Object.keys(next)) {
        next[key] = { ...next[key], enabled };
      }
      return next;
    });
  }, []);

  const handleSave = async () => {
    setIsSaving(true);
    setSaveError(null);
    try {
      const config = localToGuardConfig(
        scanMode,
        inputScanners,
        outputScanners,
        sanitize,
        failFast,
      );
      await updateGuardConfig(keyId, config);
      onSaved(config);
    } catch (err) {
      setSaveError(
        err instanceof Error ? err.message : "Failed to save config",
      );
    } finally {
      setIsSaving(false);
    }
  };

  const handleRemoveConfig = async () => {
    setIsSaving(true);
    setSaveError(null);
    try {
      await updateGuardConfig(keyId, null);
      onSaved(null);
    } catch (err) {
      setSaveError(
        err instanceof Error ? err.message : "Failed to remove config",
      );
    } finally {
      setIsSaving(false);
    }
  };

  const showInput = scanMode === "prompt_only" || scanMode === "both";
  const showOutput = scanMode === "output_only" || scanMode === "both";

  const filteredInput = ALL_INPUT_SCANNERS.filter((name) => {
    if (!inputFilter) return true;
    const meta = SCANNER_META[name];
    const q = inputFilter.toLowerCase();
    return (
      name.includes(q) ||
      meta?.label.toLowerCase().includes(q) ||
      meta?.category.toLowerCase().includes(q)
    );
  });

  const filteredOutput = ALL_OUTPUT_SCANNERS.filter((name) => {
    if (!outputFilter) return true;
    const meta = SCANNER_META[name];
    const q = outputFilter.toLowerCase();
    return (
      name.includes(q) ||
      meta?.label.toLowerCase().includes(q) ||
      meta?.category.toLowerCase().includes(q)
    );
  });

  return (
    <div className="bg-stone-50 border border-stone-300 rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-stone-200">
        <div className="flex items-center gap-3">
          <IconShieldBolt className="w-5 h-5 text-lime-500" />
          <div>
            <h3 className="text-sm font-bold text-stone-800">
              Guard Protection Config
            </h3>
            <p className="text-[11px] text-stone-500">
              Key:{" "}
              <span className="font-semibold text-stone-400">{keyName}</span>
              {" · "}
              Configure what this API key protects automatically
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-stone-500 hover:text-stone-700 transition-colors p-1"
        >
          <IconX className="w-4 h-4" />
        </button>
      </div>

      <div className="p-5 space-y-5">
        <div className="space-y-2">
          <Label className="text-xs font-mono uppercase text-stone-500">
            Config Theme
          </Label>
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-1.5">
            {PRESET_BUTTON_ORDER.map((presetId) => {
              const isCustom = presetId === "custom";
              const preset = isCustom
                ? {
                    label: "Custom",
                    description: "Manual scanner selection and thresholds.",
                  }
                : GUARD_PRESETS[presetId];

              return (
                <button
                  key={presetId}
                  onClick={() => applyPreset(presetId)}
                  className={`px-3 py-2 rounded-lg border text-left transition-colors ${
                    selectedPreset === presetId
                      ? "bg-lime-500/20 border-lime-500 text-lime-400"
                      : "border-stone-300 text-stone-500 hover:text-stone-700"
                  }`}
                >
                  <p className="text-[11px] font-mono uppercase">{preset.label}</p>
                  <p className="text-[10px] text-stone-500 truncate">
                    {preset.description}
                  </p>
                </button>
              );
            })}
          </div>
          <p className="text-[10px] text-stone-600">
            Pick a recommended baseline, then fine-tune any scanner below.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label className="text-xs font-mono uppercase text-stone-500">
              Scan Mode
            </Label>
            <div className="flex gap-1.5">
              {(
                [
                  {
                    mode: "prompt_only" as ScanMode,
                    label: "Input Only",
                  },
                  {
                    mode: "output_only" as ScanMode,
                    label: "Output Only",
                  },
                  { mode: "both" as ScanMode, label: "Both", icon: "BOTH" },
                ] as const
              ).map(({ mode, label }) => (
                <button
                  key={mode}
                  onClick={() => {
                    setSelectedPreset("custom");
                    setScanMode(mode);
                  }}
                  className={`flex-1 px-3 py-2 text-xs font-mono uppercase rounded-lg border transition-colors ${
                    scanMode === mode
                      ? "bg-lime-500/20 border-lime-500 text-lime-400"
                      : "border-stone-300 text-stone-500 hover:text-stone-700"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            <p className="text-[10px] text-stone-600">
              {scanMode === "prompt_only" &&
                'API callers just send {"prompt": "..."} - no extra headers needed'}
              {scanMode === "output_only" &&
                'API callers just send {"output": "..."} - no extra headers needed'}
              {scanMode === "both" &&
                "Callers must send X-Scan-Type header (prompt / output / both) to specify what to scan"}
            </p>
          </div>

          <div className="space-y-2">
            <Label className="text-xs font-mono uppercase text-stone-500">
              Options
            </Label>
            <div className="flex flex-col gap-2">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={sanitize}
                  onChange={(e) => {
                    setSelectedPreset("custom");
                    setSanitize(e.target.checked);
                  }}
                  className="rounded border-stone-300 accent-lime-500"
                />
                <span className="text-xs text-stone-400">
                  Return sanitized text
                </span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={failFast}
                  onChange={(e) => {
                    setSelectedPreset("custom");
                    setFailFast(e.target.checked);
                  }}
                  className="rounded border-stone-300 accent-lime-500"
                />
                <span className="text-xs text-stone-400">
                  Fail fast (stop after first failure)
                </span>
              </label>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {showInput && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <IconArrowRight className="w-3.5 h-3.5 text-stone-500" />
                  <span className="text-stone-400 font-semibold text-[11px] uppercase font-mono tracking-wider">
                    Input Scanners
                  </span>
                  <span className="text-[10px] font-mono bg-stone-100 text-stone-500 px-1.5 py-0.5 rounded">
                    {countEnabled(inputScanners)}/{ALL_INPUT_SCANNERS.length}
                  </span>
                </div>
                <div className="flex gap-1">
                  <button
                    onClick={() => toggleAllInput(true)}
                    className="text-[9px] font-mono text-lime-500 hover:text-lime-400 px-1.5 py-0.5 rounded border border-lime-500/20"
                  >
                    All on
                  </button>
                  <button
                    onClick={() => toggleAllInput(false)}
                    className="text-[9px] font-mono text-red-500 hover:text-red-400 px-1.5 py-0.5 rounded border border-red-500/20"
                  >
                    All off
                  </button>
                </div>
              </div>

              <input
                type="text"
                placeholder="Filter scanners..."
                value={inputFilter}
                onChange={(e) => setInputFilter(e.target.value)}
                className="w-full bg-stone-100 border border-stone-200 rounded-lg px-3 py-1.5 text-[11px] text-stone-400 placeholder-stone-600 focus:outline-none focus:border-stone-300"
              />

              <div className="flex flex-col gap-1.5 max-h-[400px] overflow-y-auto pr-1">
                {filteredInput.map((name) => (
                  <ScannerToggleRow
                    key={`input-${name}`}
                    name={name}
                    entry={inputScanners[name]}
                    onToggle={() =>
                      updateInput(name, {
                        enabled: !inputScanners[name].enabled,
                      })
                    }
                    onThresholdChange={(v) =>
                      updateInput(name, { threshold: v })
                    }
                    onSettingsChange={(v) =>
                      updateInput(name, { settingsJson: v })
                    }
                  />
                ))}
              </div>
            </div>
          )}

          {showOutput && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <IconArrowLeft className="w-3.5 h-3.5 text-stone-500" />
                  <span className="text-stone-400 font-semibold text-[11px] uppercase font-mono tracking-wider">
                    Output Scanners
                  </span>
                  <span className="text-[10px] font-mono bg-stone-100 text-stone-500 px-1.5 py-0.5 rounded">
                    {countEnabled(outputScanners)}/{ALL_OUTPUT_SCANNERS.length}
                  </span>
                </div>
                <div className="flex gap-1">
                  <button
                    onClick={() => toggleAllOutput(true)}
                    className="text-[9px] font-mono text-lime-500 hover:text-lime-400 px-1.5 py-0.5 rounded border border-lime-500/20"
                  >
                    All on
                  </button>
                  <button
                    onClick={() => toggleAllOutput(false)}
                    className="text-[9px] font-mono text-red-500 hover:text-red-400 px-1.5 py-0.5 rounded border border-red-500/20"
                  >
                    All off
                  </button>
                </div>
              </div>

              <input
                type="text"
                placeholder="Filter scanners..."
                value={outputFilter}
                onChange={(e) => setOutputFilter(e.target.value)}
                className="w-full bg-stone-100 border border-stone-200 rounded-lg px-3 py-1.5 text-[11px] text-stone-400 placeholder-stone-600 focus:outline-none focus:border-stone-300"
              />

              <div className="flex flex-col gap-1.5 max-h-[400px] overflow-y-auto pr-1">
                {filteredOutput.map((name) => (
                  <ScannerToggleRow
                    key={`output-${name}`}
                    name={name}
                    entry={outputScanners[name]}
                    onToggle={() =>
                      updateOutput(name, {
                        enabled: !outputScanners[name].enabled,
                      })
                    }
                    onThresholdChange={(v) =>
                      updateOutput(name, { threshold: v })
                    }
                    onSettingsChange={(v) =>
                      updateOutput(name, { settingsJson: v })
                    }
                  />
                ))}
              </div>
            </div>
          )}
        </div>

        {saveError && (
          <div className="p-3 bg-red-900/20 border border-red-700 rounded-lg text-red-400 text-xs">
            {saveError}
          </div>
        )}

        <div className="flex items-center justify-between pt-3 border-t border-stone-200">
          <div className="flex gap-2">
            {hasExisting && (
              <Button
                variant="ghost"
                size="sm"
                onClick={handleRemoveConfig}
                disabled={isSaving}
                className="text-xs text-red-500 hover:text-red-400"
              >
                Remove Config
              </Button>
            )}
          </div>
          <div className="flex gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={onClose}
              className="text-xs"
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleSave}
              disabled={isSaving}
              className="text-xs"
            >
              {isSaving ? (
                <>
                  <IconLoader2 className="w-3 h-3 mr-1 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <IconCheck className="w-3 h-3 mr-1" />
                  Save Config
                </>
              )}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ConfigBadge({ config }: { config: GuardConfig | null }) {
  if (!config) {
    return (
      <span className="text-[10px] font-mono text-stone-600 px-1.5 py-0.5 rounded border border-stone-200 bg-stone-50">
        No config
      </span>
    );
  }

  const modeLabel =
    config.scan_mode === "prompt_only"
      ? "Input"
      : config.scan_mode === "output_only"
        ? "Output"
        : "Both";

  const inputCount = Object.values(config.input_scanners).filter(
    (s) => s.enabled,
  ).length;
  const outputCount = Object.values(config.output_scanners).filter(
    (s) => s.enabled,
  ).length;

  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[10px] font-mono text-lime-400 px-1.5 py-0.5 rounded border border-lime-500/20 bg-lime-500/10">
        {modeLabel}
      </span>
      {(config.scan_mode === "prompt_only" || config.scan_mode === "both") && (
        <span className="text-[10px] font-mono text-stone-500">
          {inputCount}in
        </span>
      )}
      {(config.scan_mode === "output_only" || config.scan_mode === "both") && (
        <span className="text-[10px] font-mono text-stone-500">
          {outputCount}out
        </span>
      )}
    </div>
  );
}


export default function CredentialsPage() {
  const [keys, setKeys] = useState<ApiKeyDisplay[]>([]);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [selectedLang, setSelectedLang] = useState("curl");
  const [codeCopied, setCodeCopied] = useState(false);
  const [configuringKeyId, setConfiguringKeyId] = useState<string | null>(null);
  const [codeSnippets, setCodeSnippets] = useState(() =>
    buildCodeSnippets("http://YOUR_HOST"),
  );
  useEffect(() => {
    setCodeSnippets(buildCodeSnippets(window.location.origin));
  }, []);

  const loadKeys = useCallback(async () => {
    try {
      const result = await listApiKeys();
      setKeys(
        result.map((k) => ({
          id: k.id,
          name: k.name,
          keyPrefix: k.keyPrefix,
          createdAt: new Date(k.createdAt),
          lastUsedAt: k.lastUsedAt ? new Date(k.lastUsedAt) : null,
          guardConfig: k.guardConfig,
        })),
      );
    } catch (err) {
      console.error("Failed to load API keys:", err);
    }
  }, []);

  useEffect(() => {
    void loadKeys();
  }, [loadKeys]);

  const handleCreate = async () => {
    if (!newKeyName.trim()) return;
    setIsCreating(true);
    setCreateError(null);
    try {
      const result = await createApiKey(newKeyName.trim());
      if (!result.ok) {
        setCreateError(result.error);
        return;
      }

      setNewKey(result.key);
      setNewKeyName("");
      await loadKeys();
    } catch (err) {
      setCreateError(
        err instanceof Error ? err.message : "Failed to create API key",
      );
      console.error("Failed to create API key:", err);
    } finally {
      setIsCreating(false);
    }
  };

  const handleRevoke = async (keyId: string) => {
    try {
      if (configuringKeyId === keyId) {
        setConfiguringKeyId(null);
      }
      await revokeApiKey(keyId);
      await loadKeys();
    } catch (err) {
      console.error("Failed to revoke API key:", err);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const copyCode = () => {
    navigator.clipboard.writeText(
      codeSnippets[selectedLang as keyof typeof codeSnippets],
    );
    setCodeCopied(true);
    setTimeout(() => setCodeCopied(false), 2000);
  };

  const handleConfigSaved = (keyId: string, config: GuardConfig | null) => {
    setKeys((prev) =>
      prev.map((k) => (k.id === keyId ? { ...k, guardConfig: config } : k)),
    );
    setConfiguringKeyId(null);
  };

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-10">
      <div>
        <h1 className="text-xl font-bold">API Credentials</h1>
        <p className="text-sm text-stone-500">
          Manage API keys and configure per-key guard protection for the LLM
          Guard API
        </p>
      </div>

      {/* Create New Key */}
      <div className="flex flex-col gap-6">
        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconKey className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              API Keys
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200"></span>
          <Button
            size="sm"
            onClick={() => setShowCreate(!showCreate)}
            className="h-6 px-3 text-xs font-mono uppercase"
          >
            <IconPlus className="w-3 h-3 mr-1" />
            New Key
          </Button>
        </div>

        {showCreate && (
          <div className="bg-stone-50 border border-stone-200 rounded-2xl p-6">
            <div className="flex flex-col gap-4">
              <div className="space-y-2">
                <Label htmlFor="keyName">Key Name</Label>
                <Input
                  id="keyName"
                  placeholder="e.g., Production API Key"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                />
              </div>
              <Button
                onClick={handleCreate}
                disabled={!newKeyName.trim() || isCreating}
                className="w-fit"
              >
                {isCreating ? "Creating..." : "Create API Key"}
              </Button>
              {createError && (
                <p className="text-sm text-red-500">{createError}</p>
              )}
            </div>
          </div>
        )}


        {newKey && (
          <div className="bg-lime-900/20 border border-lime-700 rounded-2xl p-6">
            <div className="flex flex-col gap-4">
              <p className="text-lime-400 text-sm font-semibold">
                API Key Created Successfully!
              </p>
              <p className="text-stone-400 text-xs">
                Copy this key now. You won&apos;t be able to see it again.
              </p>
              <div className="flex gap-2 items-center">
                <code className="flex-1 bg-stone-100 px-4 py-2 rounded-lg font-mono text-sm break-all">
                  {newKey}
                </code>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => copyToClipboard(newKey)}
                >
                  {copied ? (
                    <IconCheck className="w-4 h-4" />
                  ) : (
                    <IconCopy className="w-4 h-4" />
                  )}
                </Button>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setNewKey(null);
                  setShowCreate(false);
                }}
                className="w-fit"
              >
                Done
              </Button>
            </div>
          </div>
        )}
        <div className="bg-stone-50 border border-stone-200 rounded-2xl overflow-hidden">
          {keys.length === 0 ? (
            <div className="p-8 text-center text-stone-500">
              <IconKey className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No API keys yet</p>
              <p className="text-xs mt-1">
                Create one to start using the Guard API
              </p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="border-b border-stone-200">
                <tr className="text-left text-xs font-mono uppercase text-stone-500">
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Key</th>
                  <th className="px-4 py-3">Protection</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3">Last Used</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {keys.map((key) => (
                  <tr
                    key={key.id}
                    className="border-b border-stone-200 last:border-0"
                  >
                    <td className="px-4 py-3 font-medium">{key.name}</td>
                    <td className="px-4 py-3">
                      <code className="text-stone-500 font-mono text-sm">
                        {key.keyPrefix}...
                      </code>
                    </td>
                    <td className="px-4 py-3">
                      <ConfigBadge config={key.guardConfig} />
                    </td>
                    <td className="px-4 py-3 text-stone-500 text-sm">
                      {new Date(key.createdAt).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-stone-500 text-sm">
                      {key.lastUsedAt
                        ? new Date(key.lastUsedAt).toLocaleDateString()
                        : "Never"}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        {/* Configure Protection */}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() =>
                            setConfiguringKeyId(
                              configuringKeyId === key.id ? null : key.id,
                            )
                          }
                          className={`${
                            configuringKeyId === key.id
                              ? "text-lime-400 hover:text-lime-300"
                              : "text-stone-500 hover:text-stone-700"
                          }`}
                          title="Configure guard protection"
                        >
                          <IconSettings className="w-4 h-4" />
                        </Button>

                        {/* Revoke */}
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-red-500 hover:text-red-400"
                            >
                              <IconTrash className="w-4 h-4" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>
                                Revoke API Key?
                              </AlertDialogTitle>
                              <AlertDialogDescription>
                                This will immediately invalidate the key. Any
                                applications using this key will stop working.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => handleRevoke(key.id)}
                                className="bg-red-600 hover:bg-red-700"
                              >
                                Revoke Key
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {configuringKeyId && (
          <GuardConfigPanel
            key={configuringKeyId}
            keyId={configuringKeyId}
            keyName={
              keys.find((k) => k.id === configuringKeyId)?.name ?? "Unknown"
            }
            initialConfig={
              keys.find((k) => k.id === configuringKeyId)?.guardConfig ?? null
            }
            onClose={() => setConfiguringKeyId(null)}
            onSaved={(config) => handleConfigSaved(configuringKeyId, config)}
          />
        )}

        <div className="flex gap-4 items-center">
          <div className="flex gap-2 items-center">
            <IconKey className="w-4 h-4 text-stone-500" />
            <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
              How to use your API key
            </span>
          </div>
          <span className="flex-1 h-px bg-stone-200"></span>
        </div>

        <div className="bg-stone-50 border border-stone-200 rounded-2xl p-5 mb-2">
          <div className="flex items-start gap-3 mb-4">
            <IconShieldBolt className="w-5 h-5 text-lime-500 mt-0.5 flex-shrink-0" />
            <div className="text-xs text-stone-400 space-y-1.5">
              <p className="font-semibold text-stone-700">
                Per-key protection means simpler API calls
              </p>
              <p>
                When you configure protection on an API key, the scanners run
                automatically based on that config. Your API calls become
                simpler:
              </p>
              <ul className="list-disc list-inside space-y-1 text-stone-500">
                <li>
                  <span className="font-mono text-lime-400">prompt_only</span>{" "}
                  or{" "}
                  <span className="font-mono text-lime-400">output_only</span>
                  {" → "}just send the text, no extra headers needed
                </li>
                <li>
                  <span className="font-mono text-lime-400">both</span>
                  {" → "}send{" "}
                  <code className="text-stone-700 bg-stone-100 px-1 py-0.5 rounded">
                    X-Scan-Type: prompt
                  </code>{" "}
                  or{" "}
                  <code className="text-stone-700 bg-stone-100 px-1 py-0.5 rounded">
                    X-Scan-Type: output
                  </code>{" "}
                  header to specify what you&apos;re scanning
                </li>
                <li>
                  Keys without config use the legacy per-request behaviour
                  (caller sends full scanner config each time)
                </li>
              </ul>
            </div>
          </div>
        </div>

        <div className="flex border border-stone-200 rounded-2xl overflow-hidden">
          <div className="flex flex-col border-r border-stone-200 bg-stone-50">
            {LANGUAGES.map((lang) => (
              <button
                key={lang.id}
                type="button"
                onClick={() => setSelectedLang(lang.id)}
                className={`flex items-center gap-3 px-4 py-3 border-b border-stone-200 last:border-b-0 transition-colors duration-200 ease cursor-pointer ${
                  selectedLang === lang.id
                    ? "bg-stone-100"
                    : "bg-stone-50 hover:bg-stone-100"
                }`}
              >
                <img
                  alt={lang.name}
                  className={`w-5 h-5 ${lang.darkInvert ? "dark:invert" : ""}`}
                  src={lang.icon}
                />
                <span
                  className={`text-sm font-medium ${
                    selectedLang === lang.id
                      ? "text-stone-800"
                      : "text-stone-500"
                  }`}
                >
                  {lang.name}
                </span>
              </button>
            ))}
          </div>
          <div className="flex-1 bg-stone-50 relative">
            <div className="absolute top-4 right-4 z-10">
              <Button
                size="sm"
                variant="secondary"
                onClick={copyCode}
                className="h-6 px-3 text-xs font-mono uppercase"
              >
                {codeCopied ? (
                  <>
                    <IconCheck className="w-4 h-4 mr-1" />
                    Copied
                  </>
                ) : (
                  <>
                    <IconCopy className="w-4 h-4 mr-1" />
                    Copy
                  </>
                )}
              </Button>
            </div>
            <div className="overflow-auto p-6 max-h-[450px] min-h-[450px]">
              <pre className="whitespace-pre text-sm">
                <code className="text-stone-700 font-mono">
                  {codeSnippets[selectedLang as keyof typeof codeSnippets]}
                </code>
              </pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
