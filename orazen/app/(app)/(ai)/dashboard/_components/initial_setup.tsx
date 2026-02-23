"use client";

import { useState, useEffect, useCallback } from "react";
import Image from "next/image";
import Link from "next/link";
import {
  IconCheck,
  IconLoader2,
  IconChevronRight,
  IconX,
} from "@tabler/icons-react";
import { listApiKeys } from "@/lib/actions/api-keys";
import { listModelConfigs } from "@/lib/actions/models";
import { getGuardStats } from "@/lib/actions/guard";
import { listScans } from "@/lib/actions/scans";


interface SetupStep {
  key: string;
  number: number;
  title: string;
  description: string;
  configured: boolean;
  loading: boolean;
  configuredLabel: string;
  notConfiguredLabel: string;
  buttonLabel: string;
  href: string;
  image: string;
}

function StatusBadge({
  configured,
  loading,
  configuredLabel,
  notConfiguredLabel,
}: {
  configured: boolean;
  loading: boolean;
  configuredLabel: string;
  notConfiguredLabel: string;
}) {
  if (loading) {
    return (
      <span className="flex items-center gap-2">
        <IconLoader2 size={12} className="animate-spin text-stone-500" />
        <span className="text-stone-500 font-semibold text-xs tracking-[0.48px] font-mono uppercase">
          Checking...
        </span>
      </span>
    );
  }

  if (configured) {
    return (
      <span className="flex items-center gap-2">
        <span className="size-2.5 border-[1.5px] rounded-full bg-emerald-300 border-emerald-700"></span>
        <span className="text-emerald-500 font-semibold text-xs tracking-[0.48px] font-mono uppercase">
          {configuredLabel}
        </span>
      </span>
    );
  }

  return (
    <span className="flex items-center gap-2">
      <span className="size-2.5 border-[1.5px] rounded-full bg-rose-300 border-rose-700"></span>
      <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase">
        {notConfiguredLabel}
      </span>
    </span>
  );
}


function StepRow({ step }: { step: SetupStep }) {
  return (
    <div className="flex items-center justify-between gap-6 px-6 py-6">
      <div className="flex items-start gap-6 flex-1 w-1/2">
        <div
          className={`size-8 rounded-full flex items-center justify-center shrink-0 transition-colors ${
            step.configured
              ? "bg-emerald-500/20 border border-emerald-500/40"
              : "bg-stone-100"
          }`}
        >
          {step.configured ? (
            <IconCheck size={16} className="text-emerald-400" />
          ) : (
            <p className="text-stone-800 font-medium text-base font-mono text-center">
              {step.number}
            </p>
          )}
        </div>
        <div className="space-y-4">
          <div>
            <div className="flex items-center gap-4 mb-2">
              <p
                className={`font-medium text-base ${
                  step.configured
                    ? "text-stone-500 dark:text-stone-500"
                    : "text-stone-800"
                }`}
              >
                {step.title}
              </p>
              <StatusBadge
                configured={step.configured}
                loading={step.loading}
                configuredLabel={step.configuredLabel}
                notConfiguredLabel={step.notConfiguredLabel}
              />
            </div>
            <p className="text-stone-500 dark:text-stone-600 font-normal text-sm">
              {step.description}
            </p>
          </div>
          {!step.configured && !step.loading && (
            <Link href={step.href}>
              <button
                type="button"
                className="group cursor-pointer box-border flex items-center justify-center font-semibold font-mono uppercase border transition-all ease-in duration-75 whitespace-nowrap text-center select-none disabled:shadow-none disabled:opacity-50 disabled:cursor-not-allowed gap-x-1 active:shadow-none active:scale-95 text-xs leading-4 rounded-lg px-3 py-1 h-6
                  text-stone-950 bg-stone-200 border-2 border-stone-300 hover:bg-stone-300
                  disabled:bg-stone-200 disabled:border-stone-300"
                translate="no"
              >
                {step.buttonLabel}
                <span className="-mr-1">
                  <IconChevronRight size={14} />
                </span>
              </button>
            </Link>
          )}
          {step.configured && (
            <Link href={step.href}>
              <button
                type="button"
                className="group cursor-pointer box-border flex items-center justify-center font-semibold font-mono uppercase border transition-all ease-in duration-75 whitespace-nowrap text-center select-none gap-x-1 active:shadow-none active:scale-95 text-xs leading-4 rounded-lg px-3 py-1 h-6
                  text-emerald-400 bg-transparent border border-emerald-500/30 hover:bg-emerald-500/10
                  dark:border-emerald-500/30 dark:hover:bg-emerald-500/10"
                translate="no"
              >
                Manage
                <span className="-mr-1">
                  <IconChevronRight size={14} />
                </span>
              </button>
            </Link>
          )}
        </div>
      </div>
      <div className="flex-1 w-1/2 flex justify-end">
        <Image
          width={100}
          height={100}
          alt={step.title}
          src={step.image}
          className={step.configured ? "opacity-40" : "opacity-100"}
        />
      </div>
    </div>
  );
}


export default function InitialSetup() {
  const [hasApiKeys, setHasApiKeys] = useState(false);
  const [hasModels, setHasModels] = useState(false);
  const [hasGuardScans, setHasGuardScans] = useState(false);
  const [hasGarakScans, setHasGarakScans] = useState(false);

  const [loadingApiKeys, setLoadingApiKeys] = useState(true);
  const [loadingModels, setLoadingModels] = useState(true);
  const [loadingGuard, setLoadingGuard] = useState(true);
  const [loadingScans, setLoadingScans] = useState(true);

  const [dismissed, setDismissed] = useState(false);

  const fetchSetupStatus = useCallback(async () => {
    // Fetch all in parallel
    const [apiKeysPromise, modelsPromise, guardPromise, scansPromise] = [
      listApiKeys()
        .then((keys) => {
          const activeKeys = keys.filter((k) => !k.revokedAt);
          setHasApiKeys(activeKeys.length > 0);
        })
        .catch(() => setHasApiKeys(false))
        .finally(() => setLoadingApiKeys(false)),

      listModelConfigs()
        .then((models) => {
          setHasModels(models.length > 0);
        })
        .catch(() => setHasModels(false))
        .finally(() => setLoadingModels(false)),

      getGuardStats()
        .then((stats) => {
          setHasGuardScans(stats.totalScans > 0);
        })
        .catch(() => setHasGuardScans(false))
        .finally(() => setLoadingGuard(false)),

      listScans(5)
        .then((scans) => {
          const completedScans = scans.filter(
            (s) => s.status === "completed" || s.status === "running",
          );
          setHasGarakScans(completedScans.length > 0);
        })
        .catch(() => setHasGarakScans(false))
        .finally(() => setLoadingScans(false)),
    ];

    await Promise.allSettled([
      apiKeysPromise,
      modelsPromise,
      guardPromise,
      scansPromise,
    ]);
  }, []);

  useEffect(() => {
    fetchSetupStatus();
  }, [fetchSetupStatus]);

  const allLoaded =
    !loadingApiKeys && !loadingModels && !loadingGuard && !loadingScans;
  const allConfigured =
    allLoaded && hasApiKeys && hasModels && hasGuardScans && hasGarakScans;

  if (allConfigured || dismissed) {
    return null;
  }

  const configuredCount = [
    hasApiKeys,
    hasModels,
    hasGuardScans,
    hasGarakScans,
  ].filter(Boolean).length;

  const steps: SetupStep[] = [
    {
      key: "api-keys",
      number: 1,
      title: "Add API Credentials",
      description:
        "Add your LLM provider API keys (OpenAI, HuggingFace, Ollama, etc.).",
      configured: hasApiKeys,
      loading: loadingApiKeys,
      configuredLabel: "Configured",
      notConfiguredLabel: "Not Configured",
      buttonLabel: "Add Credentials",
      href: "/credentials",
      image: "/official/logo-icon.webp",
    },
    {
      key: "models",
      number: 2,
      title: "Configure LLM Model",
      description:
        "Select and configure the LLM model you want to test for security vulnerabilities.",
      configured: hasModels,
      loading: loadingModels,
      configuredLabel: "Configured",
      notConfiguredLabel: "Not Set",
      buttonLabel: "Configure Model",
      href: "/models",
      image: "/official/logo-icon.webp",
    },
    {
      key: "guard",
      number: 3,
      title: "Test Connection",
      description:
        "Verify your LLM connection is working correctly before running security scans.",
      configured: hasGuardScans,
      loading: loadingGuard,
      configuredLabel: "Tested",
      notConfiguredLabel: "Not Tested",
      buttonLabel: "Test Connection",
      href: "/guard",
      image: "/official/logo-icon.webp",
    },
    {
      key: "scan",
      number: 4,
      title: "Run Security Scan",
      description:
        "Launch your first Garak vulnerability scan to test prompt injection, jailbreaks, and more.",
      configured: hasGarakScans,
      loading: loadingScans,
      configuredLabel: "Completed",
      notConfiguredLabel: "Pending",
      buttonLabel: "Start Scan",
      href: "/scanner",
      image: "/official/logo-icon.webp",
    },
  ];

  return (
    <div className="border border-stone-200 rounded-2xl overflow-hidden relative">
      {allLoaded && configuredCount > 0 && (
        <button
          onClick={() => setDismissed(true)}
          className="absolute top-4 right-4 z-10 p-1 rounded-lg text-stone-600 hover:text-stone-400 hover:bg-stone-100 transition-colors"
          title="Dismiss setup wizard"
        >
          <IconX size={16} />
        </button>
      )}

      {/* Header */}
      <div className="bg-stone-50 px-6 py-4 border-b border-stone-200">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-stone-800 font-medium text-base">
              Welcome to Orazen Security Suite
            </p>
            <p className="text-stone-500 dark:text-stone-600 font-normal text-sm">
              Follow these steps to configure your LLM and start testing for
              vulnerabilities with Garak and LLM Guard.
            </p>
          </div>
          {allLoaded && (
            <div className="flex items-center gap-3 shrink-0 ml-4">
              <div className="flex gap-1">
                {[0, 1, 2, 3].map((i) => (
                  <div
                    key={i}
                    className={`h-1.5 w-6 rounded-full transition-colors ${
                      i < configuredCount ? "bg-emerald-500" : "bg-stone-300"
                    }`}
                  />
                ))}
              </div>
              <span className="text-xs font-mono text-stone-500">
                {configuredCount}/4
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Steps */}
      <div className="bg-stone-50">
        {steps.map((step, idx) => (
          <div key={step.key}>
            {idx > 0 && <div className="border-t border-stone-200/50 mx-6" />}
            <StepRow step={step} />
          </div>
        ))}
      </div>
    </div>
  );
}
