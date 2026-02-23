"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { listScans, type Scan } from "@/lib/actions/scans";
import {
  IconRadar,
  IconShieldCheck,
  IconAlertTriangle,
  IconLoader2,
  IconRefresh,
  IconChevronRight,
  IconCircleFilled,
  IconBug,
  IconFlame,
  IconSkull,
} from "@tabler/icons-react";

interface GarakStats {
  totalScans: number;
  completedScans: number;
  runningScans: number;
  failedScans: number;
  totalVulnerabilities: number;
  avgRiskScore: number;
  highestRiskScore: number;
  lastScanAt: string | null;
}

function computeStats(scans: Scan[]): GarakStats {
  const completed = scans.filter((s) => s.status === "completed");
  const running = scans.filter(
    (s) => s.status === "running" || s.status === "queued",
  );
  const failed = scans.filter((s) => s.status === "failed");

  const totalVulnerabilities = completed.reduce(
    (sum, s) => sum + s.vulnerabilitiesFound,
    0,
  );

  const riskScores = completed
    .map((s) => s.riskScore)
    .filter((r): r is number => r !== null && r !== undefined);

  const avgRiskScore =
    riskScores.length > 0
      ? riskScores.reduce((a, b) => a + b, 0) / riskScores.length
      : 0;

  const highestRiskScore = riskScores.length > 0 ? Math.max(...riskScores) : 0;

  const sorted = [...scans].sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  );

  return {
    totalScans: scans.length,
    completedScans: completed.length,
    runningScans: running.length,
    failedScans: failed.length,
    totalVulnerabilities,
    avgRiskScore,
    highestRiskScore,
    lastScanAt: sorted.length > 0 ? sorted[0].createdAt : null,
  };
}

function getRiskColor(score: number): string {
  if (score >= 0.7) return "text-red-400";
  if (score >= 0.4) return "text-orange-400";
  if (score >= 0.1) return "text-yellow-400";
  return "text-lime-400";
}

function getRiskBg(score: number): string {
  if (score >= 0.7) return "bg-red-500/10 border-red-500/20";
  if (score >= 0.4) return "bg-orange-500/10 border-orange-500/20";
  if (score >= 0.1) return "bg-yellow-500/10 border-yellow-500/20";
  return "bg-lime-500/10 border-lime-500/20";
}

function getRiskLabel(score: number): string {
  if (score >= 0.7) return "Critical";
  if (score >= 0.4) return "High";
  if (score >= 0.1) return "Medium";
  return "Low";
}

function getStatusIcon(status: string) {
  switch (status) {
    case "completed":
      return <IconShieldCheck className="w-3.5 h-3.5 text-lime-500" />;
    case "running":
    case "queued":
      return <IconLoader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />;
    case "failed":
      return <IconAlertTriangle className="w-3.5 h-3.5 text-red-400" />;
    default:
      return <IconCircleFilled className="w-3.5 h-3.5 text-stone-500" />;
  }
}

function getStatusBadgeColor(status: string): string {
  switch (status) {
    case "completed":
      return "bg-lime-500/10 text-lime-400 border-lime-500/20";
    case "running":
    case "queued":
      return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    case "failed":
      return "bg-red-500/10 text-red-400 border-red-500/20";
    default:
      return "bg-stone-500/10 text-stone-400 border-stone-500/20";
  }
}

function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;

  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

export default function GarakSummary() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const fetchScans = useCallback(async () => {
    try {
      const data = await listScans(20);
      setScans(data);
    } catch (err) {
      console.error("Failed to fetch Garak scans:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  // Poll for running scans
  useEffect(() => {
    const hasRunning = scans.some(
      (s) => s.status === "running" || s.status === "queued",
    );
    if (!hasRunning) return;

    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, [scans, fetchScans]);

  const stats = computeStats(scans);
  const recentScans = [...scans]
    .sort(
      (a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    )
    .slice(0, 5);

  return (
    <div className="flex flex-col gap-6">
      {/* Section Header */}
      <div className="flex gap-4 items-center">
        <div className="flex gap-2 items-center">
          <IconRadar className="w-4 h-4 text-stone-500" />
          <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
            Garak Vulnerability Scans
          </span>
        </div>
        <span className="flex-1 h-px bg-stone-200" />
        {stats.runningScans > 0 && (
          <div className="flex items-center gap-1 px-2 py-0.5 rounded-md border border-blue-500/20 bg-blue-500/10">
            <IconLoader2 className="w-3 h-3 text-blue-400 animate-spin" />
            <span className="text-[10px] font-mono uppercase text-blue-400">
              {stats.runningScans} running
            </span>
          </div>
        )}
      </div>

      {/* Main Card */}
      <div
        className={`flex flex-col bg-stone-50 border border-stone-200 rounded-2xl transition-opacity ${
          isLoading ? "opacity-60" : "opacity-100"
        }`}
      >
        {/* Description Row */}
        <div className="flex justify-between py-4 px-6 items-center">
          <p className="text-stone-800 font-normal text-sm leading-5">
            Automated red-teaming results powered by NVIDIA Garak.
          </p>
          <button
            onClick={() => {
              setIsLoading(true);
              fetchScans();
            }}
            className="flex items-center gap-1 px-2 py-0.5 rounded-md border border-stone-200 hover:bg-stone-100 transition-colors"
          >
            <IconRefresh
              className={`w-3 h-3 text-stone-500 ${isLoading ? "animate-spin" : ""}`}
            />
            <span className="text-[10px] font-mono uppercase text-stone-500">
              Refresh
            </span>
          </button>
        </div>

        {/* Stats Grid */}
        <div className="border-y border-stone-200 overflow-hidden shrink-0">
          {isLoading && scans.length === 0 ? (
            <div className="p-8 flex items-center justify-center">
              <IconLoader2 className="w-6 h-6 text-stone-500 animate-spin" />
            </div>
          ) : scans.length === 0 ? (
            <div className="p-8 text-center">
              <IconRadar className="w-10 h-10 mx-auto mb-3 text-stone-400" />
              <p className="text-stone-500 text-sm">
                No vulnerability scans yet
              </p>
              <p className="text-stone-600 text-xs mt-1">
                Run your first scan from the{" "}
                <Link
                  href="/scanner"
                  className="text-blue-400 hover:text-blue-300 underline"
                >
                  Garak Scanner
                </Link>{" "}
                page
              </p>
            </div>
          ) : (
            <>
              {/* Stat Cards */}
              <div className="grid grid-cols-4">
                {/* Total Scans */}
                <div className="border-stone-200 border-b border-r p-4">
                  <div className="flex flex-col gap-1">
                    <span className="flex items-center gap-2">
                      <IconRadar className="w-3 h-3 text-stone-500" />
                      <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase leading-4">
                        Total Scans
                      </span>
                    </span>
                    <div className="flex gap-2 items-baseline">
                      <p className="text-stone-800 font-semibold text-sm leading-5">
                        {stats.totalScans}
                      </p>
                      <p className="text-stone-600 font-normal text-xs font-mono leading-4">
                        {stats.completedScans} completed
                      </p>
                    </div>
                  </div>
                </div>

                {/* Vulnerabilities Found */}
                <div className="border-stone-200 border-b border-r p-4">
                  <div className="flex flex-col gap-1">
                    <span className="flex items-center gap-2">
                      <IconBug className="w-3 h-3 text-orange-500" />
                      <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase leading-4">
                        Vulnerabilities
                      </span>
                    </span>
                    <div className="flex gap-2 items-baseline">
                      <p
                        className={`font-semibold text-sm leading-5 ${
                          stats.totalVulnerabilities > 0
                            ? "text-orange-400"
                            : "text-lime-400"
                        }`}
                      >
                        {stats.totalVulnerabilities}
                      </p>
                      <p className="text-stone-600 font-normal text-xs font-mono leading-4">
                        found
                      </p>
                    </div>
                  </div>
                </div>

                {/* Average Risk */}
                <div className="border-stone-200 border-b border-r p-4">
                  <div className="flex flex-col gap-1">
                    <span className="flex items-center gap-2">
                      <IconFlame className="w-3 h-3 text-yellow-500" />
                      <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase leading-4">
                        Avg Risk
                      </span>
                    </span>
                    <div className="flex gap-2 items-baseline">
                      <p
                        className={`font-semibold text-sm leading-5 ${getRiskColor(stats.avgRiskScore)}`}
                      >
                        {(stats.avgRiskScore * 100).toFixed(0)}%
                      </p>
                      <p className="text-stone-600 font-normal text-xs font-mono leading-4">
                        {getRiskLabel(stats.avgRiskScore)}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Highest Risk */}
                <div className="border-stone-200 border-b p-4">
                  <div className="flex flex-col gap-1">
                    <span className="flex items-center gap-2">
                      <IconSkull className="w-3 h-3 text-red-500" />
                      <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase leading-4">
                        Peak Risk
                      </span>
                    </span>
                    <div className="flex gap-2 items-baseline">
                      <p
                        className={`font-semibold text-sm leading-5 ${getRiskColor(stats.highestRiskScore)}`}
                      >
                        {(stats.highestRiskScore * 100).toFixed(0)}%
                      </p>
                      <p className="text-stone-600 font-normal text-xs font-mono leading-4">
                        {getRiskLabel(stats.highestRiskScore)}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Recent Scans List */}
              <div className="divide-y divide-stone-200">
                {recentScans.map((scan) => (
                  <div
                    key={scan.id}
                    className="flex items-center gap-4 px-6 py-3 hover:bg-stone-100/50 transition-colors"
                  >
                    <div className="flex items-center gap-2 min-w-0 flex-1">
                      {getStatusIcon(scan.status)}
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase ${getStatusBadgeColor(scan.status)}`}
                      >
                        {scan.status}
                      </span>
                      <span className="text-stone-300 text-sm capitalize truncate">
                        {scan.scanType} scan
                      </span>
                    </div>

                    {/* Progress bar for running scans */}
                    {(scan.status === "running" ||
                      scan.status === "queued") && (
                      <div className="flex items-center gap-2 w-28">
                        <div className="w-16 h-1.5 bg-stone-200 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-blue-500 transition-all duration-300 rounded-full"
                            style={{ width: `${scan.progress}%` }}
                          />
                        </div>
                        <span className="text-[10px] font-mono text-stone-500">
                          {scan.progress}%
                        </span>
                      </div>
                    )}

                    {/* Vulnerabilities count */}
                    {scan.status === "completed" && (
                      <div className="flex items-center gap-3">
                        {scan.vulnerabilitiesFound > 0 ? (
                          <span className="text-xs text-orange-400 font-mono">
                            {scan.vulnerabilitiesFound} vuln
                            {scan.vulnerabilitiesFound !== 1 ? "s" : ""}
                          </span>
                        ) : (
                          <span className="text-xs text-lime-500 font-mono">
                            0 vulns
                          </span>
                        )}
                        {scan.riskScore !== null && (
                          <span
                            className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${getRiskBg(scan.riskScore)} ${getRiskColor(scan.riskScore)}`}
                          >
                            {(scan.riskScore * 100).toFixed(0)}%
                          </span>
                        )}
                      </div>
                    )}

                    {/* Timestamp */}
                    <span className="text-stone-600 text-xs font-mono whitespace-nowrap">
                      {timeAgo(scan.createdAt)}
                    </span>

                    {/* View report link */}
                    {scan.status === "completed" && (
                      <Link
                        href={`/reports?scan=${scan.id}`}
                        className="text-stone-600 hover:text-stone-300 transition-colors"
                      >
                        <IconChevronRight className="w-4 h-4" />
                      </Link>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex py-4 px-6 items-center justify-between">
          <Link
            href="/scanner"
            className="cursor-pointer flex items-center justify-center font-semibold font-mono uppercase border transition-all ease-in duration-75 whitespace-nowrap text-center select-none gap-x-1 active:scale-95 text-xs leading-4 rounded-lg px-3 py-1 h-6 bg-stone-0 border-stone-200 hover:bg-stone-100 hover:border-stone-300"
          >
            Run New Scan
            <IconRadar className="w-3 h-3" />
          </Link>
          {scans.length > 0 && (
            <Link
              href="/reports"
              className="cursor-pointer flex items-center justify-center font-semibold font-mono uppercase border transition-all ease-in duration-75 whitespace-nowrap text-center select-none gap-x-1 active:scale-95 text-xs leading-4 rounded-lg px-3 py-1 h-6 bg-stone-0 border-stone-200 hover:bg-stone-100 hover:border-stone-300"
            >
              View All Reports
              <IconChevronRight className="w-3 h-3 -mr-1" />
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}
