"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import {
  IconRadar,
  IconShieldCheck,
  IconAlertTriangle,
  IconLoader2,
  IconBug,
  IconFlame,
  IconSkull,
  IconChevronDown,
  IconChevronUp,
  IconClock,
  IconSend,
  IconCheck,
  IconX,
  IconTerminal2,
  IconActivity,
  IconCircleFilled,
} from "@tabler/icons-react";
import { getScanStatus, getScanLogs, type ProbeLog } from "@/lib/actions/scans";


interface LiveVulnerability {
  id: string;
  probe_name: string;
  category: string;
  severity: string;
  description: string;
  success_rate: number | null;
  detector_name: string | null;
  timestamp: number;
}

interface ScanProgress {
  status: string;
  progress: number;
  probesCompleted: number;
  probesTotal: number;
  vulnerabilitiesFound: number;
}

interface LiveScanMonitorProps {
  scanId: string;
  onComplete?: () => void;
  onProgress?: (progress: ScanProgress) => void;
}


function getSeverityIcon(severity: string) {
  switch (severity.toLowerCase()) {
    case "critical":
      return <IconSkull className="w-4 h-4 text-red-500" />;
    case "high":
      return <IconFlame className="w-4 h-4 text-orange-500" />;
    case "medium":
      return <IconAlertTriangle className="w-4 h-4 text-yellow-500" />;
    default:
      return <IconBug className="w-4 h-4 text-blue-400" />;
  }
}

function getSeverityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "high":
      return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "medium":
      return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    default:
      return "bg-blue-500/20 text-blue-400 border-blue-500/30";
  }
}

function getProbeStatusIcon(status: string) {
  switch (status) {
    case "passed":
      return <IconCheck className="w-3.5 h-3.5 text-lime-500" />;
    case "failed":
      return <IconX className="w-3.5 h-3.5 text-red-400" />;
    case "error":
      return <IconAlertTriangle className="w-3.5 h-3.5 text-orange-400" />;
    case "skipped":
      return <IconCircleFilled className="w-3.5 h-3.5 text-stone-500" />;
    case "running":
      return <IconLoader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />;
    default:
      return <IconCircleFilled className="w-3.5 h-3.5 text-stone-600" />;
  }
}

function getProbeStatusColor(status: string): string {
  switch (status) {
    case "passed":
      return "text-lime-400";
    case "failed":
      return "text-red-400";
    case "error":
      return "text-orange-400";
    case "skipped":
      return "text-stone-500";
    default:
      return "text-stone-400";
  }
}

function formatDuration(ms: number | null): string {
  if (ms === null || ms === undefined) return "-";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}


export default function LiveScanMonitor({
  scanId,
  onComplete,
  onProgress,
}: LiveScanMonitorProps) {
  const [progress, setProgress] = useState<ScanProgress>({
    status: "queued",
    progress: 0,
    probesCompleted: 0,
    probesTotal: 0,
    vulnerabilitiesFound: 0,
  });
  const [vulnerabilities, setVulnerabilities] = useState<LiveVulnerability[]>(
    [],
  );
  const [probeLogs, setProbeLogs] = useState<ProbeLog[]>([]);
  const [activeTab, setActiveTab] = useState<"feed" | "timeline" | "logs">(
    "feed",
  );
  const [expandedLog, setExpandedLog] = useState<string | null>(null);
  const [isTerminal, setIsTerminal] = useState(false);
  const feedEndRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const completeCalled = useRef(false);

  useEffect(() => {
    if (activeTab === "feed" && feedEndRef.current) {
      feedEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [vulnerabilities.length, activeTab]);

  const startPolling = useCallback(() => {
    if (pollIntervalRef.current) return; // Already polling

    const poll = async () => {
      try {
        const result = await getScanStatus(scanId);
        if ("error" in result) return;

        const newProgress: ScanProgress = {
          status: result.status,
          progress: result.progress,
          probesCompleted: result.probesCompleted,
          probesTotal: result.probesTotal,
          vulnerabilitiesFound: result.vulnerabilitiesFound,
        };
        setProgress(newProgress);
        onProgress?.(newProgress);

        if (
          result.status === "completed" ||
          result.status === "failed" ||
          result.status === "cancelled"
        ) {
          setIsTerminal(true);
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
          }
          if (!completeCalled.current) {
            completeCalled.current = true;
            onComplete?.();
          }
        }
      } catch {
      }
    };

    poll(); // Immediate first poll
    pollIntervalRef.current = setInterval(poll, 2000);
  }, [scanId, onComplete, onProgress]);

  const connectSSE = useCallback(() => {
    // Try SSE first
    const apiBase =
      typeof window !== "undefined"
        ? process.env.NEXT_PUBLIC_RUST_API_URL || ""
        : "";

    if (apiBase) {
      try {
        const es = new EventSource(`${apiBase}/v1/scan/${scanId}/events`, {
          withCredentials: true,
        });
        eventSourceRef.current = es;

        es.addEventListener("progress", (e) => {
          try {
            const data = JSON.parse(e.data);
            const newProgress: ScanProgress = {
              status: data.status,
              progress: data.progress,
              probesCompleted: data.probes_completed,
              probesTotal: data.probes_total,
              vulnerabilitiesFound: data.vulnerabilities_found,
            };
            setProgress(newProgress);
            onProgress?.(newProgress);
          } catch {
            // ignore parse errors
          }
        });

        es.addEventListener("vulnerability", (e) => {
          try {
            const data = JSON.parse(e.data);
            setVulnerabilities((prev) => {
              if (prev.some((v) => v.id === data.id)) return prev;
              return [
                ...prev,
                {
                  id: data.id,
                  probe_name: data.probe_name,
                  category: data.category,
                  severity: data.severity,
                  description: data.description,
                  success_rate: data.success_rate,
                  detector_name: data.detector_name,
                  timestamp: Date.now(),
                },
              ];
            });
          } catch {
            // ignore
          }
        });

        es.addEventListener("completed", () => {
          setIsTerminal(true);
          setProgress((prev) => ({
            ...prev,
            status: "completed",
            progress: 100,
          }));
          if (!completeCalled.current) {
            completeCalled.current = true;
            onComplete?.();
          }
          es.close();
        });

        es.addEventListener("failed", () => {
          setIsTerminal(true);
          setProgress((prev) => ({ ...prev, status: "failed" }));
          if (!completeCalled.current) {
            completeCalled.current = true;
            onComplete?.();
          }
          es.close();
        });

        es.addEventListener("cancelled", () => {
          setIsTerminal(true);
          setProgress((prev) => ({ ...prev, status: "cancelled" }));
          if (!completeCalled.current) {
            completeCalled.current = true;
            onComplete?.();
          }
          es.close();
        });

        es.onerror = () => {
          es.close();
          eventSourceRef.current = null;
          startPolling();
        };

        return;
      } catch {
      }
    }

    startPolling();
  }, [scanId, onComplete, onProgress, startPolling]);

  useEffect(() => {
    if (isTerminal) {
      // Final fetch of logs regardless of active tab
      getScanLogs(scanId).then((result) => {
        if (!("error" in result)) {
          setProbeLogs(result.logs);
        }
      });
      return;
    }

    if (activeTab !== "logs") return;

    const fetchLogs = async () => {
      try {
        const result = await getScanLogs(scanId);
        if (!("error" in result)) {
          setProbeLogs(result.logs);
        }
      } catch {
        // ignore
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [scanId, isTerminal, activeTab]);

  // Connect on mount
  useEffect(() => {
    connectSSE();

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    };
  }, [connectSSE]);


  const isActive =
    progress.status === "running" || progress.status === "queued";

  const severityCounts = vulnerabilities.reduce(
    (acc, v) => {
      const s = v.severity.toLowerCase();
      if (s === "critical") acc.critical++;
      else if (s === "high") acc.high++;
      else if (s === "medium") acc.medium++;
      else acc.low++;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );

  return (
    <div className="bg-stone-50 border border-stone-200 rounded-2xl overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-stone-200">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            {isActive ? (
              <IconRadar className="w-5 h-5 text-blue-400 animate-pulse" />
            ) : progress.status === "completed" ? (
              <IconShieldCheck className="w-5 h-5 text-lime-500" />
            ) : (
              <IconAlertTriangle className="w-5 h-5 text-red-400" />
            )}
            <h3 className="font-semibold">
              {isActive
                ? "Scan In Progress"
                : progress.status === "completed"
                  ? "Scan Complete"
                  : `Scan ${progress.status.charAt(0).toUpperCase() + progress.status.slice(1)}`}
            </h3>
          </div>
          <div className="flex items-center gap-3">
            {isActive && (
              <span className="text-xs text-blue-400 animate-pulse flex items-center gap-1">
                <IconActivity className="w-3.5 h-3.5" />
                LIVE
              </span>
            )}
            <span className="text-xs text-stone-500 font-mono">
              {scanId.slice(0, 8)}...
            </span>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="flex items-center gap-3">
          <div className="flex-1 h-2 bg-stone-100 rounded-full overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ease-out rounded-full ${
                progress.status === "completed"
                  ? "bg-lime-500"
                  : progress.status === "failed"
                    ? "bg-red-500"
                    : "bg-blue-500"
              }`}
              style={{
                width: `${Math.max(progress.progress, isActive ? 2 : 0)}%`,
              }}
            />
          </div>
          <span className="text-sm font-mono text-stone-400 min-w-[3rem] text-right">
            {progress.progress}%
          </span>
        </div>

        {/* Stats Row */}
        <div className="flex items-center gap-6 mt-3 text-xs text-stone-500">
          <div className="flex items-center gap-1.5">
            <IconRadar className="w-3.5 h-3.5" />
            <span>
              {progress.probesCompleted}/{progress.probesTotal} probes
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <IconBug className="w-3.5 h-3.5" />
            <span
              className={
                vulnerabilities.length > 0
                  ? "text-orange-400 font-semibold"
                  : ""
              }
            >
              {vulnerabilities.length || progress.vulnerabilitiesFound} vulns
              found
            </span>
          </div>
          {severityCounts.critical > 0 && (
            <span className="text-red-400 font-semibold">
              {severityCounts.critical} critical
            </span>
          )}
          {severityCounts.high > 0 && (
            <span className="text-orange-400 font-semibold">
              {severityCounts.high} high
            </span>
          )}
          {probeLogs.length > 0 && (
            <div className="flex items-center gap-1.5">
              <IconSend className="w-3.5 h-3.5" />
              <span>
                {probeLogs.reduce((sum, l) => sum + l.promptsSent, 0)} prompts
                sent
              </span>
            </div>
          )}
          {probeLogs.length > 0 && (
            <div className="flex items-center gap-1.5">
              <IconClock className="w-3.5 h-3.5" />
              <span>
                {formatDuration(
                  probeLogs.reduce((sum, l) => sum + (l.durationMs || 0), 0),
                )}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-stone-200">
        <button
          onClick={() => setActiveTab("feed")}
          className={`px-4 py-2 text-xs font-mono uppercase tracking-wider transition-colors ${
            activeTab === "feed"
              ? "text-white border-b-2 border-blue-500 bg-stone-100"
              : "text-stone-500 hover:text-stone-700"
          }`}
        >
          <div className="flex items-center gap-1.5">
            <IconBug className="w-3.5 h-3.5" />
            Vulnerability Feed
            {vulnerabilities.length > 0 && (
              <span className="ml-1 px-1.5 py-0.5 text-[10px] rounded bg-orange-500/20 text-orange-400">
                {vulnerabilities.length}
              </span>
            )}
          </div>
        </button>
        <button
          onClick={() => setActiveTab("timeline")}
          className={`px-4 py-2 text-xs font-mono uppercase tracking-wider transition-colors ${
            activeTab === "timeline"
              ? "text-white border-b-2 border-blue-500 bg-stone-100"
              : "text-stone-500 hover:text-stone-700"
          }`}
        >
          <div className="flex items-center gap-1.5">
            <IconActivity className="w-3.5 h-3.5" />
            Probe Timeline
            {probeLogs.length > 0 && (
              <span className="ml-1 px-1.5 py-0.5 text-[10px] rounded bg-stone-200 text-stone-700">
                {probeLogs.length}
              </span>
            )}
          </div>
        </button>
        <button
          onClick={() => setActiveTab("logs")}
          className={`px-4 py-2 text-xs font-mono uppercase tracking-wider transition-colors ${
            activeTab === "logs"
              ? "text-white border-b-2 border-blue-500 bg-stone-100"
              : "text-stone-500 hover:text-stone-700"
          }`}
        >
          <div className="flex items-center gap-1.5">
            <IconTerminal2 className="w-3.5 h-3.5" />
            Verbose Logs
          </div>
        </button>
      </div>

      {/* Tab Content */}
      <div className="max-h-[400px] overflow-auto">
        {/* ── Vulnerability Feed ── */}
        {activeTab === "feed" && (
          <div className="divide-y divide-stone-200/50">
            {vulnerabilities.length === 0 ? (
              <div className="p-8 text-center text-stone-500">
                {isActive ? (
                  <>
                    <IconRadar className="w-10 h-10 mx-auto mb-3 animate-pulse opacity-50" />
                    <p className="text-sm">Waiting for vulnerabilities...</p>
                    <p className="text-xs mt-1 text-stone-600">
                      Vulnerabilities will appear here in real-time as probes
                      execute
                    </p>
                  </>
                ) : (
                  <>
                    <IconShieldCheck className="w-10 h-10 mx-auto mb-3 text-lime-500 opacity-50" />
                    <p className="text-sm">No vulnerabilities found!</p>
                    <p className="text-xs mt-1 text-stone-600">
                      Your model passed all security probes
                    </p>
                  </>
                )}
              </div>
            ) : (
              <>
                {vulnerabilities.map((vuln, index) => (
                  <div
                    key={vuln.id || index}
                    className="p-3 hover:bg-stone-100 transition-colors animate-in fade-in slide-in-from-bottom-2 duration-300"
                    style={{ animationDelay: `${index * 50}ms` }}
                  >
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5">
                        {getSeverityIcon(vuln.severity)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span
                            className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border ${getSeverityColor(vuln.severity)}`}
                          >
                            {vuln.severity}
                          </span>
                          <span className="text-sm font-medium truncate">
                            {vuln.probe_name}
                          </span>
                          <span className="text-xs text-stone-600">
                            {vuln.category}
                          </span>
                        </div>
                        <p className="text-xs text-stone-400 line-clamp-2">
                          {vuln.description}
                        </p>
                        <div className="flex items-center gap-3 mt-1 text-[10px] text-stone-600">
                          {vuln.success_rate != null && (
                            <span>
                              Score: {(vuln.success_rate * 100).toFixed(0)}%
                            </span>
                          )}
                          {vuln.detector_name && (
                            <span>Detector: {vuln.detector_name}</span>
                          )}
                          <span>
                            {new Date(vuln.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
                <div ref={feedEndRef} />
              </>
            )}
          </div>
        )}

        {/* ── Probe Timeline ── */}
        {activeTab === "timeline" && (
          <div className="divide-y divide-stone-200/50">
            {probeLogs.length === 0 ? (
              <div className="p-8 text-center text-stone-500">
                {isActive ? (
                  <>
                    <IconLoader2 className="w-10 h-10 mx-auto mb-3 animate-spin opacity-50" />
                    <p className="text-sm">Waiting for probe results...</p>
                  </>
                ) : (
                  <p className="text-sm">No probe execution data available</p>
                )}
              </div>
            ) : (
              probeLogs.map((log) => (
                <div
                  key={log.id}
                  className="p-3 hover:bg-stone-100 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div>{getProbeStatusIcon(log.status)}</div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">
                          {log.probeName}
                        </span>
                        <span
                          className={`text-[10px] font-mono uppercase ${getProbeStatusColor(log.status)}`}
                        >
                          {log.status}
                        </span>
                        {log.probeClass && (
                          <span className="text-[10px] text-stone-600 truncate max-w-[200px]">
                            {log.probeClass.split(".").slice(-1)[0]}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-[10px] text-stone-500">
                        <span className="flex items-center gap-1">
                          <IconSend className="w-3 h-3" />
                          {log.promptsSent} sent
                        </span>
                        <span className="flex items-center gap-1 text-lime-500/80">
                          <IconCheck className="w-3 h-3" />
                          {log.promptsPassed} passed
                        </span>
                        {log.promptsFailed > 0 && (
                          <span className="flex items-center gap-1 text-red-400/80">
                            <IconX className="w-3 h-3" />
                            {log.promptsFailed} failed
                          </span>
                        )}
                        <span className="flex items-center gap-1">
                          <IconClock className="w-3 h-3" />
                          {formatDuration(log.durationMs)}
                        </span>
                        {log.detectorName && (
                          <span className="text-stone-600">
                            det: {log.detectorName}
                          </span>
                        )}
                      </div>
                    </div>
                    {/* Probe mini progress bar */}
                    <div className="flex flex-col items-end gap-1 min-w-[60px]">
                      {log.promptsSent > 0 && (
                        <div className="w-full h-1.5 bg-stone-100 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              log.promptsFailed > 0
                                ? "bg-red-500"
                                : "bg-lime-500"
                            }`}
                            style={{
                              width: `${
                                log.promptsSent > 0
                                  ? ((log.promptsPassed + log.promptsFailed) /
                                      log.promptsSent) *
                                    100
                                  : 0
                              }%`,
                            }}
                          />
                        </div>
                      )}
                    </div>
                  </div>
                  {log.errorMessage && (
                    <div className="mt-2 ml-7 text-[10px] text-red-400/80 bg-red-500/5 rounded px-2 py-1 font-mono">
                      {log.errorMessage}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {/* ── Verbose Logs ── */}
        {activeTab === "logs" && (
          <div className="divide-y divide-stone-200/50">
            {probeLogs.length === 0 ? (
              <div className="p-8 text-center text-stone-500">
                <IconTerminal2 className="w-10 h-10 mx-auto mb-3 opacity-50" />
                <p className="text-sm">No verbose logs available yet</p>
              </div>
            ) : (
              probeLogs.map((log) => (
                <div key={log.id}>
                  <button
                    onClick={() =>
                      setExpandedLog(expandedLog === log.id ? null : log.id)
                    }
                    className="w-full p-3 hover:bg-stone-100 transition-colors text-left"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {getProbeStatusIcon(log.status)}
                        <span className="text-sm font-medium">
                          {log.probeName}
                        </span>
                        <span className="text-[10px] text-stone-500">
                          {log.logLines.length} log entries
                        </span>
                      </div>
                      {expandedLog === log.id ? (
                        <IconChevronUp className="w-4 h-4 text-stone-500" />
                      ) : (
                        <IconChevronDown className="w-4 h-4 text-stone-500" />
                      )}
                    </div>
                  </button>
                  {expandedLog === log.id && (
                    <div className="bg-stone-50 border-t border-stone-200 px-4 py-3">
                      <div className="font-mono text-[11px] leading-5 space-y-0.5 max-h-[250px] overflow-auto">
                        {log.logLines.length > 0 ? (
                          log.logLines.map((line, i) => {
                            const isError =
                              line.toLowerCase().includes("error") ||
                              line.toLowerCase().includes("fatal");
                            const isWarning =
                              line.toLowerCase().includes("warning") ||
                              line.toLowerCase().includes("warn");
                            const isFailed =
                              line.toLowerCase().includes("failed") ||
                              line.toLowerCase().includes("vulns=");

                            let textColor = "text-stone-400";
                            if (isError) textColor = "text-red-400";
                            else if (isWarning) textColor = "text-orange-400";
                            else if (isFailed) textColor = "text-yellow-400";

                            return (
                              <div key={i} className={textColor}>
                                <span className="text-stone-600 select-none mr-2">
                                  {String(i + 1).padStart(2, "0")}
                                </span>
                                {line}
                              </div>
                            );
                          })
                        ) : (
                          <div className="text-stone-600 italic">
                            No verbose log lines for this probe
                          </div>
                        )}
                      </div>
                      {log.errorMessage && (
                        <div className="mt-2 text-[11px] text-red-400 bg-red-500/5 rounded px-2 py-1">
                          Error: {log.errorMessage}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}
