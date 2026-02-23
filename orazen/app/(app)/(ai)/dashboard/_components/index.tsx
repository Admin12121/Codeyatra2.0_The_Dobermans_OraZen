"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { getGuardStats } from "@/lib/actions/guard";
import { useGuardEvents } from "@/hooks/use-guard-events";
import { IconCircleFilled } from "@tabler/icons-react";

const PERIOD_MAP: Record<string, string> = {
  today: "today",
  "24hours": "24h",
  "48hours": "48h",
  "3days": "3d",
  "7days": "7d",
};

interface Stats {
  totalScans: number;
  threatsBlocked: number;
  safePrompts: number;
  avgLatency: number;
}

const Analytics = () => {
  const [period, setPeriod] = useState("7days");
  const [stats, setStats] = useState<Stats>({
    totalScans: 0,
    threatsBlocked: 0,
    safePrompts: 0,
    avgLatency: 0,
  });
  const [isLoading, setIsLoading] = useState(true);

  const { connected: sseConnected, stats: realtimeStats } = useGuardEvents({
    enabled: true,
    onStatsUpdate: (s) => {
      if (period === "7days") {
        setStats({
          totalScans: s.total_scans,
          threatsBlocked: s.threats_blocked,
          safePrompts: s.safe_prompts,
          avgLatency: s.avg_latency,
        });
      }
    },
  });

  useEffect(() => {
    if (realtimeStats && period === "7days") {
      setStats({
        totalScans: realtimeStats.total_scans,
        threatsBlocked: realtimeStats.threats_blocked,
        safePrompts: realtimeStats.safe_prompts,
        avgLatency: realtimeStats.avg_latency,
      });
    }
  }, [realtimeStats, period]);

  const fetchStats = useCallback(async (selectedPeriod: string) => {
    setIsLoading(true);
    try {
      const apiPeriod = PERIOD_MAP[selectedPeriod] || "7d";
      const data = await getGuardStats(apiPeriod);
      setStats(data);
    } catch (err) {
      console.error("Failed to fetch guard stats:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats(period);
  }, [period, fetchStats]);

  const handlePeriodChange = (value: string) => {
    setPeriod(value);
  };

  const threatPercent =
    stats.totalScans > 0
      ? Math.round((stats.threatsBlocked / stats.totalScans) * 100)
      : 0;

  const safePercent =
    stats.totalScans > 0
      ? Math.round((stats.safePrompts / stats.totalScans) * 100)
      : 0;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex gap-4 items-center">
        <div className="flex gap-2 items-center">
          <span className="text-stone-500">
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M21 21H10C6.70017 21 5.05025 21 4.02513 19.9749C3 18.9497 3 17.2998 3 14V3"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                vectorEffect="non-scaling-stroke"
              ></path>
              <path
                d="M5 20C5.43938 16.8438 7.67642 8.7643 10.4282 8.7643C12.3301 8.7643 12.8226 12.6353 14.6864 12.6353C17.8931 12.6353 17.4282 4 21 4"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                vectorEffect="non-scaling-stroke"
              ></path>
            </svg>
          </span>
          <span className="text-stone-500 font-semibold text-xs uppercase font-mono tracking-[0.48px]">
            Security Analytics
          </span>
        </div>
        <span className="flex-1 h-px bg-stone-200"></span>
      </div>
      <div
        className={`flex bg-stone-50 flex-col border border-stone-200 rounded-2xl transition-opacity ${isLoading ? "opacity-60" : "opacity-100"}`}
      >
        <div className="flex justify-between py-4 px-6 items-center">
          <div className="flex items-center gap-3 flex-1">
            <p className="text-stone-800 font-normal text-sm leading-5">
              Monitor your LLM security scans and threat detection activity.
            </p>
            {/* Real-time connection indicator */}
            <div
              className="flex items-center gap-1 px-2 py-0.5 rounded-md border border-stone-200"
              title={
                sseConnected
                  ? "Real-time updates active"
                  : "Real-time updates disconnected"
              }
            >
              <IconCircleFilled
                className={`w-1.5 h-1.5 ${sseConnected ? "text-lime-500" : "text-stone-600"}`}
              />
              <span className="text-[10px] font-mono uppercase text-stone-500">
                {sseConnected ? "Live" : "Offline"}
              </span>
            </div>
          </div>
          <Select value={period} onValueChange={handlePeriodChange}>
            <SelectTrigger className="w-fit h-6 border-transparent hover:bg-stone-100 font-semibold font-mono uppercase text-xs gap-1 px-3">
              <SelectValue />
            </SelectTrigger>
            <SelectContent position={"popper"} className="p-1">
              <SelectItem value="today">Today</SelectItem>
              <SelectItem value="24hours">Last 24 Hours</SelectItem>
              <SelectItem value="48hours">Last 48 Hours</SelectItem>
              <SelectItem value="3days">Last 3 Days</SelectItem>
              <SelectItem value="7days">Last 7 Days</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="border-y border-stone-200 overflow-hidden shrink-0">
          <div className="grid grid-cols-4">
            <div className="border-stone-200 [&:nth-child(-n+4)]:border-b [&:not(:nth-child(4n))]:border-r ">
              <div className="p-4 flex gap-4 items-center flex-1 justify-between h-full relative  ">
                <div className="flex flex-col gap-1 w-full">
                  <div className="flex  gap-0 justify-between items-center w-full">
                    <span className="flex items-center gap-2">
                      <svg
                        width="12"
                        height="12"
                        viewBox="0 0 12 12"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                        className="fill-stone-500 stroke-stone-800"
                      >
                        <g clipPath="url(#«r3u»)">
                          <path
                            d="M6 11C8.76142 11 11 8.76142 11 6C11 3.23858 8.76142 1 6 1C3.23858 1 1 3.23858 1 6C1 8.76142 3.23858 11 6 11Z"
                            strokeWidth="1.5"
                            strokeLinejoin="round"
                            vectorEffect="non-scaling-stroke"
                          ></path>
                        </g>
                        <defs>
                          <clipPath id="«r3u»">
                            <rect width="12" height="12" fill="white"></rect>
                          </clipPath>
                        </defs>
                      </svg>
                      <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase leading-4">
                        TOTAL SCANS
                      </span>
                    </span>
                  </div>
                  <div className="flex gap-2 items-baseline">
                    <p className="text-stone-800 font-semibold text-sm leading-5 align-baseline">
                      {stats.totalScans.toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>
            </div>
            <div className="border-stone-200 [&:nth-child(-n+4)]:border-b [&:not(:nth-child(4n))]:border-r ">
              <div className="p-4 flex gap-4 items-center flex-1 justify-between h-full relative  ">
                <div className="flex flex-col gap-1 w-full">
                  <div className="flex  gap-0 justify-between items-center w-full">
                    <span className="flex items-center gap-2">
                      <svg
                        width="12"
                        height="12"
                        viewBox="0 0 12 12"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                        className="fill-stone-300 stroke-stone-500"
                      >
                        <g clipPath="url(#«r40»)">
                          <path
                            d="M2.96045 2.953C4.07918 1.83426 4.63855 1.27489 5.29285 1.09036C5.75525 0.95995 6.24475 0.95995 6.70715 1.09036C7.36145 1.27489 7.9208 1.83426 9.03955 2.953C10.1583 4.07173 10.7177 4.63111 10.9022 5.28541C11.0326 5.74781 11.0326 6.23731 10.9022 6.69971C10.7177 7.35401 10.1583 7.91335 9.03955 9.0321C7.9208 10.1509 7.36145 10.7102 6.70715 10.8948C6.24475 11.0252 5.75525 11.0252 5.29285 10.8948C4.63855 10.7102 4.07918 10.1509 2.96045 9.0321C1.84171 7.91335 1.28234 7.35401 1.09781 6.69971C0.967396 6.23731 0.967396 5.74781 1.09781 5.28541C1.28234 4.63111 1.84171 4.07173 2.96045 2.953Z"
                            strokeWidth="1.5"
                            strokeLinejoin="round"
                            vectorEffect="non-scaling-stroke"
                          ></path>
                        </g>
                        <defs>
                          <clipPath id="«r40»">
                            <rect width="12" height="12" fill="white"></rect>
                          </clipPath>
                        </defs>
                      </svg>
                      <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase leading-4">
                        THREATS DETECTED
                      </span>
                    </span>
                  </div>
                  <div className="flex gap-2 items-baseline">
                    <p className="text-stone-800 font-semibold text-sm leading-5 align-baseline">
                      {stats.threatsBlocked.toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>
            </div>
            <div className="border-stone-200 [&:nth-child(-n+4)]:border-b [&:not(:nth-child(4n))]:border-r ">
              <div className="p-4 flex gap-4 items-center flex-1 justify-between h-full relative  ">
                <div className="flex flex-col gap-1 w-full">
                  <div className="flex  gap-0 justify-between items-center w-full">
                    <span className="flex items-center gap-2">
                      <svg
                        width="12"
                        height="12"
                        viewBox="0 0 12 12"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                        className="fill-brand-400 stroke-brand-600"
                      >
                        <g clipPath="url(#«r42»)">
                          <path
                            d="M5.961 2.38757C8.34815 1.57378 9.5417 1.16688 10.1837 1.80886C10.8256 2.45083 10.4187 3.64441 9.605 6.03156L9.0508 7.65716C8.42585 9.49046 8.11335 10.4071 7.5982 10.483C7.45975 10.5034 7.3164 10.4911 7.17935 10.4471C6.66975 10.2835 6.40035 9.31701 5.86155 7.38406C5.74205 6.95531 5.6823 6.74091 5.5462 6.57716C5.5067 6.52965 5.4629 6.48586 5.4154 6.44636C5.25165 6.31026 5.03725 6.25051 4.60852 6.13101C2.67555 5.59221 1.70907 5.3228 1.54545 4.81319C1.50146 4.67617 1.48918 4.53282 1.50958 4.39433C1.58544 3.87921 2.50209 3.56672 4.3354 2.94174L5.961 2.38757Z"
                            strokeWidth="1.5"
                            vectorEffect="non-scaling-stroke"
                          ></path>
                        </g>
                        <defs>
                          <clipPath id="«r42»">
                            <rect width="12" height="12" fill="white"></rect>
                          </clipPath>
                        </defs>
                      </svg>
                      <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase leading-4">
                        SAFE PROMPTS
                      </span>
                    </span>
                  </div>
                  <div className="flex gap-2 items-baseline">
                    <p className="text-stone-800 font-semibold text-sm leading-5 align-baseline">
                      {stats.safePrompts.toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>
            </div>
            <div className="border-stone-200 [&:nth-child(-n+4)]:border-b [&:not(:nth-child(4n))]:border-r ">
              <div className="p-4 flex gap-4 items-center flex-1 justify-between h-full relative  ">
                <div className="flex flex-col gap-1 w-full">
                  <div className="flex  gap-0 justify-between items-center w-full">
                    <span className="flex items-center gap-2">
                      <svg
                        width="12"
                        height="12"
                        viewBox="0 0 12 12"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                        className="fill-lime-400 stroke-lime-600"
                      >
                        <g clipPath="url(#«r44»)">
                          <path
                            d="M6 11C8.76142 11 11 8.76142 11 6C11 3.23858 8.76142 1 6 1C3.23858 1 1 3.23858 1 6C1 8.76142 3.23858 11 6 11Z"
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            vectorEffect="non-scaling-stroke"
                          ></path>
                        </g>
                        <defs>
                          <clipPath id="«r44»">
                            <rect width="12" height="12" fill="white"></rect>
                          </clipPath>
                        </defs>
                      </svg>
                      <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase leading-4">
                        THREATS BLOCKED
                      </span>
                    </span>
                  </div>
                  <div className="flex gap-2 items-baseline">
                    <p className="text-stone-800 font-semibold text-sm leading-5 align-baseline">
                      {threatPercent}%
                    </p>
                    <p className="text-stone-500 dark:text-stone-600 font-normal text-xs font-mono leading-4 align-baseline">
                      {stats.threatsBlocked.toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>
            </div>
            <div className="border-stone-200 [&:nth-child(-n+4)]:border-b [&:not(:nth-child(4n))]:border-r ">
              <div className="p-4 flex gap-4 items-center flex-1 justify-between h-full relative  ">
                <div className="flex flex-col gap-1 w-full">
                  <div className="flex  gap-0 justify-between items-center w-full">
                    <span className="flex items-center gap-2">
                      <svg
                        width="12"
                        height="12"
                        viewBox="0 0 12 12"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                        className="fill-purple-400 stroke-purple-600"
                      >
                        <path
                          d="M2.55386 7.1854L2.79297 3.94883C2.80937 3.72682 2.82321 3.51849 2.83616 3.32348C2.92508 1.98445 2.9724 1.27193 3.52403 1.04745C4.07566 0.822965 4.6011 1.3024 5.58855 2.20339C5.73235 2.33462 5.886 2.47478 6.0509 2.62302L8.4551 4.78392C9.1313 5.3917 9.46945 5.69565 9.4967 5.9868C9.51545 6.18665 9.45335 6.38565 9.32445 6.53875C9.13665 6.7618 8.6867 6.81621 7.78685 6.9249C7.4078 6.97071 7.21825 6.9936 7.10365 7.09445C7.02395 7.16455 6.9688 7.25861 6.94625 7.36275C6.91385 7.5125 6.98535 7.69075 7.12835 8.04731L7.8697 9.89545C7.95535 10.109 7.99815 10.2158 7.9975 10.314C7.9966 10.4465 7.94325 10.573 7.8493 10.6657C7.77955 10.7344 7.67355 10.7776 7.4616 10.8638C7.24965 10.9501 7.14365 10.9932 7.04605 10.9926C6.9146 10.9917 6.7889 10.9379 6.69695 10.8433C6.6287 10.7731 6.58585 10.6663 6.5002 10.4528L5.75885 8.6046C5.61585 8.2481 5.54435 8.0698 5.41775 7.98475C5.32975 7.92565 5.22515 7.8966 5.1195 7.9019C4.9675 7.90955 4.81537 8.0257 4.51112 8.25795C3.78881 8.8094 3.42766 9.0851 3.13873 9.056C2.94042 9.0361 2.7585 8.9364 2.63415 8.77955C2.45297 8.551 2.4866 8.0958 2.55386 7.1854Z"
                          strokeWidth="1.5"
                          strokeLinejoin="round"
                          vectorEffect="non-scaling-stroke"
                        ></path>
                      </svg>
                      <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase leading-4">
                        SAFE RATE
                      </span>
                    </span>
                  </div>
                  <div className="flex gap-2 items-baseline">
                    <p className="text-stone-800 font-semibold text-sm leading-5 align-baseline">
                      {safePercent}%
                    </p>
                    <p className="text-stone-500 dark:text-stone-600 font-normal text-xs font-mono leading-4 align-baseline">
                      {stats.safePrompts.toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>
            </div>
            <div className="border-stone-200 [&:nth-child(-n+4)]:border-b [&:not(:nth-child(4n))]:border-r ">
              <div className="p-4 flex gap-4 items-center flex-1 justify-between h-full relative  ">
                <div className="flex flex-col gap-1 w-full">
                  <div className="flex  gap-0 justify-between items-center w-full">
                    <span className="flex items-center gap-2">
                      <svg
                        width="12"
                        height="12"
                        viewBox="0 0 12 12"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                        className="fill-orange-400 stroke-orange-600"
                      >
                        <g clipPath="url(#«r47»)">
                          <path
                            d="M6.9624 10.5H5.0376C2.72238 10.5 1.56478 10.5 1.13818 9.74695C0.711587 8.99395 1.30368 7.9957 2.48787 5.99925L3.45029 4.37667C4.5878 2.45889 5.15655 1.5 6 1.5C6.84345 1.5 7.4122 2.45888 8.5497 4.37666L9.51215 5.99925C10.6963 7.9957 11.2884 8.99395 10.8618 9.74695C10.4352 10.5 9.2776 10.5 6.9624 10.5Z"
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            vectorEffect="non-scaling-stroke"
                          ></path>
                        </g>
                        <defs>
                          <clipPath id="«r47»">
                            <rect width="12" height="12" fill="white"></rect>
                          </clipPath>
                        </defs>
                      </svg>
                      <span className="text-stone-800 font-semibold text-xs tracking-[0.48px] font-mono uppercase leading-4">
                        AVG LATENCY
                      </span>
                    </span>
                  </div>
                  <div className="flex gap-2 items-baseline">
                    <p className="text-stone-800 font-semibold text-sm leading-5 align-baseline">
                      {stats.avgLatency}ms
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="flex py-4 px-6 items-center justify-center">
          <a
            type="button"
            className=" cursor-pointer box-border  flex items-center justify-center font-semibold font-mono uppercase border transition-all ease-in duration-75 whitespace-nowrap text-center select-none disabled:shadow-none disabled:opacity-50 disabled:cursor-not-allowed gap-x-1 active:shadow-none active:scale-95 text-xs leading-4 rounded-lg px-3 py-1 h-6 bg-stone-0 border-stone-200 hover:bg-stone-100 hover:border-stone-300 disabled:bg-stone-100 disabled:border-stone-200"
            translate="no"
            href="/logs"
          >
            View Activity Logs
            <span className="-mr-1">
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M9.00005 6C9.00005 6 15 10.4189 15 12C15 13.5812 9 18 9 18"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                ></path>
              </svg>
            </span>
          </a>
        </div>
      </div>
    </div>
  );
};

export default Analytics;
