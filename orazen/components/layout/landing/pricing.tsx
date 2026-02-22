"use client";

import React, { useState, useCallback, useRef, useEffect } from "react";
import { useEsewaPayment } from "@/hooks/use-esewa-payment";
import { useRouter } from "next/navigation";
import { useSession } from "@/lib/auth-client";

export interface TierPricing {
  price: number;
  tier: string;
  note?: string;
}

export interface VolumeTier {
  label: string;
  value: number;
  guardOnly: TierPricing;
  full: TierPricing;
}

export const CURRENCY = "रू";

export const tiers: VolumeTier[] = [
  {
    label: "5K",
    value: 5_000,
    guardOnly: { price: 0, tier: "Free", note: "15-day trial · Guard only" },
    full: { price: 1900, tier: "Starter", note: "Garak requires paid plan" },
  },
  {
    label: "10K",
    value: 10_000,
    guardOnly: { price: 1500, tier: "Starter" },
    full: { price: 2900, tier: "Starter" },
  },
  {
    label: "25K",
    value: 25_000,
    guardOnly: { price: 2900, tier: "Starter" },
    full: { price: 4500, tier: "Starter" },
  },
  {
    label: "50K",
    value: 50_000,
    guardOnly: { price: 4500, tier: "Starter" },
    full: { price: 6900, tier: "Pro" },
  },
  {
    label: "100K",
    value: 100_000,
    guardOnly: { price: 6900, tier: "Pro" },
    full: { price: 9900, tier: "Pro" },
  },
  {
    label: "250K",
    value: 250_000,
    guardOnly: { price: 12900, tier: "Pro" },
    full: { price: 18900, tier: "Pro" },
  },
  {
    label: "500K",
    value: 500_000,
    guardOnly: { price: 19900, tier: "Pro" },
    full: { price: 29900, tier: "Pro" },
  },
  {
    label: "1M",
    value: 1_000_000,
    guardOnly: { price: 34900, tier: "Pro" },
    full: { price: 49900, tier: "Pro" },
  },
  {
    label: "1M+",
    value: -1,
    guardOnly: { price: -1, tier: "Enterprise" },
    full: { price: -1, tier: "Enterprise" },
  },
];

export interface Feature {
  label: string;
  included: boolean;
}

export const guardOnlyFeatures: Feature[] = [
  { label: "Real-time prompt scanning", included: true },
  { label: "Toxicity & bias detection", included: true },
  { label: "PII filtering & anonymization", included: true },
  { label: "Prompt injection detection", included: true },
  { label: "Gibberish & noise filtering", included: true },
  { label: "Garak vulnerability scans", included: false },
  { label: "Custom Garak probes", included: false },
];

export const fullFeatures: Feature[] = [
  { label: "Garak vulnerability scans", included: true },
  { label: "Jailbreak & injection testing", included: true },
  { label: "Hallucination probes", included: true },
  { label: "Detailed security reports", included: true },
  { label: "Advanced scanner configuration", included: true },
  { label: "Priority GPU queue", included: true },
  { label: "Custom Garak probes", included: false },
];

export const sharedFeatures: string[] = [
  "API key management",
  "Dashboard & analytics",
  "Threat detection logs",
  "रू 0.15 / additional scan",
];

function CheckIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 18 18"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="shrink-0"
    >
      <rect
        width="18"
        height="18"
        rx="9"
        className="fill-blue-500/15 dark:fill-blue-400/25"
      />
      <path
        d="M5.5 9.5L7.5 11.5L12.5 6.5"
        className="stroke-blue-500 dark:stroke-blue-400"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function XIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 18 18"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="shrink-0"
    >
      <rect
        width="18"
        height="18"
        rx="9"
        className="fill-stone-400/15 dark:fill-zinc-500/25"
      />
      <path
        d="M6.5 6.5L11.5 11.5M11.5 6.5L6.5 11.5"
        className="stroke-stone-400 dark:stroke-zinc-500"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function ArrowIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="shrink-0 transition-transform group-hover:translate-x-0.5"
    >
      <path
        d="M3 8H13M13 8L9 4M13 8L9 12"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function EsewaLogo() {
  return (
    <span className="flex items-center gap-1.5 text-white font-bold text-xs tracking-normal normal-case">
      <svg
        width="20"
        height="20"
        viewBox="16 16 160 160"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="shrink-0"
      >
        <path
          fill="#5CBF41"
          d="M96 36a60 60 0 00-60 60 60 60 0 0060 60 60 60 0 0059.57-54H133V90h22.697A60 60 0 0096 36z"
        />
        <path
          fill="#ffffff"
          d="M94.99 60c-11.395.028-20.651 4.787-26.39 13.332a46.5 46.5 0 00-3.704 7.32c-2.62 9.187-2.461 17.944.083 26.44 1.009 3.335 2.82 7.405 4.328 9.727 8.421 12.298 20.987 16.487 34.375 12.998 8.24-2.285 14.173-7.415 18.158-15.7 2.349-4.882 2.664-7.004 1.129-7.593-1.957-.75-2.634-.362-3.781 2.183-1.62 3.592-6.35 8.146-10.5 10.108-6.802 2.532-14.865 2.503-20.008-.574-2.04-1.227-4.647-3.319-5.793-4.649-4.514-5.237-7.695-13.41-8.096-20.81l-.187-3.48 10.83-1.739c5.957-.956 14.7-2.342 19.43-3.08 13.652-2.129 14.071-2.383 12.334-7.5-1.353-3.984-3.921-7.914-7.002-10.977C105.832 61.307 99.815 60.001 94.99 60zm-3.896 5.076c1.534-.03 3.06.215 4.513.766 3.8 1.44 7.13 6.226 7.389 10.617.189 3.195-.68 3.53-14.352 5.547-6.217.917-11.707 1.823-12.199 2.012-.493.189-1.044.105-1.225-.188-.545-.881.689-6.26 2.147-9.361 2.672-5.685 8.248-9.288 13.727-9.393z"
        />
      </svg>
      eSewa
    </span>
  );
}

function SpinnerIcon() {
  return (
    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}

function AnimatedPrice({ value }: { value: number }) {
  const [display, setDisplay] = useState(value);
  const rafRef = useRef<number>(0);
  const startRef = useRef(display);
  const targetRef = useRef(value);
  const startTimeRef = useRef(0);

  useEffect(() => {
    if (targetRef.current === value) return;
    startRef.current = display;
    targetRef.current = value;
    startTimeRef.current = 0;

    cancelAnimationFrame(rafRef.current);

    function animate(ts: number) {
      const elapsed =
        ts - (startTimeRef.current || (startTimeRef.current = ts));
      const duration = 400;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(
        startRef.current + (targetRef.current - startRef.current) * eased,
      );

      setDisplay(current);
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(animate);
      }
    }

    rafRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(rafRef.current);
  }, [value]);

  return (
    <>
      {CURRENCY} {display.toLocaleString("en-IN")}
    </>
  );
}

function VolumeSlider({
  selectedIndex,
  onChange,
}: {
  selectedIndex: number;
  onChange: (index: number) => void;
}) {
  const trackRef = useRef<HTMLDivElement>(null);
  const isDragging = useRef(false);
  const max = tiers.length - 1;

  const pct = (selectedIndex / max) * 100;

  const getIndexFromPosition = useCallback(
    (clientX: number) => {
      if (!trackRef.current) return selectedIndex;

      const rect = trackRef.current.getBoundingClientRect();
      const x = clientX - rect.left;
      const ratio = Math.max(0, Math.min(1, x / rect.width));
      return Math.round(ratio * max);
    },
    [max, selectedIndex],
  );

  const handlePointerDown = useCallback(
    (e: React.PointerEvent) => {
      isDragging.current = true;
      (e.target as HTMLElement).setPointerCapture(e.pointerId);
      const idx = getIndexFromPosition(e.clientX);
      if (idx !== selectedIndex) onChange(idx);
    },
    [getIndexFromPosition, onChange, selectedIndex],
  );

  const handlePointerMove = useCallback(
    (e: React.PointerEvent) => {
      if (!isDragging.current) return;
      const idx = getIndexFromPosition(e.clientX);
      if (idx !== selectedIndex) onChange(idx);
    },
    [getIndexFromPosition, onChange, selectedIndex],
  );

  const handlePointerUp = useCallback(() => {
    isDragging.current = false;
  }, []);

  return (
    <div className="flex flex-col gap-6 w-full">
      {/* Labels */}
      <div className="relative w-full h-5">
        {tiers.map((t, i) => {
          const left = `${(i / max) * 100}%`;
          const isActive = i === selectedIndex;
          return (
            <button
              key={t.label}
              onClick={() => onChange(i)}
              className="absolute cursor-pointer bg-transparent border-none p-0 -translate-x-1/2"
              style={{ left }}
            >
              <span
                className={`text-xs font-mono transition-all select-none whitespace-nowrap ${
                  isActive
                    ? "text-stone-900 dark:text-white font-bold"
                    : "text-stone-400 dark:text-zinc-400 font-normal"
                }`}
              >
                {t.label}
              </span>
            </button>
          );
        })}
      </div>

      <div
        ref={trackRef}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerCancel={handlePointerUp}
        className="relative h-2 cursor-pointer"
        role="slider"
        aria-valuemin={0}
        aria-valuemax={max}
        aria-valuenow={selectedIndex}
        aria-label="Volume tier selector"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight" && selectedIndex < max)
            onChange(selectedIndex + 1);
          if (e.key === "ArrowLeft" && selectedIndex > 0)
            onChange(selectedIndex - 1);
        }}
      >
        <div className="absolute inset-0 rounded-full bg-stone-200 dark:bg-zinc-600" />

        <div
          className="absolute inset-y-0 left-0 rounded-full bg-stone-600 dark:bg-zinc-300 transition-[width] duration-200"
          style={{ left: 0, width: `${pct}%` }}
        />

        <div
          className="absolute top-1/2 h-5 w-5 rounded-full bg-stone-700 dark:bg-white border-2 border-white dark:border-zinc-800 shadow-md transition-[left] duration-200 z-10"
          style={{
            left: `${pct}%`,
            touchAction: "none",
            transform: "translate(-50%, -50%)",
          }}
        />
      </div>
    </div>
  );
}

function MobileVolumeSelect({
  selectedIndex,
  onChange,
}: {
  selectedIndex: number;
  onChange: (index: number) => void;
}) {
  return (
    <div className="flex flex-col gap-2">
      <label className="text-stone-800 dark:text-zinc-100 font-medium text-sm">
        Monthly guard scans
      </label>
      <select
        value={selectedIndex}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full rounded-md border border-stone-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-stone-800 dark:text-zinc-100 font-mono focus:outline-none focus:ring-2 focus:ring-stone-400 dark:focus:ring-zinc-500"
      >
        {tiers.map((t, i) => (
          <option key={t.label} value={i}>
            {t.label} scans / month
          </option>
        ))}
      </select>
    </div>
  );
}

function PriceDisplay({ pricing }: { pricing: TierPricing }) {
  if (pricing.price === -1) {
    return (
      <div className="flex md:flex-row flex-col gap-2 md:items-center py-5 md:py-10 px-4 md:px-6">
        <p className="font-light text-[40px] text-stone-800 dark:text-white">
          Custom Price
        </p>
        <div className="flex flex-col gap-0.5">
          <p className="text-stone-800 dark:text-zinc-100 font-semibold text-sm font-mono uppercase">
            {pricing.tier}
          </p>
          <p className="text-stone-500 dark:text-zinc-400 font-normal text-xs">
            tailored to your needs
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex md:flex-row flex-col gap-2 md:items-center py-5 md:py-10 px-4 md:px-6">
      <p className="font-light text-[40px] text-stone-800 dark:text-white tabular-nums">
        <AnimatedPrice value={pricing.price} />
      </p>
      <div className="flex flex-col gap-0.5">
        <p className="text-stone-800 dark:text-zinc-100 font-semibold text-sm font-mono uppercase">
          {pricing.tier}
        </p>
        <p className="text-stone-500 dark:text-zinc-400 font-normal text-xs">
          {pricing.note ? (
            <span>{pricing.note}</span>
          ) : (
            <>
              <span className="md:hidden">प्रति महिना • billed monthly</span>
              <span className="hidden md:inline">
                प्रति महिना • billed monthly
              </span>
            </>
          )}
        </p>
      </div>
    </div>
  );
}

function FeatureList({
  features,
  heading,
  headingColor,
}: {
  features: Feature[];
  heading: string;
  headingColor?: string;
}) {
  return (
    <div className="flex flex-col gap-3 py-6 px-4 md:px-6">
      <p
        className={`font-semibold text-sm ${headingColor ?? "text-stone-800 dark:text-zinc-100"}`}
      >
        {heading}
      </p>
      {features.map((f) => (
        <div key={f.label} className="flex items-center gap-2">
          {f.included ? <CheckIcon /> : <XIcon />}
          <p
            className={`text-sm ${
              f.included
                ? "text-stone-700 dark:text-zinc-200 font-normal"
                : "text-stone-400 dark:text-zinc-500 font-normal line-through"
            }`}
          >
            {f.label}
          </p>
        </div>
      ))}
    </div>
  );
}

export type PricingColumnType = "guard" | "full";

function CtaButton({
  pricing,
  column,
  variant,
  colorScheme,
  isLoggedIn,
  paymentLoading,
  onAction,
}: {
  pricing: TierPricing;
  column: PricingColumnType;
  variant: "landing" | "dashboard";
  colorScheme: "dark" | "green";
  isLoggedIn: boolean;
  paymentLoading: boolean;
  onAction: (pricing: TierPricing, column: PricingColumnType) => void;
}) {
  const isFree = pricing.price === 0;
  const isEnterprise = pricing.price === -1;
  const isPaid = pricing.price > 0;
  const isProcessing = paymentLoading && isPaid;

  let label: string;
  if (isProcessing) {
    label = "Processing…";
  } else if (isEnterprise) {
    label = "Contact Sales";
  } else if (isFree) {
    if (variant === "dashboard") {
      label = "Current Plan";
    } else {
      label = isLoggedIn ? "Go to Dashboard" : "Start Free Trial";
    }
  } else {
    if (variant === "dashboard") {
      label = isLoggedIn ? "Continue to Pay" : "Log in to Pay";
    } else {
      label = isLoggedIn ? "Continue to Pay" : "Sign up & Pay";
    }
  }

  const baseClasses =
    "w-full md:px-6! group px-4 py-3 h-11 flex items-center font-semibold font-mono text-sm uppercase tracking-[0.56px] cursor-pointer transition-all outline-none disabled:opacity-60 disabled:cursor-wait";

  const colorClasses =
    colorScheme === "green"
      ? "bg-[#60BB46] hover:bg-[#4fa538] text-white"
      : "bg-stone-700 dark:bg-zinc-700 text-stone-50 dark:text-white hover:bg-stone-950 dark:hover:bg-zinc-600";
  const isDisabledFree = isFree && variant === "dashboard";

  return (
    <button
      type="button"
      disabled={isProcessing || isDisabledFree}
      onClick={() => onAction(pricing, column)}
      className={`${baseClasses} ${colorClasses} ${isDisabledFree ? "opacity-50 cursor-default!" : ""}`}
    >
      <div className="flex items-center justify-between w-full">
        {isProcessing ? (
          <span className="flex items-center gap-2">
            <SpinnerIcon />
            {label}
          </span>
        ) : (
          label
        )}
        {!isProcessing && isPaid ? (
          <EsewaLogo />
        ) : !isProcessing && !isDisabledFree ? (
          <ArrowIcon />
        ) : null}
      </div>
    </button>
  );
}

export interface PricingProps {
  variant?: "landing" | "dashboard";
  defaultIndex?: number;
  className?: string;
  onTierChange?: (tier: VolumeTier, index: number) => void;
}

export function PricingCore({
  variant = "landing",
  defaultIndex = 2,
  className,
  onTierChange,
}: PricingProps) {
  const [selectedIndex, setSelectedIndex] = useState(defaultIndex);

  const handleTierChange = useCallback(
    (index: number) => {
      setSelectedIndex(index);
      onTierChange?.(tiers[index], index);
    },
    [onTierChange],
  );

  useEffect(() => {
    onTierChange?.(tiers[selectedIndex], selectedIndex);
  }, []);
  const router = useRouter();
  const { data: session } = useSession();
  const isLoggedIn = !!session?.user;

  const {
    initiatePayment,
    loading: paymentLoading,
    error: paymentError,
    clearError,
  } = useEsewaPayment();

  const currentTier = tiers[selectedIndex];

  const handleCta = useCallback(
    (pricing: TierPricing, column: PricingColumnType) => {
      if (pricing.price === -1) {
        window.location.href =
          "mailto:sales@Orazen.com?subject=Enterprise%20Plan%20Inquiry";
        return;
      }

      if (pricing.price === 0) {
        if (variant === "dashboard") {
          return;
        }
        router.push(isLoggedIn ? "/dashboard" : "/login");
        return;
      }

      if (!isLoggedIn) {
        router.push("/login");
        return;
      }
      initiatePayment(selectedIndex, column);
    },
    [initiatePayment, router, isLoggedIn, variant, selectedIndex],
  );

  const isLanding = variant === "landing";

  return (
    <div className={`flex flex-col items-center w-full ${className ?? ""}`}>
      {paymentError && (
        <div className="fixed top-4 right-4 z-50 flex items-center gap-3 bg-red-50 dark:bg-red-950/80 border border-red-200 dark:border-red-800 text-red-800 dark:text-red-200 px-4 py-3 rounded-lg shadow-lg max-w-sm animate-in slide-in-from-top-2">
          <p className="text-sm flex-1">{paymentError}</p>
          <button
            type="button"
            onClick={clearError}
            className="text-red-400 hover:text-red-600 dark:text-red-400 dark:hover:text-red-200 text-lg leading-none cursor-pointer"
          >
            ×
          </button>
        </div>
      )}

      {isLanding && (
        <div className="flex flex-col gap-2 items-center px-4 lg:px-0 mb-8">
          <p className="text-stone-800 dark:text-zinc-300 font-normal text-xs uppercase font-mono leading-4 text-center">
            Simple pricing
          </p>
          <p className="text-stone-800 dark:text-white font-normal text-2xl cooper text-center">
            Scale protection with your usage
          </p>
          <p className="text-stone-500 dark:text-zinc-400 font-normal text-sm text-center max-w-md">
            Start free for 15 days with 5K Guard scans. Upgrade when you&apos;re
            ready. Pay easily with eSewa. No hidden fees.
          </p>
        </div>
      )}

      {!isLanding && (
        <div className="flex flex-col gap-1 items-start w-full mb-6">
          <p className="text-stone-800 dark:text-white font-semibold text-sm">
            Select a plan
          </p>
          <p className="text-stone-500 dark:text-zinc-400 font-normal text-xs">
            Choose your volume tier and pay securely with eSewa.
          </p>
        </div>
      )}

      <div
        className={`flex flex-col items-center w-full overflow-hidden ${isLanding ? "max-w-4xl md:border-x border-stone-200 dark:border-zinc-800" : "max-w-4xl"}`}
      >
        <div
          className={`flex flex-col w-full md:px-0 md:py-6 py-4 px-4 ${isLanding ? "bg-stone-100 dark:bg-zinc-800/70" : "bg-stone-50 dark:bg-zinc-800/50 rounded-t-lg border border-b-0 border-stone-200 dark:border-zinc-800"}`}
        >
          <div className="lg:flex flex-col items-center gap-4 w-full hidden">
            <div className="flex flex-col items-center gap-1">
              <p className="text-stone-800 dark:text-white font-medium text-sm font-mono">
                How many guard scans do you need per month?
              </p>
            </div>
            <div className="flex flex-col px-10 w-full">
              <VolumeSlider
                selectedIndex={selectedIndex}
                onChange={handleTierChange}
              />
            </div>
          </div>

          <div className="flex flex-col gap-4 lg:hidden px-4">
            <MobileVolumeSelect
              selectedIndex={selectedIndex}
              onChange={handleTierChange}
            />
          </div>
        </div>

        <div className="flex flex-col w-full items-center">
          <div
            className={`grid grid-cols-1 md:grid-cols-2 auto-rows-fr w-full border-t border-stone-200 dark:border-zinc-800 ${!isLanding ? "border border-b-0 dark:bg-zinc-900/30" : ""}`}
          >
            <div className="flex flex-col w-full md:border-r border-stone-200 dark:border-zinc-800">
              <div className="px-4 md:px-6 py-3 flex items-center justify-between border-b border-stone-200 dark:border-zinc-800">
                <p className="text-stone-800 dark:text-white font-semibold text-sm font-mono uppercase">
                  Guard <br className="sm:hidden" />
                  Only
                </p>
                {currentTier.guardOnly.price === 0 && (
                  <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-600 bg-emerald-50 dark:bg-emerald-500/15 dark:text-emerald-400 px-2 py-0.5 rounded-full font-semibold">
                    Free
                  </span>
                )}
              </div>

              <div className="border-b border-stone-200 dark:border-zinc-800">
                <PriceDisplay pricing={currentTier.guardOnly} />
              </div>

              <div>
                <CtaButton
                  pricing={currentTier.guardOnly}
                  column="guard"
                  variant={variant}
                  colorScheme="dark"
                  isLoggedIn={isLoggedIn}
                  paymentLoading={paymentLoading}
                  onAction={handleCta}
                />
              </div>

              <FeatureList features={guardOnlyFeatures} heading="Includes" />
            </div>

            <div className="flex flex-col w-full border-t md:border-t-0 border-stone-200 dark:border-zinc-800">
              <div className="px-4 md:px-6 py-3 flex items-center justify-between border-b border-stone-200 dark:border-zinc-800">
                <p className="text-stone-800 dark:text-white font-semibold text-sm font-mono uppercase">
                  Guard + <br className="sm:hidden" />
                  Vulnerability Testing
                </p>
                <span className="text-[10px] font-mono uppercase tracking-wider text-purple-600 bg-purple-50 dark:bg-purple-500/15 dark:text-purple-400 px-2 py-0.5 rounded-full font-semibold">
                  Recommended
                </span>
              </div>
              <div className="border-b border-stone-200 dark:border-zinc-800">
                <PriceDisplay pricing={currentTier.full} />
              </div>

              <div>
                <CtaButton
                  pricing={currentTier.full}
                  column="full"
                  variant={variant}
                  colorScheme="green"
                  isLoggedIn={isLoggedIn}
                  paymentLoading={paymentLoading}
                  onAction={handleCta}
                />
              </div>

              <FeatureList
                features={fullFeatures}
                heading='Everything in "Guard Only", plus:'
                headingColor="text-indigo-600 dark:text-indigo-400"
              />
            </div>
          </div>

          <div
            className={`flex flex-col gap-4 px-4 md:px-6 py-6 items-center w-full border-t border-stone-200 dark:border-zinc-800 ${!isLanding ? "border-x border-b rounded-b-lg" : ""}`}
          >
            <p className="text-stone-800 dark:text-white font-medium text-sm">
              Both plans include
            </p>
            <div className="flex flex-col md:flex-row md:items-center md:w-full gap-2">
              {sharedFeatures.map((f) => (
                <div key={f} className="flex-1">
                  <div className="flex items-center gap-2">
                    <CheckIcon />
                    <p className="text-stone-700 dark:text-zinc-200 font-normal text-sm">
                      {f}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

const stageOneBreakdown = [
  "Code Quality and Execution: 30 marks",
  "Innovation and Impact: 30 marks",
  "Mentor Evaluation and Team Collaboration: 10 marks",
];

const stageTwoBreakdown = [
  "Clarity and Structure: 5 marks",
  "Engagement and Storytelling: 5 marks",
  "Handling Q and A: 5 marks",
  "Business and Impact Understanding: 5 marks",
];

const Pricing = () => {
  return (
    <section
      id="rubric"
      className="mt-30 flex flex-col gap-6 border-b border-stone-200 px-4 py-10 dark:border-zinc-800 md:px-6"
    >
      <div className="mx-auto flex w-full max-w-5xl flex-col items-center gap-2 text-center">
        <p className="font-mono text-xs uppercase leading-4 text-stone-800 dark:text-zinc-300">
          Judging Criteria Snapshot
        </p>
        <p className="cooper text-2xl font-normal text-stone-800 dark:text-white">
          Build with the scorecard in mind
        </p>
        <p className="max-w-3xl text-sm leading-6 text-stone-600 dark:text-zinc-400">
          Stage 1 shortlists the top 12 teams. Final winners are decided by
          cumulative marks from both stages.
        </p>
      </div>

      <div className="mx-auto grid w-full max-w-5xl grid-cols-1 gap-4 md:grid-cols-2">
        <article className="flex flex-col gap-3 border border-dashed px-4 py-5 md:px-6">
          <div className="flex items-center justify-between">
            <p className="font-mono text-xs uppercase text-stone-800 dark:text-zinc-200">
              Stage 1
            </p>
            <span className="rounded-full bg-indigo-50 px-2 py-0.5 text-xs font-mono uppercase tracking-wide text-indigo-600 dark:bg-indigo-500/15 dark:text-indigo-300">
              70 Marks
            </span>
          </div>
          <p className="text-sm font-semibold uppercase leading-5 text-stone-800 dark:text-white">
            Technical Evaluation and Team Coordination
          </p>
          <ul className="flex flex-col gap-2">
            {stageOneBreakdown.map((item) => (
              <li
                key={item}
                className="text-sm leading-5 text-stone-600 dark:text-zinc-400"
              >
                {item}
              </li>
            ))}
          </ul>
        </article>

        <article className="flex flex-col gap-3 border border-dashed px-4 py-5 md:px-6">
          <div className="flex items-center justify-between">
            <p className="font-mono text-xs uppercase text-stone-800 dark:text-zinc-200">
              Stage 2
            </p>
            <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-mono uppercase tracking-wide text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-300">
              20 Marks
            </span>
          </div>
          <p className="text-sm font-semibold uppercase leading-5 text-stone-800 dark:text-white">
            Final Presentation Round
          </p>
          <ul className="flex flex-col gap-2">
            {stageTwoBreakdown.map((item) => (
              <li
                key={item}
                className="text-sm leading-5 text-stone-600 dark:text-zinc-400"
              >
                {item}
              </li>
            ))}
          </ul>
        </article>
      </div>

      <div className="mx-auto flex w-full max-w-5xl items-center justify-between border border-dashed px-4 py-4 md:px-6">
        <p className="font-mono text-xs uppercase text-stone-700 dark:text-zinc-300">
          Grand Total
        </p>
        <p className="cooper text-xl text-stone-800 dark:text-white">
          70 + 20 = 90 marks
        </p>
      </div>
    </section>
  );
};

export default Pricing;
