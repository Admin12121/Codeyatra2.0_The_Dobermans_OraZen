// ============================================================
// Orazen — Subscription Plan Configuration
// ============================================================
// Single source of truth for all plan tiers, limits, pricing,
// and feature flags. Used by account page, usage section,
// billing, and plan enforcement throughout the frontend.
//
// NOTE: All prices are in NPR (Nepali Rupee) and paid via eSewa.
// Actual prices are volume-based — see lib/esewa.ts PRICING_TABLE
// and components/layout/landing/pricing.tsx for the tier slider.
// The prices shown here are the starting/base prices for each tier.
// ============================================================

// ============================================
// Types
// ============================================

export type PlanId = "free_trial" | "starter" | "pro" | "enterprise";

export interface PlanLimit {
  /** Max LLM Guard prompt scans per billing period (-1 = unlimited) */
  guardScans: number;
  /** Max Garak vulnerability scans per billing period (-1 = unlimited) */
  garakScans: number;
  /** Max active (non-revoked) API keys (-1 = unlimited) */
  apiKeys: number;
  /** Max model configurations (-1 = unlimited) */
  modelConfigs: number;
  /** Max prompts per Garak probe */
  maxPromptsPerProbe: number;
  /** Whether advanced per-scanner config is allowed */
  advancedScanConfig: boolean;
  /** Whether priority queue is enabled for GPU jobs */
  priorityQueue: boolean;
  /** Whether full API access (programmatic) is available */
  fullApiAccess: boolean;
  /** Whether SSO is available */
  sso: boolean;
  /** Whether custom Garak probes are available */
  customProbes: boolean;
  /** Whether dedicated GPU is included */
  dedicatedGpu: boolean;
  /** Rate limit: requests per minute per API key */
  rateLimitRpm: number;
}

export interface PlanTier {
  id: PlanId;
  name: string;
  /** Short marketing tagline */
  tagline: string;
  /** Price display string (e.g. "रू 1,500", "Custom") */
  price: string;
  /** Numeric price in NPR for comparison/sorting (0 for free, -1 for custom) */
  priceNpr: number;
  /** Billing period label */
  period: string;
  /** Duration note (e.g. "15 days" for trial) */
  durationNote?: string;
  /** Feature list for display in plan cards */
  features: string[];
  /** Detailed limits */
  limits: PlanLimit;
  /** Whether to show "Recommended" badge */
  recommended: boolean;
  /** CTA button label when not on this plan */
  ctaLabel: string;
  /** Badge color class for plan indicators */
  badgeClass: string;
  /** Sort order for display */
  order: number;
}

// ============================================
// Plan Definitions
// ============================================

const FREE_TRIAL: PlanTier = {
  id: "free_trial",
  name: "Free Trial",
  tagline: "Get started and explore",
  price: "रू 0",
  priceNpr: 0,
  period: "15 days",
  durationNote: "15-day trial — Guard only",
  features: [
    "5,000 LLM Guard scans",
    "1 API key",
    "3 model configurations",
    "Basic threat detection",
    "Community support",
  ],
  limits: {
    guardScans: 5_000,
    garakScans: 0,
    apiKeys: 1,
    modelConfigs: 3,
    maxPromptsPerProbe: 10,
    advancedScanConfig: false,
    priorityQueue: false,
    fullApiAccess: false,
    sso: false,
    customProbes: false,
    dedicatedGpu: false,
    rateLimitRpm: 60,
  },
  recommended: false,
  ctaLabel: "Start Free Trial",
  badgeClass: "bg-zinc-700 text-stone-400 border-zinc-600",
  order: 0,
};

const STARTER: PlanTier = {
  id: "starter",
  name: "Starter",
  tagline: "For individuals and small teams",
  price: "रू 1,500",
  priceNpr: 1500,
  period: " / महिना",
  features: [
    "10K–25K Guard scans / month",
    "Garak vulnerability scans included",
    "3 API keys",
    "5 model configurations",
    "Basic scanner configuration",
    "Email support",
    "Scan history & reports",
  ],
  limits: {
    guardScans: 50_000,
    garakScans: 10,
    apiKeys: 3,
    modelConfigs: 5,
    maxPromptsPerProbe: 25,
    advancedScanConfig: false,
    priorityQueue: false,
    fullApiAccess: true,
    sso: false,
    customProbes: false,
    dedicatedGpu: false,
    rateLimitRpm: 120,
  },
  recommended: false,
  ctaLabel: "Upgrade to Starter",
  badgeClass: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  order: 1,
};

const PRO: PlanTier = {
  id: "pro",
  name: "Pro",
  tagline: "For growing security teams",
  price: "रू 6,900",
  priceNpr: 6900,
  period: " / महिना",
  features: [
    "50K–1M Guard scans / month",
    "Full Garak vulnerability testing",
    "10 API keys",
    "20 model configurations",
    "Advanced per-scanner configuration",
    "Priority GPU queue",
    "Full API access",
    "Priority support",
    "Custom scanner thresholds",
    "Detailed vulnerability reports",
  ],
  limits: {
    guardScans: 500_000,
    garakScans: 50,
    apiKeys: 10,
    modelConfigs: 20,
    maxPromptsPerProbe: 50,
    advancedScanConfig: true,
    priorityQueue: true,
    fullApiAccess: true,
    sso: false,
    customProbes: false,
    dedicatedGpu: false,
    rateLimitRpm: 300,
  },
  recommended: true,
  ctaLabel: "Upgrade to Pro",
  badgeClass: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  order: 2,
};

const ENTERPRISE: PlanTier = {
  id: "enterprise",
  name: "Enterprise",
  tagline: "For organizations with advanced needs",
  price: "Custom",
  priceNpr: -1,
  period: "",
  features: [
    "Unlimited LLM Guard scans",
    "Unlimited Garak scans",
    "Unlimited API keys",
    "Unlimited model configurations",
    "All scanners included",
    "Dedicated GPU instance",
    "Custom Garak probes",
    "SSO / SAML integration",
    "SLA guarantee (99.9%)",
    "On-premise deployment option",
    "Dedicated support engineer",
    "Custom integrations",
  ],
  limits: {
    guardScans: -1,
    garakScans: -1,
    apiKeys: -1,
    modelConfigs: -1,
    maxPromptsPerProbe: 100,
    advancedScanConfig: true,
    priorityQueue: true,
    fullApiAccess: true,
    sso: true,
    customProbes: true,
    dedicatedGpu: true,
    rateLimitRpm: 1000,
  },
  recommended: false,
  ctaLabel: "Contact Sales",
  badgeClass: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  order: 3,
};

// ============================================
// Exports
// ============================================

/** All plans in display order */
export const PLANS: PlanTier[] = [FREE_TRIAL, STARTER, PRO, ENTERPRISE];

/** Quick lookup map by plan ID */
export const PLAN_MAP: Record<PlanId, PlanTier> = {
  free_trial: FREE_TRIAL,
  starter: STARTER,
  pro: PRO,
  enterprise: ENTERPRISE,
};

// ============================================
// Helper Functions
// ============================================

/**
 * Resolve a plan ID string from the database to a PlanTier.
 * Falls back to free_trial if the plan string is null, empty, or unrecognized.
 *
 * The database `organization.plan` column stores values like
 * "free", "free_trial", "starter", "pro", "enterprise", or null.
 */
export function resolvePlan(planStr: string | null | undefined): PlanTier {
  if (!planStr) return FREE_TRIAL;

  const normalized = planStr.toLowerCase().trim();

  // Direct match
  if (normalized in PLAN_MAP) {
    return PLAN_MAP[normalized as PlanId];
  }

  // Legacy aliases
  if (normalized === "free") return FREE_TRIAL;
  if (normalized === "basic") return STARTER;
  if (normalized === "team") return PRO;

  return FREE_TRIAL;
}

/**
 * Get the limit value for a specific resource.
 * Returns -1 for unlimited.
 */
export function getPlanLimit(
  planStr: string | null | undefined,
  resource: keyof PlanLimit,
): number | boolean {
  const plan = resolvePlan(planStr);
  return plan.limits[resource];
}

/**
 * Check if a numeric usage is within the plan limit.
 * Unlimited (-1) always returns true.
 */
export function isWithinLimit(
  planStr: string | null | undefined,
  resource: "guardScans" | "garakScans" | "apiKeys" | "modelConfigs",
  currentUsage: number,
): boolean {
  const limit = resolvePlan(planStr).limits[resource];
  if (limit === -1) return true;
  return currentUsage < limit;
}

/**
 * Calculate usage percentage for display.
 * Returns 0 for unlimited plans.
 */
export function usagePercent(
  planStr: string | null | undefined,
  resource: "guardScans" | "garakScans" | "apiKeys" | "modelConfigs",
  currentUsage: number,
): number {
  const limit = resolvePlan(planStr).limits[resource];
  if (limit === -1) return 0;
  if (limit === 0) return 100;
  return Math.min((currentUsage / limit) * 100, 100);
}

/**
 * Format a limit number for display.
 * -1 → "Unlimited", otherwise locale-formatted number.
 */
export function formatLimit(limit: number): string {
  if (limit === -1) return "Unlimited";
  return limit.toLocaleString();
}

/**
 * Check if a boolean feature is available on the plan.
 */
export function hasFeature(
  planStr: string | null | undefined,
  feature:
    | "advancedScanConfig"
    | "priorityQueue"
    | "fullApiAccess"
    | "sso"
    | "customProbes"
    | "dedicatedGpu",
): boolean {
  return resolvePlan(planStr).limits[feature] as boolean;
}

/**
 * Get the next tier up from the current plan (for upgrade prompts).
 * Returns null if already on the highest plan.
 */
export function getUpgradePlan(
  planStr: string | null | undefined,
): PlanTier | null {
  const current = resolvePlan(planStr);
  const nextOrder = current.order + 1;
  return PLANS.find((p) => p.order === nextOrder) ?? null;
}

/**
 * Check if a plan is the free trial.
 */
export function isFreePlan(planStr: string | null | undefined): boolean {
  const plan = resolvePlan(planStr);
  return plan.id === "free_trial";
}

/**
 * Check if a plan is a paid plan (Starter, Pro, or Enterprise).
 */
export function isPaidPlan(planStr: string | null | undefined): boolean {
  const plan = resolvePlan(planStr);
  return plan.order >= 1;
}

// ============================================
// Cost & Currency Constants
// ============================================

/** Currency symbol for display */
export const CURRENCY_SYMBOL = "रू";

/** Currency code */
export const CURRENCY_CODE = "NPR";

/** Estimated GPU cost per 5,000 guard scans (T4 @ ~$0.50/hr) */
export const COST_PER_5K_SCANS_USD = 0.07;

/** Estimated GPU cost per 10,000 guard scans (T4 @ ~$0.50/hr) */
export const COST_PER_10K_SCANS_USD = 0.14;

/** Estimated GPU cost per Garak scan (~15 min avg on T4) */
export const COST_PER_GARAK_SCAN_USD = 0.125;

/** Estimated cost per free trial user (5K guard scans, no Garak) */
export const COST_PER_FREE_TRIAL_USER_USD = 0.07;

/** Monthly infrastructure base cost (budget GPU provider) */
export const MONTHLY_INFRA_BASE_USD = 300;

/**
 * Format an NPR amount for display.
 * e.g. 6900 → "रू 6,900"
 */
export function formatNpr(amount: number): string {
  if (amount < 0) return "Custom";
  return `रू ${amount.toLocaleString("en-IN")}`;
}
