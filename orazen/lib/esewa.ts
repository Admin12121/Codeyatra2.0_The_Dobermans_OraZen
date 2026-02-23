// ============================================================
// eSewa Payment Integration — Utility Module (Security Hardened)
// ============================================================
// Handles HMAC-SHA256 signature generation/verification,
// configuration, and helper functions for eSewa ePay v2.
//
// SECURITY NOTES:
//   - Prices are resolved SERVER-SIDE only — never trust client amounts
//   - Transaction UUIDs use crypto.randomUUID() for unpredictability
//   - No hardcoded secrets — env vars are REQUIRED in production
//   - Pending payments expire after 30 minutes
//   - Product code is validated in response verification
//   - Constant-time HMAC comparison prevents timing attacks
//
// Docs: https://developer.esewa.com.np/pages/Epay
// ============================================================

import { createHmac, timingSafeEqual } from "crypto";

// ============================================================
// Configuration
// ============================================================

/** eSewa environment configuration */
interface EsewaConfig {
  /** eSewa merchant/product code */
  productCode: string;
  /** HMAC secret key provided by eSewa */
  secretKey: string;
  /** eSewa payment form URL */
  paymentUrl: string;
  /** eSewa transaction status verification URL */
  verifyUrl: string;
  /** Whether we're in sandbox/test mode */
  isSandbox: boolean;
}

// Cache the config so we only validate once per process
let _cachedConfig: EsewaConfig | null = null;

/**
 * Clear the cached eSewa config (useful for testing or env changes).
 */
export function clearEsewaConfigCache(): void {
  _cachedConfig = null;
}

/**
 * Get eSewa configuration based on environment variables.
 *
 * Mode resolution (in priority order):
 *   1. ESEWA_ENVIRONMENT=production  → require real keys, use production URLs
 *   2. ESEWA_ENVIRONMENT=sandbox     → always sandbox, even if NODE_ENV=production
 *   3. ESEWA_ENVIRONMENT not set     → sandbox if keys are absent, production if keys are present
 *
 * This means NODE_ENV=production (set by Next.js build/Docker) does NOT
 * force eSewa into production mode. Only ESEWA_ENVIRONMENT=production does.
 * This lets you run an optimized Next.js build against the eSewa sandbox.
 */
export function getEsewaConfig(): EsewaConfig {
  if (_cachedConfig) return _cachedConfig;

  const esewaEnv = process.env.ESEWA_ENVIRONMENT; // "production" | "sandbox" | undefined
  const secretKey = process.env.ESEWA_SECRET_KEY;
  const productCode = process.env.ESEWA_PRODUCT_CODE;

  // Determine whether eSewa itself should run in production mode.
  // ONLY an explicit ESEWA_ENVIRONMENT=production triggers strict mode.
  // When ESEWA_ENVIRONMENT is unset, we auto-detect: if both keys are
  // provided we use production; otherwise we fall back to sandbox.
  const esewaProduction =
    esewaEnv === "production" ||
    (esewaEnv !== "sandbox" && !!secretKey && !!productCode);

  if (esewaEnv === "production" && !secretKey) {
    throw new Error(
      "ESEWA_SECRET_KEY environment variable is required when ESEWA_ENVIRONMENT=production. " +
        "Payment processing cannot proceed without it.",
    );
  }

  if (esewaEnv === "production" && !productCode) {
    throw new Error(
      "ESEWA_PRODUCT_CODE environment variable is required when ESEWA_ENVIRONMENT=production.",
    );
  }

  const isSandbox = !esewaProduction;

  if (isSandbox) {
    console.warn(
      "[eSewa] Using sandbox test credentials (EPAYTEST). " +
        "Set ESEWA_ENVIRONMENT=production with real keys for live payments.",
    );
  }

  _cachedConfig = {
    productCode: productCode || (isSandbox ? "EPAYTEST" : ""),
    secretKey: secretKey || (isSandbox ? "8gBm/:&EnhH.1/q" : ""),
    paymentUrl: isSandbox
      ? "https://rc-epay.esewa.com.np/api/epay/main/v2/form"
      : "https://epay.esewa.com.np/api/epay/main/v2/form",
    // Official docs: sandbox status check is rc.esewa.com.np (NOT uat.esewa.com.np)
    verifyUrl: isSandbox
      ? "https://rc.esewa.com.np/api/epay/transaction/status/"
      : "https://esewa.com.np/api/epay/transaction/status/",
    isSandbox,
  };

  return _cachedConfig;
}

// ============================================================
// HMAC Signature
// ============================================================

/**
 * Generate HMAC-SHA256 signature for eSewa ePay v2.
 *
 * eSewa expects the message in this exact format:
 *   `total_amount={amount},transaction_uuid={uuid},product_code={code}`
 *
 * The signature is Base64-encoded.
 */
export function generateEsewaSignature(
  totalAmount: number,
  transactionUuid: string,
  productCode: string,
  secretKey: string,
): string {
  const message = `total_amount=${totalAmount},transaction_uuid=${transactionUuid},product_code=${productCode}`;
  const hmac = createHmac("sha256", secretKey);
  hmac.update(message);
  return hmac.digest("base64");
}

/**
 * Verify an HMAC-SHA256 signature from eSewa's response.
 * Uses crypto.timingSafeEqual for constant-time comparison
 * to prevent timing attacks.
 */
export function verifyEsewaSignature(
  signedFieldNames: string,
  responseData: Record<string, string | number>,
  receivedSignature: string,
  secretKey: string,
): boolean {
  // Build the message from signed_field_names order
  const fields = signedFieldNames.split(",");
  const message = fields
    .map((field) => `${field}=${responseData[field] ?? ""}`)
    .join(",");

  const hmac = createHmac("sha256", secretKey);
  hmac.update(message);
  const computedSignature = hmac.digest("base64");

  // Use timingSafeEqual for constant-time comparison
  const computedBuf = Buffer.from(computedSignature, "utf-8");
  const receivedBuf = Buffer.from(receivedSignature, "utf-8");

  if (computedBuf.length !== receivedBuf.length) {
    return false;
  }

  return timingSafeEqual(computedBuf, receivedBuf);
}

// ============================================================
// Payment Form Data
// ============================================================

/** Data required to build the eSewa payment form */
export interface EsewaPaymentFormData {
  /** Amount (excluding tax) */
  amount: number;
  /** Tax amount */
  tax_amount: number;
  /** Service charge by merchant on product */
  product_service_charge: number;
  /** Delivery charge by merchant on product */
  product_delivery_charge: number;
  /** Total amount (amount + tax + service_charge + delivery_charge) */
  total_amount: number;
  /** Unique transaction identifier */
  transaction_uuid: string;
  /** Merchant product code */
  product_code: string;
  /** HMAC-SHA256 signature (Base64) */
  signature: string;
  /** Comma-separated list of signed field names */
  signed_field_names: string;
  /** URL eSewa redirects to on success */
  success_url: string;
  /** URL eSewa redirects to on failure */
  failure_url: string;
}

/**
 * Build the complete eSewa payment form data.
 * This data should be used to construct a form that POSTs to eSewa's payment URL.
 */
export function buildPaymentFormData(params: {
  amount: number;
  taxAmount?: number;
  productServiceCharge?: number;
  productDeliveryCharge?: number;
  transactionUuid: string;
  successUrl: string;
  failureUrl: string;
}): EsewaPaymentFormData {
  const config = getEsewaConfig();
  const taxAmount = params.taxAmount ?? 0;
  const productServiceCharge = params.productServiceCharge ?? 0;
  const productDeliveryCharge = params.productDeliveryCharge ?? 0;
  const totalAmount =
    params.amount + taxAmount + productServiceCharge + productDeliveryCharge;

  // Validate amount is a positive integer (NPR, no paisa)
  if (!Number.isInteger(totalAmount) || totalAmount <= 0) {
    throw new Error(
      `Invalid payment amount: ${totalAmount}. Must be a positive integer.`,
    );
  }

  const signature = generateEsewaSignature(
    totalAmount,
    params.transactionUuid,
    config.productCode,
    config.secretKey,
  );

  return {
    amount: params.amount,
    tax_amount: taxAmount,
    product_service_charge: productServiceCharge,
    product_delivery_charge: productDeliveryCharge,
    total_amount: totalAmount,
    transaction_uuid: params.transactionUuid,
    product_code: config.productCode,
    signature,
    signed_field_names: "total_amount,transaction_uuid,product_code",
    success_url: params.successUrl,
    failure_url: params.failureUrl,
  };
}

// ============================================================
// Response Decoding
// ============================================================

/** Decoded eSewa success response */
export interface EsewaSuccessResponse {
  transaction_code: string;
  status: string;
  total_amount: string;
  transaction_uuid: string;
  product_code: string;
  signed_field_names: string;
  signature: string;
}

/**
 * Decode the base64-encoded response data from eSewa's success redirect.
 * eSewa sends a `data` query parameter that is a Base64-encoded JSON string.
 *
 * SECURITY: Validates required fields exist before returning.
 */
export function decodeEsewaResponse(
  base64Data: string,
): EsewaSuccessResponse | null {
  try {
    // Reject excessively large payloads (prevent DoS via huge base64 strings)
    if (base64Data.length > 4096) {
      console.error("eSewa response data exceeds maximum length");
      return null;
    }

    const jsonString = Buffer.from(base64Data, "base64").toString("utf-8");
    const parsed = JSON.parse(jsonString);

    // Validate required fields exist and are strings
    const requiredFields = [
      "transaction_uuid",
      "product_code",
      "total_amount",
      "signed_field_names",
      "signature",
    ];

    for (const field of requiredFields) {
      if (
        typeof parsed[field] !== "string" ||
        parsed[field].trim().length === 0
      ) {
        console.error(`eSewa response missing or invalid field: ${field}`);
        return null;
      }
    }

    return parsed as EsewaSuccessResponse;
  } catch {
    console.error("Failed to decode eSewa response");
    return null;
  }
}

/**
 * Verify the decoded eSewa response signature AND product code.
 *
 * SECURITY: Validates both:
 *   1. The HMAC signature matches (proves eSewa signed this data)
 *   2. The product_code matches our merchant code (prevents cross-merchant replay)
 */
export function verifyEsewaResponse(response: EsewaSuccessResponse): boolean {
  const config = getEsewaConfig();

  // Verify product code matches our merchant account
  if (response.product_code !== config.productCode) {
    console.error(
      "eSewa product code mismatch. Expected:",
      config.productCode,
      "Got:",
      response.product_code,
    );
    return false;
  }

  return verifyEsewaSignature(
    response.signed_field_names,
    response as unknown as Record<string, string | number>,
    response.signature,
    config.secretKey,
  );
}

// ============================================================
// Transaction Status Verification
// ============================================================

/** eSewa transaction status response */
export interface EsewaTransactionStatus {
  product_code: string;
  transaction_uuid: string;
  total_amount: number;
  status:
    | "COMPLETE"
    | "PENDING"
    | "FULL_REFUND"
    | "PARTIAL_REFUND"
    | "NOT_FOUND"
    | "CANCELED"
    | "AMBIGUOUS";
  ref_id: string;
}

/**
 * Verify a transaction directly with eSewa's status API.
 * This is the most reliable way to confirm payment — use this
 * as a secondary check after verifying the redirect signature.
 *
 * SECURITY: Uses a 10-second timeout to prevent hanging on eSewa downtime.
 */
export async function verifyTransactionStatus(
  transactionUuid: string,
  totalAmount: number,
): Promise<EsewaTransactionStatus | null> {
  const config = getEsewaConfig();

  const params = new URLSearchParams({
    product_code: config.productCode,
    total_amount: String(totalAmount),
    transaction_uuid: transactionUuid,
  });

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000); // 10s timeout

    const response = await fetch(`${config.verifyUrl}?${params.toString()}`, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      console.error(
        `eSewa status check failed: ${response.status} ${response.statusText}`,
      );
      return null;
    }

    const data = await response.json();

    // Validate the status response product code matches
    if (data.product_code && data.product_code !== config.productCode) {
      console.error(
        "eSewa status API product code mismatch:",
        data.product_code,
      );
      return null;
    }

    return data as EsewaTransactionStatus;
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      console.error("eSewa status API request timed out");
    } else {
      console.error("eSewa transaction status verification failed:", error);
    }
    return null;
  }
}

// ============================================================
// Volume-Tier-Aware Pricing (Server-Side Source of Truth)
// ============================================================
// SECURITY: ALL prices are defined here on the server.
// The client NEVER sends a price — it sends a planId + tierIndex,
// and the server resolves the price from this table.
//
// The pricing page UI reads from its own copy of the tiers (for display),
// but the actual charge amount is ALWAYS resolved server-side from
// this map. Even if the client is tampered with, the server will
// only charge the correct amount for the selected tier.
// ============================================================

/**
 * A single purchasable price point.
 * `planId` is what gets stored in the subscription table.
 */
export interface PricePoint {
  /** Amount in NPR (integer, e.g. 6500 = रू6,500) */
  amount: number;
  /** The subscription plan ID this maps to: "starter" | "pro" */
  planId: "starter" | "pro";
  /** Human-readable tier name for receipts */
  tierLabel: string;
}

/**
 * Server-side pricing table keyed by `{tierIndex}-{column}`.
 *
 * tierIndex: 0–8 (matching the tiers array in pricing.tsx)
 * column: "guard" or "full"
 *
 * IMPORTANT: If you change prices in pricing.tsx, you MUST update
 * this table too. The server will reject any payment attempt where
 * the tier/column combination is not found here.
 */
const PRICING_TABLE: Record<string, PricePoint> = {
  // 5K — guard only is FREE (not in table), full costs money
  // Full ratio: N/A (guard is free)
  "0-full": { amount: 1900, planId: "starter", tierLabel: "5K Full" },

  // 10K — both paid (ratio: 1.93x)
  "1-guard": { amount: 1500, planId: "starter", tierLabel: "10K Guard" },
  "1-full": { amount: 2900, planId: "starter", tierLabel: "10K Full" },

  // 25K (ratio: 1.55x)
  "2-guard": { amount: 2900, planId: "starter", tierLabel: "25K Guard" },
  "2-full": { amount: 4500, planId: "starter", tierLabel: "25K Full" },

  // 50K (ratio: 1.53x)
  "3-guard": { amount: 4500, planId: "starter", tierLabel: "50K Guard" },
  "3-full": { amount: 6900, planId: "pro", tierLabel: "50K Full" },

  // 100K (ratio: 1.43x)
  "4-guard": { amount: 6900, planId: "pro", tierLabel: "100K Guard" },
  "4-full": { amount: 9900, planId: "pro", tierLabel: "100K Full" },

  // 250K (ratio: 1.47x)
  "5-guard": { amount: 12900, planId: "pro", tierLabel: "250K Guard" },
  "5-full": { amount: 18900, planId: "pro", tierLabel: "250K Full" },

  // 500K (ratio: 1.50x)
  "6-guard": { amount: 19900, planId: "pro", tierLabel: "500K Guard" },
  "6-full": { amount: 29900, planId: "pro", tierLabel: "500K Full" },

  // 1M (ratio: 1.43x)
  "7-guard": { amount: 34900, planId: "pro", tierLabel: "1M Guard" },
  "7-full": { amount: 49900, planId: "pro", tierLabel: "1M Full" },

  // 1M+ (Enterprise) — not self-serve, not in this table
};

/** Valid tier indices (0–8) */
const MAX_TIER_INDEX = 8;

/** Valid columns */
export type PricingColumn = "guard" | "full";

/**
 * Resolve the price for a given tier index and column.
 *
 * SECURITY: This is the ONLY function that determines the charge amount.
 * It never trusts client-provided prices.
 *
 * Returns null if:
 *   - The tier/column is free (5K guard only)
 *   - The tier/column is enterprise (1M+)
 *   - The tier index is out of range
 *   - The combination is invalid
 */
export function resolveTierPrice(
  tierIndex: number,
  column: PricingColumn,
): PricePoint | null {
  // Validate tier index
  if (
    !Number.isInteger(tierIndex) ||
    tierIndex < 0 ||
    tierIndex > MAX_TIER_INDEX
  ) {
    return null;
  }

  const key = `${tierIndex}-${column}`;
  return PRICING_TABLE[key] ?? null;
}

/**
 * Get all valid tier indices for a column.
 * Useful for validation.
 */
export function getValidTierIndices(column: PricingColumn): number[] {
  return Object.keys(PRICING_TABLE)
    .filter((k) => k.endsWith(`-${column}`))
    .map((k) => parseInt(k.split("-")[0], 10))
    .sort((a, b) => a - b);
}

// ============================================================
// Pending Payment Expiry
// ============================================================

/** How long a pending payment is valid (in milliseconds) */
export const PENDING_PAYMENT_TTL_MS = 30 * 60 * 1000; // 30 minutes

/**
 * Check if a pending payment has expired.
 * Payments must be completed within 30 minutes of creation.
 */
export function isPaymentExpired(createdAt: Date): boolean {
  return Date.now() - createdAt.getTime() > PENDING_PAYMENT_TTL_MS;
}

// ============================================================
// Secure Transaction UUID Generator
// ============================================================

/**
 * Generate a cryptographically secure transaction UUID.
 *
 * SECURITY: Uses crypto.randomUUID() (CSPRNG-backed) instead
 * of Math.random() to prevent transaction ID prediction.
 *
 * Format: `ora-{uuid}` — prefixed for easy identification in logs.
 */
export function generateTransactionUuid(): string {
  return `ora-${crypto.randomUUID()}`;
}

// ============================================================
// Redirect URL Builder (Safe)
// ============================================================

/**
 * Build a safe base URL for eSewa redirect callbacks.
 *
 * SECURITY: Uses NEXT_PUBLIC_APP_URL or BETTER_AUTH_URL from env
 * instead of trusting request Host/X-Forwarded-Proto headers,
 * which can be spoofed by attackers to redirect payments to
 * a phishing domain.
 *
 * Falls back to request headers ONLY in development.
 */
export function getSafeBaseUrl(request: Request): string {
  // Prefer explicit env var — this is the canonical app URL
  const envUrl = process.env.NEXT_PUBLIC_APP_URL || process.env.BETTER_AUTH_URL;

  if (envUrl) {
    // Strip trailing slash
    return envUrl.replace(/\/+$/, "");
  }

  // Development fallback: use request headers (NOT safe for production)
  if (process.env.NODE_ENV !== "production") {
    const proto = request.headers.get("x-forwarded-proto") || "http";
    const host = request.headers.get("host") || "localhost:3000";
    return `${proto}://${host}`;
  }

  // Production without env var — refuse to proceed
  throw new Error(
    "NEXT_PUBLIC_APP_URL or BETTER_AUTH_URL must be set in production. " +
      "Cannot safely construct redirect URLs from request headers.",
  );
}
