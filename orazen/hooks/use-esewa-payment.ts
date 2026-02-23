"use client";

import { useState, useCallback, useRef } from "react";

// ============================================================
// eSewa Payment Hook (Tier-Aware)
// ============================================================
// Handles the full client-side eSewa payment flow:
//   1. Calls POST /api/esewa/initiate with tierIndex + column
//   2. Server resolves price from its PRICING_TABLE (no client price)
//   3. Receives signed form data from the server
//   4. Dynamically creates and submits a form to eSewa's payment URL
//   5. User is redirected to eSewa to complete payment
//   6. eSewa redirects back to /api/esewa/verify on success/failure
//
// SECURITY: The client NEVER sends a price. It sends:
//   - tierIndex (0–8): which volume tier the user selected
//   - column ("guard" | "full"): which plan column they clicked
//
// The server resolves the exact price from its hardcoded pricing
// table. Even if a user tampers with tierIndex/column, they can
// only select from the server's known price points — never set
// an arbitrary amount.
//
// Usage:
//   const { initiatePayment, loading, error } = useEsewaPayment();
//   <button onClick={() => initiatePayment(2, "full")}>Pay</button>
// ============================================================

export interface EsewaFormData {
  amount: number;
  tax_amount: number;
  product_service_charge: number;
  product_delivery_charge: number;
  total_amount: number;
  transaction_uuid: string;
  product_code: string;
  signature: string;
  signed_field_names: string;
  success_url: string;
  failure_url: string;
}

export interface ResolvedPrice {
  amount: number;
  planId: string;
  tierLabel: string;
}

export interface InitiateResponse {
  success: boolean;
  paymentId: string;
  transactionUuid: string;
  resolvedPrice: ResolvedPrice;
  formData: EsewaFormData;
  paymentUrl: string;
}

export type PricingColumn = "guard" | "full";

interface UseEsewaPaymentReturn {
  /**
   * Initiate payment for a given tier index and column.
   *
   * @param tierIndex - Volume tier index (0–8), matching the tiers array in pricing.tsx
   * @param column - "guard" for Guard Only, "full" for Guard + Vulnerability Testing
   */
  initiatePayment: (tierIndex: number, column: PricingColumn) => Promise<void>;
  /** Whether a payment initiation is in progress */
  loading: boolean;
  /** Error message if initiation failed */
  error: string | null;
  /** Clear the current error */
  clearError: () => void;
  /** The payment ID of the last initiated payment (for tracking) */
  lastPaymentId: string | null;
  /** The server-resolved price of the last initiated payment */
  lastResolvedPrice: ResolvedPrice | null;
}

/**
 * Hook to handle eSewa payment initiation and form submission.
 *
 * The flow:
 * 1. Client calls `initiatePayment(2, "full")` (25K, Guard + Vuln Testing)
 * 2. Hook POSTs to `/api/esewa/initiate` with `{ tierIndex: 2, column: "full" }`
 * 3. Server resolves price from PRICING_TABLE → रू4,500 (starter plan)
 * 4. Server creates pending payment record + returns HMAC-signed form data
 * 5. Hook creates a hidden form and submits it to eSewa's payment URL
 * 6. User is redirected to eSewa's payment page
 * 7. After payment, eSewa redirects to `/api/esewa/verify`
 * 8. Verify route processes the payment and redirects to `/account?tab=billing`
 */
export function useEsewaPayment(): UseEsewaPaymentReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastPaymentId, setLastPaymentId] = useState<string | null>(null);
  const [lastResolvedPrice, setLastResolvedPrice] =
    useState<ResolvedPrice | null>(null);
  const formRef = useRef<HTMLFormElement | null>(null);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const initiatePayment = useCallback(
    async (tierIndex: number, column: PricingColumn) => {
      // ── Client-side validation ────────────────────────────────
      // These are basic sanity checks. The server does full validation.

      if (
        typeof tierIndex !== "number" ||
        !Number.isInteger(tierIndex) ||
        tierIndex < 0 ||
        tierIndex > 8
      ) {
        setError("Invalid tier selection. Please try again.");
        return;
      }

      if (column !== "guard" && column !== "full") {
        setError("Invalid plan column. Please try again.");
        return;
      }

      // 5K guard only is free — no payment needed
      if (tierIndex === 0 && column === "guard") {
        setError("This tier is free. No payment required.");
        return;
      }

      // 1M+ is enterprise — contact sales
      if (tierIndex === 8) {
        setError("Enterprise plans require a custom quote. Contact sales.");
        return;
      }

      setLoading(true);
      setError(null);
      setLastPaymentId(null);
      setLastResolvedPrice(null);

      try {
        // ── 1. Call initiation API ──────────────────────────────
        const response = await fetch("/api/esewa/initiate", {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({ tierIndex, column }),
        });

        if (!response.ok) {
          const body: unknown = await response.json().catch(() => null);
          const errorMessage =
            body &&
            typeof body === "object" &&
            "error" in body &&
            typeof body.error === "string"
              ? body.error
              : `Payment initiation failed (${response.status})`;

          // Surface specific error messages from server
          throw new Error(errorMessage);
        }

        const data: InitiateResponse = await response.json();

        if (!data.success || !data.formData || !data.paymentUrl) {
          throw new Error("Invalid response from payment server");
        }

        setLastPaymentId(data.paymentId);
        setLastResolvedPrice(data.resolvedPrice);

        // ── 2. Build and submit form to eSewa ───────────────────
        // Clean up any previously created form
        if (formRef.current && formRef.current.parentNode) {
          formRef.current.parentNode.removeChild(formRef.current);
          formRef.current = null;
        }

        const form = document.createElement("form");
        form.method = "POST";
        form.action = data.paymentUrl;
        form.style.display = "none";

        // Add all form fields from the server-signed data
        // NOTE: These values are HMAC-signed by the server. Modifying
        // any of them (amount, transaction_uuid, product_code) will
        // cause eSewa to reject the submission because the signature
        // won't match. This is the core security mechanism.
        const fields: Record<string, string | number> = {
          amount: data.formData.amount,
          tax_amount: data.formData.tax_amount,
          product_service_charge: data.formData.product_service_charge,
          product_delivery_charge: data.formData.product_delivery_charge,
          total_amount: data.formData.total_amount,
          transaction_uuid: data.formData.transaction_uuid,
          product_code: data.formData.product_code,
          signature: data.formData.signature,
          signed_field_names: data.formData.signed_field_names,
          success_url: data.formData.success_url,
          failure_url: data.formData.failure_url,
        };

        for (const [key, value] of Object.entries(fields)) {
          const input = document.createElement("input");
          input.type = "hidden";
          input.name = key;
          input.value = String(value);
          form.appendChild(input);
        }

        // Append to body and submit
        document.body.appendChild(form);
        formRef.current = form;

        // Small delay to ensure DOM is ready before submit
        await new Promise((resolve) => setTimeout(resolve, 50));

        form.submit();

        // NOTE: setLoading(false) is NOT called here because the browser
        // is navigating away to eSewa. The loading state will naturally
        // reset when the component unmounts during navigation. If the
        // navigation somehow fails (popup blocker, etc.), the catch
        // block below will handle cleanup.
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Payment initiation failed";
        setError(message);
        setLoading(false);
        console.error("useEsewaPayment error:", message);
      }
    },
    [],
  );

  return {
    initiatePayment,
    loading,
    error,
    clearError,
    lastPaymentId,
    lastResolvedPrice,
  };
}
