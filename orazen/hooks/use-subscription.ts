"use client";

import { useState, useEffect, useCallback } from "react";

// ============================================================
// Subscription Status Hook
// ============================================================
// Fetches the current user's subscription status from
// /api/esewa/status and caches it for the component lifetime.
// Provides a `refresh` method to re-fetch after payment.
// ============================================================

export interface SubscriptionPlan {
  id: string;
  name: string;
  tagline: string;
  badgeClass: string;
}

export interface LastPayment {
  id: string;
  amount: number;
  status: string;
  planId: string;
  esewaRefId: string | null;
  createdAt: string | null;
  periodStart: string | null;
  periodEnd: string | null;
}

export interface SubscriptionStatus {
  /** Whether the user has an active paid subscription */
  subscribed: boolean;
  /** Resolved plan details */
  plan: SubscriptionPlan;
  /** Raw subscription status: "active" | "expired" | "cancelled" | "past_due" | "none" */
  status: string;
  /** ISO 8601 start of current billing period */
  currentPeriodStart: string | null;
  /** ISO 8601 end of current billing period */
  currentPeriodEnd: string | null;
  /** Whether the plan is a paid tier (starter, pro, enterprise) */
  isPaid: boolean;
  /** Whether auto-renew is enabled */
  autoRenew: boolean;
  /** Most recent payment record */
  lastPayment: LastPayment | null;
}

interface UseSubscriptionReturn {
  /** Subscription data (null while loading or on error) */
  subscription: SubscriptionStatus | null;
  /** Whether the initial fetch is in progress */
  loading: boolean;
  /** Error message if the fetch failed */
  error: string | null;
  /** Whether the user is on an active paid plan */
  isSubscribed: boolean;
  /** The current plan ID (e.g. "free_trial", "starter", "pro") */
  planId: string;
  /** The current plan display name */
  planName: string;
  /** Re-fetch subscription status (e.g. after payment) */
  refresh: () => Promise<void>;
}

/**
 * Hook to fetch and track the current user's subscription status.
 *
 * Usage:
 * ```
 * const { isSubscribed, planName, loading } = useSubscription();
 * ```
 */
export function useSubscription(): UseSubscriptionReturn {
  const [subscription, setSubscription] = useState<SubscriptionStatus | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch("/api/esewa/status", {
        method: "GET",
        credentials: "include",
        headers: {
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        // 401 means not logged in — not an error per se
        if (response.status === 401) {
          setSubscription(null);
          return;
        }
        const body: unknown = await response.json().catch(() => null);
        const errorMessage =
          body &&
          typeof body === "object" &&
          "error" in body &&
          typeof body.error === "string"
            ? body.error
            : `Status check failed: ${response.status}`;
        throw new Error(errorMessage);
      }

      const data: SubscriptionStatus = await response.json();
      setSubscription(data);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch subscription";
      setError(message);
      console.error("useSubscription error:", message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  // Derived convenience values
  const isSubscribed = subscription?.subscribed ?? false;
  const planId = subscription?.plan?.id ?? "free_trial";
  const planName = subscription?.plan?.name ?? "Free Trial";

  return {
    subscription,
    loading,
    error,
    isSubscribed,
    planId,
    planName,
    refresh: fetchStatus,
  };
}
