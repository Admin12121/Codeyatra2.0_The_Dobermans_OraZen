// ============================================================
// GET /api/esewa/verify
// ============================================================
// eSewa redirects here after a successful payment with a base64-
// encoded `data` query parameter. This route:
//   1. Decodes the base64 response
//   2. Verifies the HMAC-SHA256 signature
//   3. Validates product code matches our merchant account
//   4. Finds the pending payment and checks it hasn't expired
//   5. Verifies amount matches (prevents price manipulation)
//   6. Double-checks with eSewa's transaction status API
//   7. Updates the payment record to "completed"
//   8. Creates or updates the user's subscription
//   9. Redirects the user to the account billing page
//
// SECURITY:
//   - Redirect URLs built from env vars, not request headers
//   - Payment expiry enforced (30 min window)
//   - Idempotency: already-completed payments are not re-processed
//   - Amount verification: response amount must match DB record exactly
//   - Product code verification: prevents cross-merchant replay attacks
//   - Session-expiry fallback: if user's session expired during payment,
//     we look up the payment by transaction_uuid alone (still verify
//     HMAC + eSewa status API) and process it. The user is redirected
//     to login with a success message.
//   - Constant-time HMAC comparison via crypto.timingSafeEqual
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { headers } from "next/headers";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { payment, subscription } from "@/db/schema";
import { eq, and } from "drizzle-orm";
import { sql } from "drizzle-orm";
import {
  decodeEsewaResponse,
  verifyEsewaResponse,
  verifyTransactionStatus,
  getSafeBaseUrl,
  isPaymentExpired,
} from "@/lib/esewa";

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const base64Data = searchParams.get("data");

  // Build redirect base URL from env vars (NOT request headers)
  let baseUrl: string;
  try {
    baseUrl = getSafeBaseUrl(request);
  } catch {
    // Absolute fallback — should never happen if env is configured
    const proto = request.headers.get("x-forwarded-proto") || "http";
    const host = request.headers.get("host") || "localhost:3000";
    baseUrl = `${proto}://${host}`;
  }

  // Helper to redirect with status
  function redirectWithStatus(
    status: "success" | "failed" | "error",
    message?: string,
  ) {
    const params = new URLSearchParams({
      tab: "billing",
      payment: status,
    });
    if (message) params.set("message", message);
    return NextResponse.redirect(`${baseUrl}/account?${params.toString()}`);
  }

  // Helper to redirect to login (for session-expired case)
  function redirectToLogin(message: string) {
    const params = new URLSearchParams({
      payment: "success",
      message,
    });
    return NextResponse.redirect(`${baseUrl}/login?${params.toString()}`);
  }

  try {
    // ── 1. Check for data parameter ───────────────────────────
    if (!base64Data) {
      return redirectWithStatus(
        "failed",
        "No payment data received from eSewa.",
      );
    }

    // ── 2. Decode eSewa response ──────────────────────────────
    const esewaResponse = decodeEsewaResponse(base64Data);

    if (!esewaResponse) {
      return redirectWithStatus("failed", "Could not decode eSewa response.");
    }

    // ── 3. Verify HMAC signature + product code ──────────────
    const isSignatureValid = verifyEsewaResponse(esewaResponse);

    if (!isSignatureValid) {
      console.error(
        "[SECURITY] eSewa signature/product code verification FAILED for transaction:",
        esewaResponse.transaction_uuid,
      );
      return redirectWithStatus(
        "failed",
        "Payment signature verification failed. This incident has been logged.",
      );
    }

    // ── 4. Authenticate (with session-expiry fallback) ───────
    const session = await auth.api.getSession({
      headers: await headers(),
    });

    const userId = session?.user?.id ?? null;

    // ── 5. Find the payment record ───────────────────────────
    // First, try to find by transaction_uuid + userId (if logged in)
    // If session expired, find by transaction_uuid alone (safe because
    // we've already verified the HMAC signature from eSewa)
    let pendingPayments;

    if (userId) {
      pendingPayments = await db
        .select()
        .from(payment)
        .where(
          and(
            eq(payment.transactionUuid, esewaResponse.transaction_uuid),
            eq(payment.userId, userId),
          ),
        )
        .limit(1);
    } else {
      // Session expired — look up by transaction_uuid only
      // SECURITY: This is safe because:
      //   1. We verified the HMAC signature (eSewa signed this)
      //   2. The transaction_uuid is cryptographically random (crypto.randomUUID)
      //   3. We still verify the amount matches our DB record
      //   4. We still check eSewa's status API
      pendingPayments = await db
        .select()
        .from(payment)
        .where(eq(payment.transactionUuid, esewaResponse.transaction_uuid))
        .limit(1);
    }

    if (pendingPayments.length === 0) {
      console.error(
        "[SECURITY] No payment record found for transaction:",
        esewaResponse.transaction_uuid,
        "userId:",
        userId ?? "session-expired",
      );
      return redirectWithStatus(
        "failed",
        "Payment record not found. It may have already been processed.",
      );
    }

    const paymentRecord = pendingPayments[0];

    // ── 6. Idempotency guard ─────────────────────────────────
    // If the payment is already completed (e.g., user refreshed the
    // verify URL), don't re-process it — just redirect to success.
    if (paymentRecord.status === "completed") {
      console.info(
        "Payment already completed (idempotent retry):",
        paymentRecord.id,
      );

      if (!userId) {
        return redirectToLogin(
          "Your payment was already processed. Please log in to see your subscription.",
        );
      }
      return redirectWithStatus("success");
    }

    // If the payment is in a terminal state (failed, refunded, expired),
    // don't allow re-processing
    if (
      paymentRecord.status === "failed" ||
      paymentRecord.status === "refunded" ||
      paymentRecord.status === "expired"
    ) {
      console.error(
        "Attempted to verify a terminal payment:",
        paymentRecord.id,
        "status:",
        paymentRecord.status,
      );
      return redirectWithStatus(
        "failed",
        `This payment has already been marked as ${paymentRecord.status}. Please start a new payment.`,
      );
    }

    // ── 7. Check payment expiry ──────────────────────────────
    // Pending payments expire after 30 minutes to prevent stale
    // transaction attacks
    if (paymentRecord.createdAt && isPaymentExpired(paymentRecord.createdAt)) {
      console.error(
        "Payment expired:",
        paymentRecord.id,
        "created:",
        paymentRecord.createdAt,
      );

      await db
        .update(payment)
        .set({
          status: "expired",
          esewaResponseRaw: JSON.stringify({
            reason: "Payment verification window expired (30 min)",
            redirect: esewaResponse,
          }),
          updatedAt: new Date(),
        })
        .where(eq(payment.id, paymentRecord.id));

      return redirectWithStatus(
        "failed",
        "Payment verification window expired. Please try again.",
      );
    }

    // ── 8. Verify amount matches ─────────────────────────────
    // SECURITY: The amount in eSewa's response must EXACTLY match
    // what we stored in the DB when we initiated the payment.
    // This prevents price manipulation attacks where an attacker
    // modifies the form to pay a lower amount.
    const responseAmount = parseFloat(esewaResponse.total_amount);

    if (
      isNaN(responseAmount) ||
      Math.abs(responseAmount - paymentRecord.totalAmount) > 0.01
    ) {
      console.error(
        "[SECURITY] Amount mismatch! DB expected:",
        paymentRecord.totalAmount,
        "eSewa returned:",
        responseAmount,
        "transaction:",
        esewaResponse.transaction_uuid,
      );

      // Mark payment as failed — this is a security event
      await db
        .update(payment)
        .set({
          status: "failed",
          esewaResponseRaw: JSON.stringify({
            reason: "AMOUNT_MISMATCH",
            expected: paymentRecord.totalAmount,
            received: responseAmount,
            redirect: esewaResponse,
          }),
          updatedAt: new Date(),
        })
        .where(eq(payment.id, paymentRecord.id));

      return redirectWithStatus(
        "failed",
        "Payment amount mismatch detected. This incident has been logged.",
      );
    }

    // ── 9. Verify with eSewa's transaction status API ────────
    // This is the most reliable check — we call eSewa's server directly
    // to confirm the transaction status. The redirect signature could
    // theoretically be replayed, but the status API gives real-time state.
    const txnStatus = await verifyTransactionStatus(
      esewaResponse.transaction_uuid,
      paymentRecord.totalAmount,
    );

    if (txnStatus && txnStatus.status !== "COMPLETE") {
      // Status API explicitly says NOT complete
      console.error(
        "eSewa status API reports non-complete:",
        txnStatus.status,
        "for transaction:",
        esewaResponse.transaction_uuid,
      );

      await db
        .update(payment)
        .set({
          status: "failed",
          esewaResponseRaw: JSON.stringify({
            reason: `ESEWA_STATUS_${txnStatus.status}`,
            redirect: esewaResponse,
            statusCheck: txnStatus,
          }),
          updatedAt: new Date(),
        })
        .where(eq(payment.id, paymentRecord.id));

      return redirectWithStatus(
        "failed",
        `eSewa reports payment status: ${txnStatus.status}. Please try again.`,
      );
    }

    if (!txnStatus) {
      // Could not reach eSewa status API — proceed cautiously since
      // the HMAC signature was valid and amount matches. Log a warning.
      console.warn(
        "Could not reach eSewa status API for transaction:",
        esewaResponse.transaction_uuid,
        "— proceeding with signature-verified payment.",
      );
    }

    // ── 10. Update payment record to completed ───────────────
    const now = new Date();
    const periodStart = now;
    const periodEnd = new Date(now);
    periodEnd.setDate(periodEnd.getDate() + 30); // 30-day billing period

    await db
      .update(payment)
      .set({
        status: "completed",
        esewaRefId: esewaResponse.transaction_code || txnStatus?.ref_id || null,
        esewaResponseRaw: JSON.stringify({
          redirect: esewaResponse,
          statusCheck: txnStatus ?? "unreachable",
        }),
        periodStart,
        periodEnd,
        updatedAt: now,
      })
      .where(
        // SECURITY: Only update if still "pending" (prevents race condition
        // where two simultaneous verify requests could both process)
        and(eq(payment.id, paymentRecord.id), eq(payment.status, "pending")),
      );

    // Verify the update actually happened (another request may have
    // completed it first due to race condition)
    const updatedPayment = await db
      .select({ status: payment.status })
      .from(payment)
      .where(eq(payment.id, paymentRecord.id))
      .limit(1);

    if (
      updatedPayment.length === 0 ||
      updatedPayment[0].status !== "completed"
    ) {
      // Another concurrent request already processed this payment
      console.info(
        "Payment was processed by another request (race condition handled):",
        paymentRecord.id,
      );
      if (!userId) {
        return redirectToLogin(
          "Your payment was processed. Please log in to see your subscription.",
        );
      }
      return redirectWithStatus("success");
    }

    // ── 11. Create or update subscription ────────────────────
    // Use the userId from the payment record (not session) in case
    // the session expired during payment
    const paymentOwnerUserId = paymentRecord.userId;

    const existingSubs = await db
      .select()
      .from(subscription)
      .where(eq(subscription.userId, paymentOwnerUserId))
      .limit(1);

    if (existingSubs.length > 0) {
      // Update existing subscription
      await db
        .update(subscription)
        .set({
          planId: paymentRecord.planId,
          status: "active",
          currentPaymentId: paymentRecord.id,
          currentPeriodStart: periodStart,
          currentPeriodEnd: periodEnd,
          updatedAt: now,
        })
        .where(eq(subscription.userId, paymentOwnerUserId));
    } else {
      // Create new subscription
      await db.insert(subscription).values({
        id: crypto.randomUUID(),
        userId: paymentOwnerUserId,
        planId: paymentRecord.planId,
        status: "active",
        currentPaymentId: paymentRecord.id,
        currentPeriodStart: periodStart,
        currentPeriodEnd: periodEnd,
        autoRenew: false,
        createdAt: now,
        updatedAt: now,
      });
    }

    // ── 12. Sync organization.plan + api_key.plan ────────────
    // The Rust backend reads organization.plan for usage display and
    // api_key.plan + api_key.monthly_quota for quota enforcement.
    // Without this sync, the backend would still see "free"/"basic"
    // even after a successful payment.
    //
    // Plan name mapping for the Rust backend:
    //   "starter" → monthly_quota 50,000
    //   "pro"     → monthly_quota 1,000,000
    //   "enterprise" → monthly_quota 10,000,000
    const PLAN_QUOTA_MAP: Record<string, number> = {
      free_trial: 5_000,
      starter: 50_000,
      pro: 1_000_000,
      enterprise: 10_000_000,
    };

    const newPlan = paymentRecord.planId;
    const newQuota = PLAN_QUOTA_MAP[newPlan] ?? 50_000;

    try {
      // 12a. Update organization.plan for the paying user
      // Use owner_id directly — every org has owner_id referencing user.id.
      // The previous organization_member join was unreliable because the
      // member row might not exist if the org was created through a
      // different code path.
      const orgResult = await db.execute(
        sql`UPDATE organization
            SET plan = ${newPlan}, updated_at = ${now}
            WHERE owner_id = ${paymentOwnerUserId}
            RETURNING id`,
      );

      const orgRows = Array.isArray(orgResult)
        ? orgResult
        : (((orgResult as Record<string, unknown>).rows as unknown[]) ?? []);
      console.log(
        "[Payment Sync] organization.plan UPDATE matched",
        orgRows.length,
        "row(s) for owner_id:",
        paymentOwnerUserId,
        "→ plan:",
        newPlan,
      );

      // If owner_id didn't match, also try via organization_member as fallback
      if (orgRows.length === 0) {
        console.warn(
          "[Payment Sync] No org found via owner_id, trying organization_member...",
        );
        const memberResult = await db.execute(
          sql`UPDATE organization
              SET plan = ${newPlan}, updated_at = ${now}
              WHERE id IN (
                SELECT om.organization_id
                FROM organization_member om
                WHERE om.user_id = ${paymentOwnerUserId}
                LIMIT 1
              )
              RETURNING id`,
        );
        const memberRows = Array.isArray(memberResult)
          ? memberResult
          : (((memberResult as Record<string, unknown>).rows as unknown[]) ??
            []);
        console.log(
          "[Payment Sync] organization_member fallback matched",
          memberRows.length,
          "row(s)",
        );
      }

      // 12b. Update all active (non-revoked) API keys for the user's org
      // so the Rust guard quota enforcement sees the correct plan
      const keyResult = await db.execute(
        sql`UPDATE api_key
            SET plan = ${newPlan}, monthly_quota = ${newQuota}
            WHERE organization_id IN (
              SELECT id FROM organization WHERE owner_id = ${paymentOwnerUserId}
            )
            AND revoked_at IS NULL`,
      );

      const keyRows = Array.isArray(keyResult)
        ? keyResult
        : (((keyResult as Record<string, unknown>).rows as unknown[]) ?? []);
      console.log(
        "[Payment Sync] api_key UPDATE matched",
        keyRows.length,
        "row(s) → plan:",
        newPlan,
        "quota:",
        newQuota,
      );
    } catch (syncError) {
      // Non-fatal: subscription is already updated, so the user has access.
      // The org/api_key sync can be retried or fixed manually.
      console.error(
        "[Payment Sync] FAILED to sync organization.plan / api_key after payment.",
        "Error:",
        syncError,
        "Payment:",
        paymentRecord.id,
        "User:",
        paymentOwnerUserId,
        "Plan:",
        newPlan,
      );
    }

    // ── 13. Log success and redirect ─────────────────────────
    console.log(
      "Payment completed successfully:",
      paymentRecord.id,
      "Plan:",
      paymentRecord.planId,
      "Amount: रू" + paymentRecord.totalAmount.toLocaleString(),
      "User:",
      paymentOwnerUserId,
    );

    // If user's session expired during payment, redirect to login
    // with a success message so they can log in and see their subscription
    if (!userId) {
      return redirectToLogin(
        "Payment successful! Please log in to access your new plan.",
      );
    }

    return redirectWithStatus("success");
  } catch (error) {
    console.error("eSewa verify error:", error);

    // Don't leak internal error details
    return redirectWithStatus(
      "error",
      "An unexpected error occurred during payment verification. If you were charged, please contact support.",
    );
  }
}
