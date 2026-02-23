// ============================================================
// POST /api/esewa/initiate
// ============================================================
// Accepts a tierIndex (0–8) and column ("guard" | "full"),
// resolves the price from the server-side PRICING_TABLE, creates
// a pending payment record, generates signed eSewa form data,
// and returns it so the client can redirect to eSewa.
//
// SECURITY:
//   - Price is NEVER accepted from the client
//   - Price is resolved server-side from PRICING_TABLE
//   - tierIndex and column are validated against known values
//   - Transaction UUID uses crypto.randomUUID() (CSPRNG)
//   - Redirect URLs are built from env vars, not request headers
//   - Pending payments expire after 30 minutes
//   - Duplicate active subscriptions are rejected
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { headers } from "next/headers";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { payment, subscription } from "@/db/schema";
import { eq, and } from "drizzle-orm";
import {
  buildPaymentFormData,
  generateTransactionUuid,
  getEsewaConfig,
  getSafeBaseUrl,
  resolveTierPrice,
  isPaymentExpired,
  type PricingColumn,
} from "@/lib/esewa";

// Rate limiting: track recent initiation attempts per user (in-memory, resets on deploy)
const recentAttempts = new Map<string, { count: number; resetAt: number }>();
const MAX_ATTEMPTS_PER_MINUTE = 5;

function checkRateLimit(userId: string): boolean {
  const now = Date.now();
  const entry = recentAttempts.get(userId);

  if (!entry || now > entry.resetAt) {
    recentAttempts.set(userId, { count: 1, resetAt: now + 60_000 });
    return true;
  }

  if (entry.count >= MAX_ATTEMPTS_PER_MINUTE) {
    return false;
  }

  entry.count++;
  return true;
}

// Cleanup stale rate limit entries periodically (prevent memory leak)
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of recentAttempts) {
    if (now > val.resetAt) recentAttempts.delete(key);
  }
}, 5 * 60_000); // every 5 minutes

export async function POST(request: NextRequest) {
  try {
    // ── 1. Authenticate ──────────────────────────────────────
    const session = await auth.api.getSession({
      headers: await headers(),
    });

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: "Authentication required" },
        { status: 401 },
      );
    }

    const userId = session.user.id;

    // ── 2. Rate limit ────────────────────────────────────────
    if (!checkRateLimit(userId)) {
      return NextResponse.json(
        { error: "Too many payment attempts. Please wait a minute." },
        { status: 429 },
      );
    }

    // ── 3. Parse & validate request body ─────────────────────
    const body = await request.json().catch(() => null);

    if (!body) {
      return NextResponse.json(
        { error: "Invalid request body" },
        { status: 400 },
      );
    }

    const { tierIndex, column } = body as {
      tierIndex: unknown;
      column: unknown;
    };

    // Validate tierIndex is an integer
    if (
      typeof tierIndex !== "number" ||
      !Number.isInteger(tierIndex) ||
      tierIndex < 0 ||
      tierIndex > 8
    ) {
      return NextResponse.json(
        { error: "Invalid tierIndex. Must be an integer between 0 and 8." },
        { status: 400 },
      );
    }

    // Validate column
    if (column !== "guard" && column !== "full") {
      return NextResponse.json(
        { error: 'Invalid column. Must be "guard" or "full".' },
        { status: 400 },
      );
    }

    const validColumn = column as PricingColumn;

    // ── 4. Resolve price from server-side pricing table ──────
    //
    // SECURITY: The price is NEVER provided by the client.
    // We look up the exact price from our hardcoded server-side
    // PRICING_TABLE using the tier index + column. If the combination
    // is not found (e.g., 5K guard = free, or 1M+ = enterprise),
    // we reject the request.
    //
    const pricePoint = resolveTierPrice(tierIndex, validColumn);

    if (!pricePoint) {
      // This tier/column combination is either free or enterprise
      if (tierIndex === 0 && validColumn === "guard") {
        return NextResponse.json(
          { error: "This tier is free. No payment required." },
          { status: 400 },
        );
      }
      if (tierIndex === 8) {
        return NextResponse.json(
          {
            error:
              "Enterprise plans require a custom quote. Please contact sales.",
          },
          { status: 400 },
        );
      }
      return NextResponse.json(
        { error: "Invalid tier/column combination." },
        { status: 400 },
      );
    }

    // ── 5. Check for active subscription ─────────────────────
    // Prevent duplicate payments if user already has an active
    // subscription at the same or higher plan level.
    const existingSubs = await db
      .select()
      .from(subscription)
      .where(
        and(eq(subscription.userId, userId), eq(subscription.status, "active")),
      )
      .limit(1);

    if (existingSubs.length > 0) {
      const sub = existingSubs[0];
      const isStillActive = new Date(sub.currentPeriodEnd) > new Date();

      if (isStillActive) {
        // Allow upgrade (starter → pro) but block same-plan repurchase
        const planRank = { free_trial: 0, starter: 1, pro: 2, enterprise: 3 };
        const currentRank = planRank[sub.planId as keyof typeof planRank] ?? 0;
        const targetRank =
          planRank[pricePoint.planId as keyof typeof planRank] ?? 0;

        if (targetRank <= currentRank) {
          return NextResponse.json(
            {
              error: `You already have an active ${sub.planId} subscription until ${sub.currentPeriodEnd.toISOString().split("T")[0]}. ${
                targetRank < currentRank
                  ? "You cannot downgrade while your current plan is active."
                  : "Wait for it to expire or contact support."
              }`,
            },
            { status: 409 },
          );
        }
        // Upgrading is allowed — proceed
      }
    }

    // ── 6. Expire stale pending payments ─────────────────────
    // Mark any old pending payments as expired to keep the DB clean
    // and prevent confusion.
    const stalePending = await db
      .select({ id: payment.id, createdAt: payment.createdAt })
      .from(payment)
      .where(and(eq(payment.userId, userId), eq(payment.status, "pending")));

    for (const stale of stalePending) {
      if (stale.createdAt && isPaymentExpired(stale.createdAt)) {
        await db
          .update(payment)
          .set({ status: "expired", updatedAt: new Date() })
          .where(eq(payment.id, stale.id));
      }
    }

    // ── 7. Generate transaction UUID and build form data ─────
    const transactionUuid = generateTransactionUuid();
    const taxAmount = 0; // No tax for now
    const totalAmount = pricePoint.amount + taxAmount;

    // Build redirect URLs from env vars (safe, not from request headers)
    const baseUrl = getSafeBaseUrl(request);

    const successUrl = `${baseUrl}/api/esewa/verify`;
    const failureUrl = `${baseUrl}/account`;

    const formData = buildPaymentFormData({
      amount: pricePoint.amount,
      taxAmount,
      transactionUuid,
      successUrl,
      failureUrl,
    });

    // ── 8. Create pending payment record ─────────────────────
    const paymentId = crypto.randomUUID();
    const now = new Date();

    await db.insert(payment).values({
      id: paymentId,
      userId,
      transactionUuid,
      productCode: formData.product_code,
      planId: pricePoint.planId,
      amount: pricePoint.amount,
      taxAmount,
      totalAmount,
      status: "pending",
      createdAt: now,
      updatedAt: now,
    });

    // ── 9. Return form data + payment URL ────────────────────
    //
    // NOTE: We return the paymentUrl here for the client to submit
    // the form to. The form data is HMAC-signed by our secret key,
    // so even if an attacker intercepts it, they cannot modify the
    // amount, transaction UUID, or redirect URLs without invalidating
    // the signature. eSewa will reject any tampered submission.
    //
    const config = getEsewaConfig();

    return NextResponse.json({
      success: true,
      paymentId,
      transactionUuid,
      // Return the resolved price so the UI can show a confirmation
      // (this is for display only — the actual charge is in the signed form)
      resolvedPrice: {
        amount: pricePoint.amount,
        planId: pricePoint.planId,
        tierLabel: pricePoint.tierLabel,
      },
      formData,
      paymentUrl: config.paymentUrl,
    });
  } catch (error) {
    console.error("eSewa initiate error:", error);

    // Don't leak internal error details to the client
    const message =
      error instanceof Error && error.message.includes("environment variable")
        ? "Payment service is not configured. Please contact support."
        : "Internal server error";

    return NextResponse.json({ error: message }, { status: 500 });
  }
}
