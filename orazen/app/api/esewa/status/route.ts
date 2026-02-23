// ============================================================
// GET /api/esewa/status
// ============================================================
// Returns the current user's subscription status including:
//   - Current plan ID and name
//   - Subscription status (active, expired, cancelled, etc.)
//   - Billing period start/end
//   - Whether the user is on a paid plan
//   - Last payment details
//
// Used by the frontend to show "Pro" badges, gate features,
// and display subscription info in the account/billing page.
// ============================================================

import { NextResponse } from "next/server";
import { headers } from "next/headers";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { subscription, payment } from "@/db/schema";
import { eq, desc } from "drizzle-orm";
import { resolvePlan } from "@/lib/plans";

export async function GET() {
  try {
    // ── 1. Authenticate ──────────────────────────────────────
    const session = await auth.api.getSession({
      headers: await headers(),
    });

    if (!session?.user?.id) {
      return NextResponse.json(
        { error: "Authentication required" },
        { status: 401 }
      );
    }

    const userId = session.user.id;

    // ── 2. Fetch subscription ────────────────────────────────
    const subscriptions = await db
      .select()
      .from(subscription)
      .where(eq(subscription.userId, userId))
      .limit(1);

    // No subscription found — user is on free trial
    if (subscriptions.length === 0) {
      const freePlan = resolvePlan("free_trial");

      return NextResponse.json({
        subscribed: false,
        plan: {
          id: freePlan.id,
          name: freePlan.name,
          tagline: freePlan.tagline,
          badgeClass: freePlan.badgeClass,
        },
        status: "none",
        currentPeriodStart: null,
        currentPeriodEnd: null,
        isPaid: false,
        autoRenew: false,
        lastPayment: null,
      });
    }

    const sub = subscriptions[0];

    // ── 3. Check if subscription is expired ──────────────────
    const now = new Date();
    const isExpired =
      sub.status === "active" && new Date(sub.currentPeriodEnd) < now;

    // If expired, update the status in DB
    if (isExpired) {
      await db
        .update(subscription)
        .set({
          status: "expired",
          updatedAt: now,
        })
        .where(eq(subscription.userId, userId));

      sub.status = "expired";
    }

    const isActive = sub.status === "active";
    const plan = resolvePlan(sub.planId);
    const isPaid = plan.order >= 1;

    // ── 4. Fetch last payment info ───────────────────────────
    let lastPayment = null;

    const payments = await db
      .select({
        id: payment.id,
        amount: payment.totalAmount,
        status: payment.status,
        planId: payment.planId,
        esewaRefId: payment.esewaRefId,
        createdAt: payment.createdAt,
        periodStart: payment.periodStart,
        periodEnd: payment.periodEnd,
      })
      .from(payment)
      .where(eq(payment.userId, userId))
      .orderBy(desc(payment.createdAt))
      .limit(1);

    if (payments.length > 0) {
      const p = payments[0];
      lastPayment = {
        id: p.id,
        amount: p.amount,
        status: p.status,
        planId: p.planId,
        esewaRefId: p.esewaRefId,
        createdAt: p.createdAt?.toISOString() ?? null,
        periodStart: p.periodStart?.toISOString() ?? null,
        periodEnd: p.periodEnd?.toISOString() ?? null,
      };
    }

    // ── 5. Return subscription status ────────────────────────
    return NextResponse.json({
      subscribed: isActive && isPaid,
      plan: {
        id: plan.id,
        name: plan.name,
        tagline: plan.tagline,
        badgeClass: plan.badgeClass,
      },
      status: sub.status,
      currentPeriodStart: sub.currentPeriodStart?.toISOString() ?? null,
      currentPeriodEnd: sub.currentPeriodEnd?.toISOString() ?? null,
      isPaid,
      autoRenew: sub.autoRenew,
      lastPayment,
    });
  } catch (error) {
    console.error("eSewa status error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
