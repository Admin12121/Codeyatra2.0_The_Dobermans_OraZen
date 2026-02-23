import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { headers } from "next/headers";

const RUST_API_URL = process.env.RUST_API_URL || "http://localhost:8080";

const SAFE_ERRORS: Record<number, { error: string; code: string }> = {
  401: { error: "Not authenticated", code: "SESSION_REQUIRED" },
  403: { error: "Access denied", code: "FORBIDDEN" },
  404: { error: "Ticket service unavailable", code: "NOT_FOUND" },
  429: { error: "Too many requests", code: "RATE_LIMITED" },
  500: { error: "Ticket creation failed", code: "TICKET_ERROR" },
};

function safeError(status: number) {
  return (
    SAFE_ERRORS[status] ?? {
      error: "Ticket creation failed",
      code: "TICKET_ERROR",
    }
  );
}

export async function POST() {
  try {
    const session = await auth.api.getSession({
      headers: await headers(),
    });

    if (!session?.session?.token) {
      return NextResponse.json(
        { error: "Not authenticated", code: "SESSION_REQUIRED" },
        { status: 401 },
      );
    }

    const sessionToken = session.session.token;
    const res = await fetch(`${RUST_API_URL}/v1/guard/events/ticket`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${sessionToken}`,
        "Content-Type": "application/json",
      },
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) {
      const upstream = await res.text().catch(() => "<unreadable>");
      console.error(
        "[api/guard/events/ticket] Upstream %d: %s",
        res.status,
        upstream,
      );
      const mapped = safeError(res.status);
      return NextResponse.json(mapped, { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json({
      ticket: data.ticket,
      expires_in: data.expires_in,
    });
  } catch (err) {
    console.error("[api/guard/events/ticket] Error:", err);
    return NextResponse.json(
      { error: "Internal server error", code: "INTERNAL_ERROR" },
      { status: 500 },
    );
  }
}
