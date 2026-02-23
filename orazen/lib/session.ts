import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "./auth";

// Type for session with user
export type SessionWithUser = {
  session: {
    id: string;
    token: string;
    userId: string;
    expiresAt: Date;
    ipAddress?: string | null;
    userAgent?: string | null;
  };
  user: {
    id: string;
    name: string | null;
    email: string;
    emailVerified: boolean;
    image: string | null;
    createdAt: Date;
    updatedAt: Date;
    twoFactorEnabled: boolean;
  };
};

/**
 * Get the current session (optional - returns null if not authenticated)
 * Use this in server components where authentication is optional
 */
export async function getOptionalSession(): Promise<SessionWithUser | null> {
  const session = await auth.api.getSession({
    headers: await headers(),
  });

  return session as SessionWithUser | null;
}

/**
 * Get the current session (required - redirects to login if not authenticated)
 * Use this in server components that require authentication
 */
export async function getRequiredSession(): Promise<SessionWithUser> {
  const session = await getOptionalSession();

  if (!session) {
    redirect("/login");
  }

  return session;
}

/**
 * Get the session token for API calls
 * Returns null if not authenticated
 */
export async function getSessionToken(): Promise<string | null> {
  const session = await getOptionalSession();
  return session?.session.token ?? null;
}

/**
 * Check if user has two-factor enabled
 */
export async function requiresTwoFactor(): Promise<boolean> {
  const session = await getOptionalSession();
  return session?.user.twoFactorEnabled ?? false;
}
