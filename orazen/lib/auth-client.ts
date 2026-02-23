"use client";

import { createAuthClient } from "better-auth/react";
import { twoFactorClient } from "better-auth/client/plugins";
import { passkeyClient } from "@better-auth/passkey/client";

// Resolve the base URL for the auth client at runtime.
// NEXT_PUBLIC_APP_URL is baked at build time — if it's set and not a
// localhost placeholder, use it.  Otherwise fall back to the browser's
// current origin so the app works on any host (LAN IP, custom domain, etc.)
// without rebuilding.
function resolveBaseURL(): string {
  // Build-time env var (only available if set during `next build`)
  const envUrl = process.env.NEXT_PUBLIC_APP_URL;
  if (envUrl && !envUrl.includes("localhost")) {
    return envUrl;
  }
  // Runtime: use whatever origin the browser is on right now
  if (typeof window !== "undefined") {
    return window.location.origin;
  }
  // SSR fallback (shouldn't be reached in "use client" modules)
  return envUrl || "http://localhost:3000";
}

// Better Auth React client with plugins
export const authClient = createAuthClient({
  baseURL: resolveBaseURL(),
  plugins: [twoFactorClient(), passkeyClient()],
});

// Export convenience methods
export const {
  signIn,
  signUp,
  signOut,
  useSession,
  getSession,
  // Two-factor methods
  twoFactor,
  // Passkey methods
  passkey,
} = authClient;

// Type exports
export type Session = typeof authClient.$Infer.Session;
export type User = typeof authClient.$Infer.Session.user;
