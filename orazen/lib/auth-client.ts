"use client";

import { createAuthClient } from "better-auth/react";
import { twoFactorClient } from "better-auth/client/plugins";
import { passkeyClient } from "@better-auth/passkey/client";

function resolveBaseURL(): string {
  const envUrl = process.env.NEXT_PUBLIC_APP_URL;
  if (envUrl && !envUrl.includes("localhost")) {
    return envUrl;
  }
  if (typeof window !== "undefined") {
    return window.location.origin;
  }
  return envUrl || "http://localhost:3000";
}

export const authClient = createAuthClient({
  baseURL: resolveBaseURL(),
  plugins: [twoFactorClient(), passkeyClient()],
});

export const {
  signIn,
  signUp,
  signOut,
  useSession,
  getSession,
  twoFactor,
  passkey,
} = authClient;


export type Session = typeof authClient.$Infer.Session;
export type User = typeof authClient.$Infer.Session.user;
