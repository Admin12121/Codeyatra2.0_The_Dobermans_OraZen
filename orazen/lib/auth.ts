import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { twoFactor } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { nextCookies } from "better-auth/next-js";
import { db } from "./db";
import { schema } from "@/db/schema";

const githubClientId = process.env.GITHUB_CLIENT_ID;
const githubClientSecret = process.env.GITHUB_CLIENT_SECRET;
const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;

// Explicit whitelist from env (comma-separated), if provided.
// e.g. BETTER_AUTH_TRUSTED_ORIGINS="https://guard.example.com,http://10.0.0.5"
const explicitOrigins: string[] = process.env.BETTER_AUTH_TRUSTED_ORIGINS
  ? process.env.BETTER_AUTH_TRUSTED_ORIGINS.split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  : [];

/**
 * Check whether a hostname belongs to a private / loopback network.
 *
 * Matches:
 *   - localhost, 127.x.x.x          (loopback)
 *   - 10.x.x.x                      (Class A private)
 *   - 172.16.x.x – 172.31.x.x      (Class B private)
 *   - 192.168.x.x                   (Class C private)
 *   - [::1]                          (IPv6 loopback)
 */
function isPrivateNetworkHost(hostname: string): boolean {
  if (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname === "::1"
  ) {
    return true;
  }

  // 10.x.x.x
  if (hostname.startsWith("10.")) return true;

  // 192.168.x.x
  if (hostname.startsWith("192.168.")) return true;

  // 172.16.0.0 – 172.31.255.255
  if (hostname.startsWith("172.")) {
    const second = parseInt(hostname.split(".")[1], 10);
    if (second >= 16 && second <= 31) return true;
  }

  // 127.x.x.x (full loopback range)
  if (hostname.startsWith("127.")) return true;

  return false;
}

/**
 * Determine whether an origin should be trusted for CSRF protection.
 *
 * - Any origin on a private / loopback network is automatically trusted
 *   (this is a self-hosted tool — LAN access is expected).
 * - Any origin listed in BETTER_AUTH_TRUSTED_ORIGINS env var is trusted.
 * - In production, set BETTER_AUTH_TRUSTED_ORIGINS to a strict whitelist
 *   and the private-network fallback still applies for internal access.
 */
function isTrustedOrigin(origin: string): boolean {
  // Explicit whitelist match
  if (explicitOrigins.includes(origin)) return true;

  try {
    const url = new URL(origin);
    return isPrivateNetworkHost(url.hostname);
  } catch {
    return false;
  }
}

export const auth = betterAuth({
  database: drizzleAdapter(db, {
    provider: "pg",
    schema,
  }),

  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false,
  },

  socialProviders: {
    ...(githubClientId && githubClientSecret
      ? {
          github: {
            clientId: githubClientId,
            clientSecret: githubClientSecret,
          },
        }
      : {}),
    ...(googleClientId && googleClientSecret
      ? {
          google: {
            clientId: googleClientId,
            clientSecret: googleClientSecret,
          },
        }
      : {}),
  },

  session: {
    expiresIn: 60 * 60 * 24 * 7,
    updateAge: 60 * 60 * 24,
    cookieCache: {
      enabled: true,
      maxAge: 60 * 5,
    },
  },

  plugins: [
    twoFactor({
      issuer: "Orazen",
    }),
    passkey({
      rpID: process.env.PASSKEY_RP_ID || "localhost",
      rpName: process.env.PASSKEY_RP_NAME || "Orazen",
      // Do NOT set `origin` to a fixed string — WebAuthn binds credentials
      // to the exact browser origin (protocol + host + port).  When omitted
      // (or null), the plugin reads the request's Origin header, which is
      // guaranteed to match the origin the browser used when creating the
      // credential.  CSRF protection is handled separately by trustedOrigins.
      origin: null,
    }),
    nextCookies(),
  ],

  // Dynamic origin trust: automatically allows private-network IPs
  // so LAN devices can access the dashboard without configuration.
  // For public deployments, set BETTER_AUTH_TRUSTED_ORIGINS to a
  // strict comma-separated whitelist.
  trustedOrigins: async (request) => {
    // Start with standard localhost origins
    const origins: string[] = [
      "http://localhost",
      "http://localhost:3000",
      "http://127.0.0.1",
      "http://127.0.0.1:3000",
    ];

    // Add any explicitly configured origins
    origins.push(...explicitOrigins);

    // Extract the request's Origin header and trust it if it's
    // from a private network (LAN IP, loopback, etc.)
    const origin = request?.headers.get("origin");
    if (origin && isTrustedOrigin(origin) && !origins.includes(origin)) {
      origins.push(origin);
    }

    return origins;
  },
});

export type Auth = typeof auth;
