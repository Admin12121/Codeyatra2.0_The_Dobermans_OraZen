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

const explicitOrigins: string[] = process.env.BETTER_AUTH_TRUSTED_ORIGINS
  ? process.env.BETTER_AUTH_TRUSTED_ORIGINS.split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  : [];


function isPrivateNetworkHost(hostname: string): boolean {
  if (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname === "::1"
  ) {
    return true;
  }

  if (hostname.startsWith("10.")) return true;

  if (hostname.startsWith("192.168.")) return true;

  if (hostname.startsWith("172.")) {
    const second = parseInt(hostname.split(".")[1], 10);
    if (second >= 16 && second <= 31) return true;
  }

  if (hostname.startsWith("127.")) return true;

  return false;
}

function isTrustedOrigin(origin: string): boolean {
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
      issuer: "Orafinite",
    }),
    passkey({
      rpID: process.env.PASSKEY_RP_ID || "localhost",
      rpName: process.env.PASSKEY_RP_NAME || "Orafinite",
      origin: null,
    }),
    nextCookies(),
  ],

  trustedOrigins: async (request) => {
    const origins: string[] = [
      "http://localhost",
      "http://localhost:3000",
      "http://127.0.0.1",
      "http://127.0.0.1:3000",
    ];

    origins.push(...explicitOrigins);

    const origin = request?.headers.get("origin");
    if (origin && isTrustedOrigin(origin) && !origins.includes(origin)) {
      origins.push(origin);
    }

    return origins;
  },
});

export type Auth = typeof auth;
