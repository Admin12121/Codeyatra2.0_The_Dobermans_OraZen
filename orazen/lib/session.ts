import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "./auth";

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

export async function getOptionalSession(): Promise<SessionWithUser | null> {
  const session = await auth.api.getSession({
    headers: await headers(),
  });

  return session as SessionWithUser | null;
}


export async function getRequiredSession(): Promise<SessionWithUser> {
  const session = await getOptionalSession();

  if (!session) {
    redirect("/login");
  }

  return session;
}


export async function getSessionToken(): Promise<string | null> {
  const session = await getOptionalSession();
  return session?.session.token ?? null;
}


export async function requiresTwoFactor(): Promise<boolean> {
  const session = await getOptionalSession();
  return session?.user.twoFactorEnabled ?? false;
}
