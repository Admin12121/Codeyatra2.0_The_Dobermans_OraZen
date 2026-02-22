import { NextResponse, type NextRequest } from "next/server";

const protectedRoutes = [
  "/dashboard",
  "/credentials",
  "/models",
  "/scanner",
  "/guard",
  "/reports",
  "/logs",
];

const authRoutes = ["/login"];

async function validateSession(request: NextRequest): Promise<boolean> {
  try {
    const sessionUrl = new URL("/api/auth/get-session", request.url);

    const res = await fetch(sessionUrl.toString(), {
      method: "GET",
      headers: {
        cookie: request.headers.get("cookie") || "",
      },
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) {
      return false;
    }

    const data = await res.json();

    return !!(data?.session && data?.user);
  } catch {
    return false;
  }
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  const isProtectedRoute = protectedRoutes.some(
    (route) => pathname === route || pathname.startsWith(`${route}/`),
  );

  const isAuthRoute = authRoutes.some(
    (route) => pathname === route || pathname.startsWith(`${route}/`),
  );

  if (!isProtectedRoute && !isAuthRoute) {
    return NextResponse.next();
  }

  const sessionCookie = request.cookies.get("better-auth.session_token");
  if (!sessionCookie?.value) {
    if (isProtectedRoute) {
      const loginUrl = new URL("/login", request.url);
      loginUrl.searchParams.set("callbackUrl", pathname);
      return NextResponse.redirect(loginUrl);
    }
    return NextResponse.next();
  }

  const isAuthenticated = await validateSession(request);

  if (isProtectedRoute && !isAuthenticated) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(loginUrl);
  }

  if (isAuthRoute && isAuthenticated) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|public|api).*)"],
};
