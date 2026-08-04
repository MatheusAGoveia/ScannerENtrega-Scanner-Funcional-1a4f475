import { createHmac, timingSafeEqual } from "node:crypto";
import { NextRequest } from "next/server.js";

export interface SessionData {
  actor: string;
  role: string;
  exp?: number;
}

function getSecret(): string {
  return (
    process.env.SESSION_SECRET ||
    process.env.SCANNER_API_KEY ||
    "dev-session-secret-change-in-prod-2026"
  );
}

export function signSession(data: SessionData): string {
  const secret = getSecret();
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  const signature = createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

export function parseSession(token: string | undefined | null): SessionData | null {
  if (!token || !token.includes(".")) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload, signature] = parts;
  if (!payload || !signature) return null;

  const secret = getSecret();
  const expectedSig = createHmac("sha256", secret).update(payload).digest("base64url");

  if (signature.length !== expectedSig.length) return null;
  const sigBuf = Buffer.from(signature);
  const expectedBuf = Buffer.from(expectedSig);
  if (!timingSafeEqual(sigBuf, expectedBuf)) return null;

  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf-8")) as SessionData;
    if (data.exp && Date.now() / 1000 > data.exp) return null;
    return data;
  } catch {
    return null;
  }
}

export function getSessionFromRequest(request: NextRequest): SessionData | null {
  const cookie = request.cookies.get("scanner_session")?.value;
  if (cookie) {
    const parsed = parseSession(cookie);
    if (parsed) return parsed;
  }
  const authHeader = request.headers.get("Authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice(7).trim();
    const parsed = parseSession(token);
    if (parsed) return parsed;
  }
  // In development, if no explicit cookie is set, fallback to default operator session
  if (process.env.NODE_ENV !== "production" && process.env.DISABLE_DEV_FALLBACK !== "true") {
    return { actor: "operador-web", role: "operator" };
  }
  return null;
}

export function isOriginAllowed(request: NextRequest): boolean {
  if (["GET", "HEAD", "OPTIONS"].includes(request.method)) return true;

  const secFetchSite = request.headers.get("sec-fetch-site");
  if (secFetchSite === "cross-site") return false;

  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");
  const host = request.headers.get("host") || request.nextUrl?.host;

  if (origin) {
    try {
      const originHost = new URL(origin).host;
      if (host && originHost !== host) return false;
    } catch {
      return false;
    }
  } else if (referer) {
    try {
      const refererHost = new URL(referer).host;
      if (host && refererHost !== host) return false;
    } catch {
      return false;
    }
  }
  return true;
}
