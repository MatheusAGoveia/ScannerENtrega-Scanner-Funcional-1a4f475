import { createHmac, timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server.js";

export interface SessionData {
  actor: string;
  role: string;
  iat: number;
  exp: number;
}

function getSessionSecret(): string | null {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.trim() === "") {
    return null;
  }
  return secret;
}

function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

export function validateCredentials(
  username?: string,
  password?: string
): { success: boolean; actor?: string; role?: string; error?: string } {
  const expectedUser = process.env.SCANNER_AUTH_USER;
  const expectedPass = process.env.SCANNER_AUTH_PASS;
  const secret = getSessionSecret();

  if (!secret || !expectedUser || !expectedPass) {
    return { success: false, error: "Autenticacao nao configurada no servidor." };
  }

  if (!username || !password) {
    return { success: false, error: "Usuario e senha sao obrigatorios." };
  }

  const userOk = safeCompare(username, expectedUser);
  const passOk = safeCompare(password, expectedPass);

  if (userOk && passOk) {
    return { success: true, actor: username, role: "operator" };
  }
  return { success: false, error: "Credenciais invalidas." };
}

export function signSession(data: SessionData): string | null {
  const secret = getSessionSecret();
  if (!secret) return null;
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  const signature = createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

export function parseSession(token: string | undefined | null): SessionData | null {
  const secret = getSessionSecret();
  if (!secret || !token || !token.includes(".")) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload, signature] = parts;
  if (!payload || !signature) return null;

  const expectedSig = createHmac("sha256", secret).update(payload).digest("base64url");

  if (signature.length !== expectedSig.length) return null;
  const sigBuf = Buffer.from(signature);
  const expectedBuf = Buffer.from(expectedSig);
  if (!timingSafeEqual(sigBuf, expectedBuf)) return null;

  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf-8")) as SessionData;
    const now = Math.floor(Date.now() / 1000);

    if (!data.actor || !data.role || typeof data.iat !== "number" || typeof data.exp !== "number") {
      return null;
    }
    if (now >= data.exp) return null;

    return data;
  } catch {
    return null;
  }
}

export function getSessionFromRequest(request: NextRequest): SessionData | null {
  const cookie = request.cookies.get("scanner_session")?.value;
  if (!cookie) return null;
  return parseSession(cookie);
}

export function isOriginAllowed(request: NextRequest): boolean {
  if (["GET", "HEAD", "OPTIONS"].includes(request.method)) return true;

  const origin = request.headers.get("origin");
  const host = request.headers.get("host") || request.nextUrl?.host;

  if (!origin) return false;

  try {
    const originHost = new URL(origin).host;
    if (!host || originHost !== host) return false;
  } catch {
    return false;
  }
  return true;
}

export function setSessionCookie(response: NextResponse, token: string): void {
  const isProd = process.env.NODE_ENV === "production";
  response.cookies.set({
    name: "scanner_session",
    value: token,
    httpOnly: true,
    sameSite: "strict",
    secure: isProd,
    path: "/",
    maxAge: 28800,
  });
}

export function clearSessionCookie(response: NextResponse): void {
  const isProd = process.env.NODE_ENV === "production";
  response.cookies.set({
    name: "scanner_session",
    value: "",
    httpOnly: true,
    sameSite: "strict",
    secure: isProd,
    path: "/",
    maxAge: 0,
  });
}
