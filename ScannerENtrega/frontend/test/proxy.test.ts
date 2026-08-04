import assert from "node:assert";
import http from "node:http";
import { test } from "node:test";

import { NextRequest } from "next/server.js";
import { POST as loginHandler } from "../app/api/scanner/login/route.ts";
import { POST as logoutHandler } from "../app/api/scanner/logout/route.ts";
import { proxy } from "../app/api/scanner/[...path]/route.ts";
import { parseSession, signSession } from "../app/api/scanner/session.ts";

process.env.SCANNER_API_KEY = "test-frontend-secret-key-32-chars";
process.env.SESSION_SECRET = "test-session-secret-key-32-chars";
process.env.SCANNER_AUTH_USER = "admin-govsec";
process.env.SCANNER_AUTH_PASS = "senha-secreta-123";

function createMockRequest(
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    cookies?: Record<string, string>;
  } = {}
): NextRequest {
  const reqHeaders = new Headers(options.headers || {});
  if (options.cookies) {
    const cookieStr = Object.entries(options.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
    reqHeaders.set("cookie", cookieStr);
  }
  return new NextRequest(new URL(url, "http://localhost:3000"), {
    method: options.method || "GET",
    headers: reqHeaders,
    body: options.body,
  });
}

test("Auth - Login succeeds with valid credentials and sets HttpOnly cookie", async () => {
  const req = createMockRequest("http://localhost:3000/api/scanner/login", {
    method: "POST",
    headers: { "content-type": "application/json", origin: "http://localhost:3000" },
    body: JSON.stringify({ username: "admin-govsec", password: "senha-secreta-123" }),
  });
  const res = await loginHandler(req);
  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.success, true);
  assert.strictEqual(data.actor, "admin-govsec");

  const setCookie = res.headers.get("set-cookie");
  assert.ok(setCookie && setCookie.includes("scanner_session="));
  assert.ok(setCookie.includes("HttpOnly"));
  assert.ok(setCookie.includes("SameSite=strict"));
});

test("Auth - Login fails with invalid credentials or missing config", async () => {
  const invalidReq = createMockRequest("http://localhost:3000/api/scanner/login", {
    method: "POST",
    headers: { "content-type": "application/json", origin: "http://localhost:3000" },
    body: JSON.stringify({ username: "admin-govsec", password: "wrong-password" }),
  });
  const invalidRes = await loginHandler(invalidReq);
  assert.strictEqual(invalidRes.status, 401);

  // Test missing auth config fails safely (returns 503/401 without default user)
  const origSecret = process.env.SESSION_SECRET;
  delete process.env.SESSION_SECRET;
  try {
    const req = createMockRequest("http://localhost:3000/api/scanner/login", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://localhost:3000" },
      body: JSON.stringify({ username: "admin-govsec", password: "senha-secreta-123" }),
    });
    const res = await loginHandler(req);
    assert.strictEqual(res.status, 401);
  } finally {
    process.env.SESSION_SECRET = origSecret;
  }
});

test("Auth - Logout clears session cookie", async () => {
  const req = createMockRequest("http://localhost:3000/api/scanner/logout", {
    method: "POST",
    headers: { origin: "http://localhost:3000" },
  });
  const res = await logoutHandler(req);
  assert.strictEqual(res.status, 200);
  const setCookie = res.headers.get("set-cookie");
  assert.ok(setCookie && setCookie.includes("scanner_session=;"));
});

test("Auth - Session expiration and invalid tokens return 401", async () => {
  const now = Math.floor(Date.now() / 1000);
  const expiredToken = signSession({
    actor: "admin-govsec",
    role: "operator",
    iat: now - 3600,
    exp: now - 10, // Expired 10 seconds ago
  });

  const parsed = parseSession(expiredToken);
  assert.strictEqual(parsed, null);

  const req = createMockRequest("http://localhost:3000/api/scanner/ranges", {
    cookies: { scanner_session: expiredToken! },
  });
  const res = await proxy(req, { params: Promise.resolve({ path: ["ranges"] }) });
  assert.strictEqual(res.status, 401);
});

test("Proxy - Returns 403 when CSRF Origin is missing or cross-site for mutation methods", async () => {
  const now = Math.floor(Date.now() / 1000);
  const validToken = signSession({
    actor: "admin-govsec",
    role: "operator",
    iat: now,
    exp: now + 3600,
  })!;

  // 1. Missing Origin header on POST -> 403
  const noOriginReq = createMockRequest("http://localhost:3000/api/scanner/ranges", {
    method: "POST",
    cookies: { scanner_session: validToken },
  });
  const noOriginRes = await proxy(noOriginReq, { params: Promise.resolve({ path: ["ranges"] }) });
  assert.strictEqual(noOriginRes.status, 403);
  assert.match((await noOriginRes.json()).detail, /CSRF/i);

  // 2. Cross-site Origin -> 403
  const crossSiteReq = createMockRequest("http://localhost:3000/api/scanner/ranges", {
    method: "POST",
    headers: { origin: "http://malicious-attacker.com" },
    cookies: { scanner_session: validToken },
  });
  const crossSiteRes = await proxy(crossSiteReq, { params: Promise.resolve({ path: ["ranges"] }) });
  assert.strictEqual(crossSiteRes.status, 403);
});

test("Proxy - Forwards requests deriving actor ONLY from session and ignoring client headers", async () => {
  const now = Math.floor(Date.now() / 1000);
  const validToken = signSession({
    actor: "real-authenticated-user",
    role: "operator",
    iat: now,
    exp: now + 3600,
  })!;

  let receivedHeaders: Record<string, string> = {};
  let receivedMethod = "";

  const server = http.createServer((req, res) => {
    receivedMethod = req.method || "";
    receivedHeaders = req.headers as Record<string, string>;
    if (req.method === "DELETE") {
      res.writeHead(204);
      res.end();
    } else {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true }));
    }
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as { port: number };
  process.env.BACKEND_URL = `http://127.0.0.1:${address.port}`;

  try {
    const req = createMockRequest("http://localhost:3000/api/scanner/ranges", {
      method: "POST",
      headers: {
        origin: "http://localhost:3000",
        host: "localhost:3000",
        "X-Scanner-Actor": "fake-client-actor",
        "X-Scanner-API-Key": "fake-client-key",
      },
      cookies: { scanner_session: validToken },
    });

    const res = await proxy(req, { params: Promise.resolve({ path: ["ranges"] }) });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(receivedMethod, "POST");
    assert.strictEqual(receivedHeaders["x-scanner-actor"], "real-authenticated-user");
  } finally {
    server.close();
  }
});

test("Proxy - Returns 403 when user role is unauthorized or forbidden", async () => {
  const now = Math.floor(Date.now() / 1000);
  const forbiddenToken = signSession({
    actor: "unauthorized-user",
    role: "forbidden",
    iat: now,
    exp: now + 3600,
  })!;

  const req = createMockRequest("http://localhost:3000/api/scanner/ranges", {
    cookies: { scanner_session: forbiddenToken },
  });
  const res = await proxy(req, { params: Promise.resolve({ path: ["ranges"] }) });
  assert.strictEqual(res.status, 403);
  assert.match((await res.json()).detail, /Acesso negado/i);
});

test("Auth - Login and Logout blocked with 403 when Origin header is missing or cross-site", async () => {
  // Login without Origin -> 403
  const loginNoOrigin = createMockRequest("http://localhost:3000/api/scanner/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "admin-govsec", password: "senha-secreta-123" }),
  });
  const loginRes = await loginHandler(loginNoOrigin);
  assert.strictEqual(loginRes.status, 403);

  // Logout without Origin -> 403
  const logoutNoOrigin = createMockRequest("http://localhost:3000/api/scanner/logout", {
    method: "POST",
  });
  const logoutRes = await logoutHandler(logoutNoOrigin);
  assert.strictEqual(logoutRes.status, 403);
});

test("Security - Secret keys are never exposed in JSON responses", async () => {
  const req = createMockRequest("http://localhost:3000/api/scanner/ranges");
  const res = await proxy(req, { params: Promise.resolve({ path: ["ranges"] }) });
  const text = await res.text();
  assert.ok(!text.includes("test-frontend-secret-key-32-chars"));
  assert.ok(!text.includes("test-session-secret-key-32-chars"));
});
