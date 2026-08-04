import assert from "node:assert";
import http from "node:http";
import { test } from "node:test";

import { NextRequest } from "next/server.js";
import { proxy } from "../app/api/scanner/[...path]/route.ts";
import { signSession } from "../app/api/scanner/session.ts";

process.env.SCANNER_API_KEY = "test-frontend-secret-key-32-chars";
process.env.SESSION_SECRET = "test-session-secret-key-32-chars";
process.env.DISABLE_DEV_FALLBACK = "true";

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

test("Proxy - Returns 401 when unauthenticated or session invalid", async () => {
  const req = createMockRequest("http://localhost:3000/api/scanner/ranges");
  const res = await proxy(req, { params: Promise.resolve({ path: ["ranges"] }) });
  assert.strictEqual(res.status, 401);
  const data = await res.json();
  assert.match(data.detail, /Sessao invalida/i);

  const invalidReq = createMockRequest("http://localhost:3000/api/scanner/ranges", {
    cookies: { scanner_session: "invalid.token.signature" },
  });
  const invalidRes = await proxy(invalidReq, { params: Promise.resolve({ path: ["ranges"] }) });
  assert.strictEqual(invalidRes.status, 401);
});

test("Proxy - Returns 403 when CSRF / Origin is cross-site for mutation methods", async () => {
  const validToken = signSession({ actor: "admin-user", role: "operator" });
  const req = createMockRequest("http://localhost:3000/api/scanner/ranges", {
    method: "POST",
    headers: {
      origin: "http://malicious-site.com",
    },
    cookies: { scanner_session: validToken },
  });
  const res = await proxy(req, { params: Promise.resolve({ path: ["ranges"] }) });
  assert.strictEqual(res.status, 403);
  const data = await res.json();
  assert.match(data.detail, /CSRF/i);
});

test("Proxy - Forwards GET, POST, PATCH, DELETE preserving path, query, status and ignoring spoofed actor/keys", async () => {
  const validToken = signSession({ actor: "real-authenticated-actor", role: "operator" });
  let receivedHeaders: Record<string, string> = {};
  let receivedMethod = "";
  let receivedUrl = "";
  let receivedBody = "";

  const server = http.createServer((req, res) => {
    receivedMethod = req.method || "";
    receivedUrl = req.url || "";
    receivedHeaders = req.headers as Record<string, string>;
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", () => {
      receivedBody = body;
      if (req.method === "DELETE") {
        res.writeHead(204);
        res.end();
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true, method: req.method }));
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as { port: number };
  const port = address.port;
  process.env.BACKEND_URL = `http://127.0.0.1:${port}`;

  try {
    // 1. Test POST forwarding & spoofed header sanitization
    const postReq = createMockRequest("http://localhost:3000/api/scanner/ranges?param=value", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Scanner-Actor": "fake-spoofed-actor",
        "X-Scanner-API-Key": "fake-client-key",
      },
      body: JSON.stringify({ name: "Range Test" }),
      cookies: { scanner_session: validToken },
    });

    const postRes = await proxy(postReq, { params: Promise.resolve({ path: ["ranges"] }) });
    assert.strictEqual(postRes.status, 200);
    assert.strictEqual(receivedMethod, "POST");
    assert.strictEqual(receivedUrl, "/api/v1/scanner/ranges?param=value");
    assert.strictEqual(receivedHeaders["x-scanner-api-key"], "test-frontend-secret-key-32-chars");
    assert.strictEqual(receivedHeaders["x-scanner-actor"], "real-authenticated-actor");
    assert.strictEqual(JSON.parse(receivedBody).name, "Range Test");

    // 2. Test DELETE forwarding & 204 No Content
    const delReq = createMockRequest("http://localhost:3000/api/scanner/ranges/123", {
      method: "DELETE",
      cookies: { scanner_session: validToken },
    });
    const delRes = await proxy(delReq, { params: Promise.resolve({ path: ["ranges", "123"] }) });
    assert.strictEqual(delRes.status, 204);
    assert.strictEqual(receivedMethod, "DELETE");
    assert.strictEqual(receivedUrl, "/api/v1/scanner/ranges/123");

    // 3. Test PATCH forwarding
    const patchReq = createMockRequest("http://localhost:3000/api/scanner/ranges/123", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled: false }),
      cookies: { scanner_session: validToken },
    });
    const patchRes = await proxy(patchReq, { params: Promise.resolve({ path: ["ranges", "123"] }) });
    assert.strictEqual(patchRes.status, 200);
    assert.strictEqual(receivedMethod, "PATCH");
  } finally {
    server.close();
  }
});

test("Proxy - Returns 403 when user role is forbidden", async () => {
  const forbiddenToken = signSession({ actor: "unauthorized-user", role: "forbidden" });
  const req = createMockRequest("http://localhost:3000/api/scanner/ranges", {
    cookies: { scanner_session: forbiddenToken },
  });
  const res = await proxy(req, { params: Promise.resolve({ path: ["ranges"] }) });
  assert.strictEqual(res.status, 403);
  const data = await res.json();
  assert.match(data.detail, /Acesso negado/i);
});

test("Proxy - Returns 502 when backend is unavailable", async () => {
  const validToken = signSession({ actor: "test-user", role: "operator" });
  process.env.BACKEND_URL = "http://127.0.0.1:59999"; // Unreachable port

  const req = createMockRequest("http://localhost:3000/api/scanner/summary", {
    cookies: { scanner_session: validToken },
  });

  const res = await proxy(req, { params: Promise.resolve({ path: ["summary"] }) });
  assert.strictEqual(res.status, 502);
  const data = await res.json();
  assert.strictEqual(data.detail, "API do scanner indisponivel.");
  // Confirm secret is NOT leaked in response
  assert.strictEqual(JSON.stringify(data).includes("test-frontend-secret-key"), false);
});
