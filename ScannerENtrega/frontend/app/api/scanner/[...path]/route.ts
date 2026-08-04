import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const backendUrl = process.env.BACKEND_URL ?? "http://localhost:8000";
const scannerApiKey = process.env.SCANNER_API_KEY;

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  if (!scannerApiKey) {
    return NextResponse.json({ detail: "SCANNER_API_KEY nao configurada no frontend." }, { status: 503 });
  }
  const { path } = await context.params;
  const target = new URL(`/api/v1/scanner/${path.join("/")}`, backendUrl);
  request.nextUrl.searchParams.forEach((value, key) => target.searchParams.append(key, value));
  const headers = new Headers();
  headers.set("X-Scanner-API-Key", scannerApiKey);
  headers.set("X-Scanner-Actor", request.headers.get("X-Scanner-Actor") ?? "operador-web");
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  const body = ["GET", "HEAD"].includes(request.method) ? undefined : await request.arrayBuffer();
  try {
    const response = await fetch(target, {
      method: request.method,
      headers,
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(30000),
    });
    const responseHeaders = new Headers();
    const responseType = response.headers.get("content-type");
    if (responseType) responseHeaders.set("content-type", responseType);
    return new NextResponse(response.body, { status: response.status, headers: responseHeaders });
  } catch {
    return NextResponse.json({ detail: "API do scanner indisponivel." }, { status: 502 });
  }
}

export const GET = proxy;
export const POST = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
