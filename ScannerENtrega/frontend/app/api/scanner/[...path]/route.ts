import { NextRequest, NextResponse } from "next/server.js";
import { getSessionFromRequest, isOriginAllowed } from "../session.ts";

export const dynamic = "force-dynamic";

export async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const backendUrl = process.env.BACKEND_URL ?? "http://localhost:8000";
  const scannerApiKey = process.env.SCANNER_API_KEY;

  if (!scannerApiKey) {
    return NextResponse.json(
      { detail: "SCANNER_API_KEY nao configurada no frontend." },
      { status: 503 }
    );
  }

  // 1. Protection against CSRF / invalid origin on mutation methods
  if (!isOriginAllowed(request)) {
    return NextResponse.json(
      { detail: "Origem nao autorizada (CSRF protection)." },
      { status: 403 }
    );
  }

  // 2. Server-side session verification
  const session = getSessionFromRequest(request);
  if (!session) {
    return NextResponse.json(
      { detail: "Sessao invalida ou nao autenticada." },
      { status: 401 }
    );
  }

  if (session.role === "forbidden") {
    return NextResponse.json(
      { detail: "Acesso negado para o perfil do usuario." },
      { status: 403 }
    );
  }

  const { path } = await context.params;
  const target = new URL(`/api/v1/scanner/${path.join("/")}`, backendUrl);
  request.nextUrl.searchParams.forEach((value, key) => target.searchParams.append(key, value));

  // 3. Build headers: Ignore client-sent actor/keys/auth and derive actor ONLY from server session
  const headers = new Headers();
  headers.set("X-Scanner-API-Key", scannerApiKey);
  headers.set("X-Scanner-Actor", session.actor);

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

    if (response.status === 204) {
      return new NextResponse(null, { status: 204 });
    }

    const responseHeaders = new Headers();
    const responseType = response.headers.get("content-type");
    if (responseType) responseHeaders.set("content-type", responseType);

    return new NextResponse(response.body, { status: response.status, headers: responseHeaders });
  } catch (err: unknown) {
    if (err instanceof Error && err.name === "TimeoutError") {
      return NextResponse.json(
        { detail: "Tempo limite de resposta do backend excedido." },
        { status: 504 }
      );
    }
    return NextResponse.json({ detail: "API do scanner indisponivel." }, { status: 502 });
  }
}

export const GET = proxy;
export const POST = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
