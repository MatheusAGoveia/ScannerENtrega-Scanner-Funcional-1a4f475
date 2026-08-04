import { NextRequest, NextResponse } from "next/server.js";
import { setSessionCookie, signSession, validateCredentials } from "../session.ts";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as { username?: string; password?: string };
    const validation = validateCredentials(body.username, body.password);

    if (!validation.success || !validation.actor || !validation.role) {
      return NextResponse.json(
        { detail: validation.error || "Credenciais invalidas." },
        { status: 401 }
      );
    }

    const now = Math.floor(Date.now() / 1000);
    const token = signSession({
      actor: validation.actor,
      role: validation.role,
      iat: now,
      exp: now + 28800, // 8 hours
    });

    if (!token) {
      return NextResponse.json(
        { detail: "Configuracao de sessao ausente no servidor." },
        { status: 503 }
      );
    }

    const response = NextResponse.json({ success: true, actor: validation.actor });
    setSessionCookie(response, token);
    return response;
  } catch {
    return NextResponse.json({ detail: "Requisicao de login invalida." }, { status: 400 });
  }
}
