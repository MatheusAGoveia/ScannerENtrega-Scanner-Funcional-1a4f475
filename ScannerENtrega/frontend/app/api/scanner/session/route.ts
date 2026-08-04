import { NextRequest, NextResponse } from "next/server.js";
import { getSessionFromRequest } from "../session.ts";

export const dynamic = "force-dynamic";

const ALLOWED_ROLES = new Set(["operator", "admin"]);

export async function GET(request: NextRequest) {
  const session = getSessionFromRequest(request);

  if (!session) {
    return NextResponse.json(
      { authenticated: false, detail: "Sessao invalida ou nao autenticada." },
      { status: 401 }
    );
  }

  if (!ALLOWED_ROLES.has(session.role)) {
    return NextResponse.json(
      { authenticated: false, detail: "Acesso negado para o perfil do usuario." },
      { status: 403 }
    );
  }

  return NextResponse.json({
    authenticated: true,
    actor: session.actor,
    role: session.role,
  });
}
