import { NextRequest, NextResponse } from "next/server.js";
import { clearSessionCookie, isOriginAllowed } from "../session.ts";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  if (!isOriginAllowed(request)) {
    return NextResponse.json(
      { detail: "Origem nao autorizada (CSRF protection)." },
      { status: 403 }
    );
  }
  const response = NextResponse.json({ success: true });
  clearSessionCookie(response);
  return response;
}
