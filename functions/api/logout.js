export async function onRequest(context) {
  if (context.request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

  const DB = context.env.DB;
  const token = getCookie(context.request.headers.get("Cookie") || "", "session");

  if (token) {
    // stesso discorso: se token_hash è hashato, qui devi hashare token
    await DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(token).run();
  }

  // cancella cookie
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": "session=; Max-Age=0; Path=/; Secure; SameSite=Lax",
    },
  });
}

function getCookie(cookieHeader, name) {
  const m = cookieHeader.match(new RegExp("(^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[2]) : null;
}