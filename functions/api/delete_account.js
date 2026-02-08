export async function onRequest(context) {
  if (context.request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

  const DB = context.env.DB;

  const auth = context.request.headers.get("Authorization") || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : null;

  const cookieTok = getCookie(context.request.headers.get("Cookie") || "", "session");
  const token = bearer || cookieTok;

  if (!token) return json({ error: "not_authenticated" }, 401);

  const tokenHash = await sha256b64u(token);

  const row = await DB.prepare(`SELECT user_id FROM sessions WHERE token_hash = ? LIMIT 1`).bind(tokenHash).first();
  if (!row) return json({ error: "not_authenticated" }, 401);

  const userId = row.user_id;

  try{
    // Remove sessions, credentials, challenges and user record
    await DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(userId).run();
    await DB.prepare(`DELETE FROM webauthn_credentials WHERE user_id = ?`).bind(userId).run();
    await DB.prepare(`DELETE FROM webauthn_challenges WHERE user_id = ?`).bind(userId).run();
    await DB.prepare(`DELETE FROM users WHERE id = ?`).bind(userId).run();
  }catch(e){
    console.error('delete_account_error', e);
    return json({ error: 'delete_failed', message: String(e) }, 500);
  }

  return json({ ok: true }, 200);
}

async function sha256b64u(text) {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return b64u(new Uint8Array(hash));
}

function b64u(bytes) {
  let bin = "";
  bytes.forEach(b => bin += String.fromCharCode(b));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
}

function getCookie(cookieHeader, name) {
  const m = cookieHeader.match(new RegExp("(^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[2]) : null;
}
