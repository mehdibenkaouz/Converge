export async function onRequest(context) {
  const DB = context.env.DB;

  const auth = context.request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) return json({ loggedIn: false }, 401);

  const tokenHash = await sha256b64u(token);

  const row = await DB.prepare(
    `SELECT s.user_id, s.expires_at, u.username, u.nickname
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND datetime(s.expires_at) > datetime('now')
     LIMIT 1`
  ).bind(tokenHash).first();

  if (!row) return json({ loggedIn: false }, 401);

  return json({
    loggedIn: true,
    user: {
      id: row.user_id,
      username: row.username,
      nickname: row.nickname ?? row.username,
    },
  }, 200);
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
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}