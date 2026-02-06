export async function onRequest(context) {
  if (context.request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

  const DB = context.env.DB;
  const user = await authUser(context.request, DB);
  if (!user) return json({ error: "unauthorized" }, 401);

  const body = await context.request.json().catch(() => null);
  if (!body) return json({ error: "bad_json" }, 400);

  const score = Number(body.score);
  if (!Number.isFinite(score) || score < 0) return json({ error: "invalid_score" }, 400);

  // aggiorna solo se migliora
  await DB.prepare(
    `UPDATE users
     SET high_score = CASE WHEN high_score < ? THEN ? ELSE high_score END
     WHERE id = ?`
  ).bind(score, score, user.id).run();

  const row = await DB.prepare(`SELECT high_score FROM users WHERE id = ?`).bind(user.id).first();
  return json({ highScore: row?.high_score ?? score }, 200);
}

async function authUser(req, DB) {
  const token = getBearer(req);
  if (!token) return null;

  const tokenHash = await sha256b64u(token);
  const row = await DB.prepare(
    `SELECT u.id
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  ).bind(tokenHash, new Date().toISOString()).first();

  return row || null;
}

function getBearer(req) {
  const h = req.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

async function sha256b64u(text) {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return b64u(new Uint8Array(hash));
}

function b64u(bytes) {
  let bin = "";
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}