export async function onRequest(context) {
  if (context.request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const DB = context.env.DB;

  try {
    const user = await authUser(context.request, DB);
    if (!user) return json({ error: "unauthorized" }, 401);

    // 1) elimina sessioni
    await DB.prepare(
      `DELETE FROM sessions WHERE user_id = ?`
    ).bind(user.id).run();

    // 2) elimina credenziali WebAuthn
    await DB.prepare(
      `DELETE FROM webauthn_credentials WHERE user_id = ?`
    ).bind(user.id).run();

    // 3) elimina challenge residue
    await DB.prepare(
      `DELETE FROM webauthn_challenges WHERE user_id = ?`
    ).bind(user.id).run();

    // 4) elimina referrals collegati
    await DB.prepare(
      `DELETE FROM referrals WHERE inviter_user_id = ? OR invitee_user_id = ?`
    ).bind(user.id, user.id).run();

    // 5) elimina utente
    await DB.prepare(
      `DELETE FROM users WHERE id = ?`
    ).bind(user.id).run();

    return json({ ok: true }, 200);

  } catch (err) {
    return json(
      {
        error: "server_error",
        message: String(err?.message || err),
      },
      500
    );
  }
}

/* --- auth helpers (copiati da score_submit.js) --- */
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
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}