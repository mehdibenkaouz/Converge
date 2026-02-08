import { verifyRegistrationResponse } from "@simplewebauthn/server";

export async function onRequest(context) {
  try {
    if (context.request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const DB = context.env.DB;

    const body = await context.request.json().catch(() => null);
    if (!body) return json({ error: "bad_json" }, 400);

    const nickname = (body.nickname || "").trim();
    const attestation = body.credential;

    if (!nickname) return json({ error: "missing_nickname" }, 400);
    if (!attestation) return json({ error: "missing_credential" }, 400);

    // 1) User
    const user = await DB.prepare(
      `SELECT id, nickname FROM users WHERE nickname = ? COLLATE NOCASE LIMIT 1`
    ).bind(nickname).first();

    if (!user) return json({ error: "user_not_found" }, 404);

    // 2) Challenge di registrazione
    const ch = await DB.prepare(
      `SELECT id, challenge
       FROM webauthn_challenges
       WHERE kind='register' AND user_id = ?
       ORDER BY id DESC
       LIMIT 1`
    ).bind(user.id).first();

    if (!ch) return json({ error: "challenge_not_found" }, 400);

    const expectedOrigin = (context.env.ORIGIN || "").replace(/\/$/, "");
    const expectedRPID = context.env.RP_ID;

    if (!expectedOrigin) return json({ error: "missing_env_origin" }, 500);
    if (!expectedRPID) return json({ error: "missing_env_rp_id" }, 500);

    // 3) Verifica registrazione (questa è la cosa corretta)
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: attestation,
        expectedChallenge: ch.challenge,
        expectedOrigin,
        expectedRPID,
        requireUserVerification: false,
      });
    } catch (e) {
      return json({ error: "verify_failed", message: String(e), name: e?.name || null }, 400);
    }

    const { verified, registrationInfo } = verification;
    if (!verified || !registrationInfo) return json({ error: "not_verified" }, 400);

    const credentialID_b64u = b64u(toU8(registrationInfo.credentialID));
    const publicKey_b64u = b64u(toU8(registrationInfo.credentialPublicKey));
    const counter = Number(registrationInfo.counter || 0);

    // 4) Salva credenziale (ora la tabella NON sarà più vuota)
    // Se vuoi evitare duplicati: UNIQUE su credential_id oppure catch errore SQLITE_CONSTRAINT.
    await DB.prepare(
      `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter)
       VALUES (?, ?, ?, ?)`
    ).bind(user.id, credentialID_b64u, publicKey_b64u, counter).run();

    // 5) Consuma challenge
    await DB.prepare(`DELETE FROM webauthn_challenges WHERE id = ?`)
      .bind(ch.id).run();

    // 6) Crea sessioni come fai nel login_finish (access + refresh)
    const access_token = await issueSession(DB, user.id, "a.", 20 * 60 * 1000);
    const refresh_token = await issueSession(DB, user.id, "r.", 30 * 24 * 60 * 60 * 1000);

    return json({ token: access_token, access_token, refresh_token, nickname: user.nickname }, 200);

  } catch (e) {
    return json({ error: "worker_exception", message: String(e?.message || e), name: e?.name || null }, 500);
  }
}

async function issueSession(DB, userId, prefix, ttlMs) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = prefix + b64u(raw);

  const tokenHash = await sha256b64u(token);
  const expires = new Date(Date.now() + ttlMs).toISOString();

  await DB.prepare(
    `INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)`
  ).bind(userId, tokenHash, expires).run();

  return token;
}

async function sha256b64u(text) {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return b64u(new Uint8Array(hash));
}

function toU8(x) {
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer);
  // fallback (non dovrebbe servire)
  return new Uint8Array(x);
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