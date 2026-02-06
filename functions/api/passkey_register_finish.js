import {
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

export async function onRequest(context) {
  if (context.request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  const DB = context.env.DB;

  const body = await context.request.json().catch(() => null);
  if (!body) return json({ error: "bad_json" }, 400);

  const nickname = (body.nickname || "").trim();
  const attResp = body.credential; // PublicKeyCredential (JSON) dal client

  if (!nickname || !attResp) return json({ error: "missing_fields" }, 400);

  const user = await DB.prepare(
    `SELECT id FROM users WHERE username = ? OR nickname = ? LIMIT 1`
  ).bind(nickname, nickname).first();
  if (!user) return json({ error: "user_not_found" }, 404);

  // recupera ultima challenge reg per user
  const ch = await DB.prepare(
    `SELECT id, challenge FROM webauthn_challenges
     WHERE kind='reg' AND user_id = ?
     ORDER BY id DESC LIMIT 1`
  ).bind(user.id).first();

  if (!ch) return json({ error: "challenge_not_found" }, 400);

  const expectedOrigin = context.env.ORIGIN;
  const expectedRPID = context.env.RP_ID;

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: ch.challenge,
      expectedOrigin,
      expectedRPID,
      requireUserVerification: false,
    });
  } catch (e) {
    return json({ error: "verify_failed", detail: String(e?.message || e) }, 400);
  }

  const { verified, registrationInfo } = verification;
  if (!verified || !registrationInfo) return json({ error: "not_verified" }, 400);

  const credentialID = toB64u(registrationInfo.credentialID);
  const credentialPublicKey = toB64u(registrationInfo.credentialPublicKey);
  const counter = registrationInfo.counter || 0;

  // salva credenziale
  try {
    await DB.prepare(
      `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter)
       VALUES (?, ?, ?, ?)`
    ).bind(user.id, credentialID, credentialPublicKey, counter).run();
  } catch (e) {
    // se già esiste, errore
    return json({ error: "credential_exists" }, 409);
  }

  // elimina challenge usata (pulizia)
  await DB.prepare(`DELETE FROM webauthn_challenges WHERE id = ?`).bind(ch.id).run();

  // crea session token
  const token = await issueSession(DB, user.id);
  return json({ token }, 200);
}

async function issueSession(DB, userId) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = b64u(raw);
  const tokenHash = await sha256b64u(token);
  const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();

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

function toB64u(buf) {
  return b64u(new Uint8Array(buf));
}

function b64u(bytes) {
  let bin = "";
  bytes.forEach(b => bin += String.fromCharCode(b));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
}