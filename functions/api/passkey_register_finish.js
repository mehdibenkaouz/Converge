import { verifyRegistrationResponse } from "@simplewebauthn/server";

export async function onRequest(context) {
  try {
    if (context.request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const DB = context.env.DB;

    const body = await context.request.json().catch(() => null);
    if (!body) return json({ error: "bad_json" }, 400);

    const nickname = String(body.nickname || "").trim();
    const att = body.credential;

    if (!nickname) return json({ error: "missing_nickname" }, 400);
    if (!att) return json({ error: "missing_credential" }, 400);

    const expectedOrigin = String(context.env.ORIGIN || "").replace(/\/$/, "");
    const expectedRPID = String(context.env.RP_ID || "").trim();

    if (!expectedOrigin) return json({ error: "missing_env", detail: "ORIGIN is not set" }, 500);
    if (!expectedRPID) return json({ error: "missing_env", detail: "RP_ID is not set" }, 500);

    // 1) user
    const user = await DB.prepare(
      `SELECT id, nickname FROM users WHERE nickname = ? COLLATE NOCASE LIMIT 1`
    ).bind(nickname).first();

    if (!user) return json({ error: "user_not_found" }, 404);

    // se ha già credenziale -> stop
    const hasCred = await DB.prepare(
      `SELECT 1 FROM webauthn_credentials WHERE user_id = ? LIMIT 1`
    ).bind(user.id).first();

    if (hasCred) return json({ error: "already_has_credential" }, 409);

    // 2) challenge reg
    const ch = await DB.prepare(
      `SELECT id, challenge FROM webauthn_challenges
       WHERE kind='reg' AND user_id = ?
       ORDER BY id DESC LIMIT 1`
    ).bind(user.id).first();

    if (!ch?.challenge) return json({ error: "challenge_not_found" }, 400);

    // 3) normalizza attestation (id/rawId DEVONO essere base64url coerenti)
    const normalizedId = normalizeB64u(att.rawId || att.id);
    if (!normalizedId) return json({ error: "missing_credential_id" }, 400);

    att.id = normalizedId;
    att.rawId = normalizedId;

    // controllo minimi campi
    if (!att.response?.clientDataJSON || !att.response?.attestationObject) {
      return json({ error: "bad_credential_shape" }, 400);
    }

    // 4) verify
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: att,
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

    // 5) estrai e VALIDAZIONE (prima di convertire!)
    const credID = registrationInfo.credentialID;
    const pubKey = registrationInfo.credentialPublicKey;

    if (!credID || byteLen(credID) === 0) {
      return json({ error: "registrationInfo_missing_credentialID" }, 400);
    }
    if (!pubKey || byteLen(pubKey) === 0) {
      return json({ error: "registrationInfo_missing_publicKey" }, 400);
    }

    const credIdB64u = b64u(new Uint8Array(credID));
    const pubKeyB64u = b64u(new Uint8Array(pubKey));
    const counter = Number(registrationInfo.counter || 0);

    // evita duplicati
    const existing = await DB.prepare(
      `SELECT id FROM webauthn_credentials WHERE credential_id = ? LIMIT 1`
    ).bind(credIdB64u).first();

    if (existing) return json({ error: "credential_already_registered" }, 409);

    // 6) insert
    await DB.prepare(
      `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter, transports)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(
      user.id,
      credIdB64u,
      pubKeyB64u,
      counter,
      JSON.stringify(att?.transports || att?.response?.transports || [])
    ).run();

    // 7) cleanup challenge reg (tutte per quell’utente)
    await DB.prepare(
      `DELETE FROM webauthn_challenges WHERE user_id = ? AND kind='reg'`
    ).bind(user.id).run();

    // 8) session
    const access_token = await issueSession(DB, user.id);
    const refresh_token = await issueRefreshSession(DB, user.id);

    return json({ token: access_token, access_token, refresh_token, nickname: user.nickname }, 200);
  } catch (e) {
    return json({ error: "worker_exception", message: String(e?.message || e) }, 500);
  }
}

function byteLen(x) {
  if (x instanceof ArrayBuffer) return x.byteLength;
  if (ArrayBuffer.isView(x)) return x.byteLength;
  return 0;
}

// normalizza base64/base64url → base64url senza padding
function normalizeB64u(s) {
  try {
    if (!s) return null;
    const bytes = fromB64u(String(s));
    return b64u(bytes);
  } catch {
    try {
      return String(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    } catch {
      return null;
    }
  }
}

function b64uToB64(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  return s + pad;
}

function fromB64u(s) {
  const b64 = b64uToB64(s);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64u(bytes) {
  let bin = "";
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function issueSession(DB, userId) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = "a." + b64u(raw);
  const tokenHash = await sha256b64u(token);
  const expires = new Date(Date.now() + 1000 * 60 * 20).toISOString();
  await DB.prepare(
    `INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)`
  ).bind(userId, tokenHash, expires).run();
  return token;
}

async function issueRefreshSession(DB, userId) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = "r." + b64u(raw);
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

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}