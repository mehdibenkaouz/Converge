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

    // Shape check minimo (come da tuo payload)
    if (!att.id || !att.rawId || att.type !== "public-key") {
      return json({ error: "bad_credential_shape", detail: "missing id/rawId/type" }, 400);
    }
    if (!att.response?.clientDataJSON || !att.response?.attestationObject) {
      return json({ error: "bad_credential_shape", detail: "missing clientDataJSON/attestationObject" }, 400);
    }

    // Normalizza id/rawId (base64url senza padding)
    const normalizedId = normalizeB64u(att.rawId || att.id);
    att.id = normalizedId;
    att.rawId = normalizedId;

    // User
    const user = await DB.prepare(
      `SELECT id, nickname FROM users WHERE nickname = ? COLLATE NOCASE LIMIT 1`
    ).bind(nickname).first();
    if (!user) return json({ error: "user_not_found" }, 404);

    // Se ha già credenziali -> stop
    const hasCred = await DB.prepare(
      `SELECT 1 FROM webauthn_credentials WHERE user_id = ? LIMIT 1`
    ).bind(user.id).first();
    if (hasCred) return json({ error: "already_has_credential" }, 409);

    // Challenge reg
    const ch = await DB.prepare(
      `SELECT id, challenge FROM webauthn_challenges
       WHERE kind='reg' AND user_id = ?
       ORDER BY id DESC LIMIT 1`
    ).bind(user.id).first();
    if (!ch?.challenge) return json({ error: "challenge_not_found" }, 400);

    // Verify (IMPORTANT: response deve essere l'oggetto credential ritornato dal browser)
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
    if (!verified) return json({ error: "not_verified" }, 400);
    if (!registrationInfo) return json({ error: "missing_registrationInfo" }, 400);

    // ✅ CAMPi GIUSTI (nuova API): registrationInfo.credential.publicKey ecc.
    const cred = registrationInfo.credential;
    if (!cred?.id) return json({ error: "missing_cred_id" }, 400);
    if (!cred?.publicKey || byteLen(cred.publicKey) === 0) {
      return json({ error: "registrationInfo_missing_publicKey" }, 400);
    }

    const credentialIdB64u = String(cred.id); // già base64url
    const publicKeyB64u = b64u(new Uint8Array(cred.publicKey));
    const counter = Number(cred.counter || 0);
    const transports = cred.transports || att.transports || [];

    // Evita duplicati
    const existing = await DB.prepare(
      `SELECT id FROM webauthn_credentials WHERE credential_id = ? LIMIT 1`
    ).bind(credentialIdB64u).first();
    if (existing) return json({ error: "credential_already_registered" }, 409);

    // Insert
    await DB.prepare(
      `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter, transports)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(
      user.id,
      credentialIdB64u,
      publicKeyB64u,
      counter,
      JSON.stringify(transports)
    ).run();

    // Cleanup challenges reg
    await DB.prepare(
      `DELETE FROM webauthn_challenges WHERE user_id = ? AND kind='reg'`
    ).bind(user.id).run();

    // Session
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

function normalizeB64u(s) {
  return String(s || "").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
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
