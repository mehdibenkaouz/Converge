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
    const attestation = body.credential;

    if (!nickname) return json({ error: "missing_nickname" }, 400);
    if (!attestation) return json({ error: "missing_credential" }, 400);

    const expectedOrigin = String(context.env.ORIGIN || "").replace(/\/$/, "");
    const expectedRPID = String(context.env.RP_ID || "");

    if (!expectedOrigin) return json({ error: "missing_env", detail: "ORIGIN is not set" }, 500);
    if (!expectedRPID) return json({ error: "missing_env", detail: "RP_ID is not set" }, 500);

    // 1) user
    const user = await DB.prepare(
      `SELECT id, nickname FROM users WHERE nickname = ? COLLATE NOCASE ORDER BY id DESC LIMIT 1`
    ).bind(nickname).first();

    if (!user) return json({ error: "user_not_found" }, 404);

    // (opzionale ma utile) se l'utente ha già credenziali, non dovrebbe essere qui
    const hasCred = await DB.prepare(
      `SELECT 1 FROM webauthn_credentials WHERE user_id = ? LIMIT 1`
    ).bind(user.id).first();

    if (hasCred) return json({ error: "already_has_credential" }, 409);

    // 2) challenge REG (usa ESATTAMENTE kind='reg' come nel begin)
    const ch = await DB.prepare(
      `SELECT id, challenge FROM webauthn_challenges
       WHERE kind='reg' AND user_id = ?
       ORDER BY id DESC LIMIT 1`
    ).bind(user.id).first();

    if (!ch) {
      // fallback compatibilità se in passato avevi scritto kind diverso (non dovrebbe servire)
      const ch2 = await DB.prepare(
        `SELECT id, challenge FROM webauthn_challenges
         WHERE (kind='register' OR kind='registration') AND user_id = ?
         ORDER BY id DESC LIMIT 1`
      ).bind(user.id).first();

      if (!ch2) return json({ error: "challenge_not_found" }, 400);
      // se troviamo un vecchio kind, usiamolo
      ch2.kind = "legacy";
      return await finishWithChallenge({ context, DB, user, ch: ch2, attestation, expectedOrigin, expectedRPID });
    }

    return await finishWithChallenge({ context, DB, user, ch, attestation, expectedOrigin, expectedRPID });
  } catch (e) {
    return json(
      { error: "worker_exception", message: String(e?.message || e), name: e?.name || null },
      500
    );
  }
}

async function finishWithChallenge({ DB, user, ch, attestation, expectedOrigin, expectedRPID }) {
  // (debug) controllo challenge letta dal clientDataJSON
  const clientCh = extractChallenge(attestation?.response?.clientDataJSON);
  if (clientCh && clientCh !== ch.challenge) {
    return json(
      { error: "challenge_mismatch", expected: ch.challenge, got: clientCh },
      400
    );
  }

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

  const credId = b64u(new Uint8Array(registrationInfo.credentialID));
  const pubKey = b64u(new Uint8Array(registrationInfo.credentialPublicKey));
  const counter = Number(registrationInfo.counter || 0);

  // evita duplicati
  const existing = await DB.prepare(
    `SELECT id FROM webauthn_credentials WHERE credential_id = ? LIMIT 1`
  ).bind(credId).first();

  if (existing) return json({ error: "credential_already_registered" }, 409);

  // 3) INSERT credenziale
  try {
    await DB.prepare(
      `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter)
       VALUES (?, ?, ?, ?)`
    ).bind(user.id, credId, pubKey, counter).run();
  } catch (e) {
    const msg = String(e?.message || e);
    // se collisione UNIQUE, torna coerente
    if (msg.includes("webauthn_credentials.credential_id")) {
      return json({ error: "credential_already_registered" }, 409);
    }
    return json({ error: "db_error", detail: msg }, 500);
  }

  // 4) cleanup challenge REG (pulisci tutte quelle dell’utente, così non crescono a infinito)
  await DB.prepare(
    `DELETE FROM webauthn_challenges WHERE user_id = ? AND (kind='reg' OR kind='register' OR kind='registration')`
  ).bind(user.id).run();

  // 5) sessioni (access + refresh)
  const access_token = await issueSession(DB, user.id);
  const refresh_token = await issueRefreshSession(DB, user.id);

  return json(
    { token: access_token, access_token, refresh_token, nickname: user.nickname },
    200
  );
}

function extractChallenge(clientDataJSON_b64u) {
  try {
    if (!clientDataJSON_b64u) return null;
    const b64 = b64uToB64(clientDataJSON_b64u);
    const o = JSON.parse(atob(b64));
    return o?.challenge || null;
  } catch {
    return null;
  }
}

async function issueSession(DB, userId) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = "a." + b64u(raw);
  const tokenHash = await sha256b64u(token);
  const expires = new Date(Date.now() + 1000 * 60 * 20).toISOString(); // 20 min
  await DB.prepare(
    `INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)`
  ).bind(userId, tokenHash, expires).run();
  return token;
}

async function issueRefreshSession(DB, userId) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = "r." + b64u(raw);
  const tokenHash = await sha256b64u(token);
  const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(); // 30 days
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

function b64u(bytes) {
  let bin = "";
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64uToB64(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  return s + pad;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}