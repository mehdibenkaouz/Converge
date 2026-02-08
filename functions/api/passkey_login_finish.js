import { verifyAuthenticationResponse } from "@simplewebauthn/server";

export async function onRequest(context) {
  try {
    if (context.request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const DB = context.env.DB;

    const body = await context.request.json().catch(() => null);
    if (!body) return json({ error: "bad_json" }, 400);

    const assertion = body.credential;
    if (!assertion) return json({ error: "missing_credential" }, 400);

    const expectedOrigin = String(context.env.ORIGIN || "").replace(/\/$/, "");
    const expectedRPID = String(context.env.RP_ID || "").trim();
    if (!expectedOrigin) return json({ error: "missing_env", detail: "ORIGIN is not set" }, 500);
    if (!expectedRPID) return json({ error: "missing_env", detail: "RP_ID is not set" }, 500);

    // normalize id/rawId
    const credId = normalizeB64u(assertion.rawId || assertion.id);
    if (!credId) return json({ error: "missing_credential_id" }, 400);
    assertion.id = credId;
    assertion.rawId = credId;

    // resolve userId from userHandle (discoverable) OR nickname
    const nickname = String(body.nickname || "").trim();
    let userId = null;

    if (nickname) {
      const u = await DB.prepare(
        `SELECT id FROM users WHERE nickname = ? COLLATE NOCASE LIMIT 1`
      ).bind(nickname).first();
      if (u?.id) userId = Number(u.id);
    }

    if (!userId && assertion?.response?.userHandle) {
      const uhBytes = fromB64u(assertion.response.userHandle);
      if (uhBytes?.length === 4) {
        userId =
          ((uhBytes[0] << 24) >>> 0) |
          (uhBytes[1] << 16) |
          (uhBytes[2] << 8) |
          uhBytes[3];
      }
    }

    // ✅ CHALLENGE: prendi SEMPRE l’ultima login challenge
    // Se userId esiste: preferisci challenge con quel user_id, ma fai fallback a NULL.
    let ch = null;

    if (userId) {
      ch = await DB.prepare(
        `SELECT id, challenge FROM webauthn_challenges
         WHERE kind='login' AND (user_id = ? OR user_id IS NULL)
         ORDER BY id DESC LIMIT 1`
      ).bind(userId).first();
    } else {
      ch = await DB.prepare(
        `SELECT id, challenge FROM webauthn_challenges
         WHERE kind='login'
         ORDER BY id DESC LIMIT 1`
      ).first();
    }

    if (!ch?.challenge) {
      return json({
        error: "challenge_not_found",
        hint: "Hai chiamato login_finish senza che login_begin abbia salvato la challenge, oppure su DB diverso."
      }, 400);
    }

    // find credential row (DB stores credential_id + public_key)
    let row = null;

    if (userId) {
      row = await DB.prepare(
        `SELECT c.credential_id, c.user_id, c.public_key, c.counter, u.nickname
         FROM webauthn_credentials c
         JOIN users u ON u.id = c.user_id
         WHERE c.user_id = ? AND c.credential_id = ?
         LIMIT 1`
      ).bind(userId, credId).first();
    }

    if (!row) {
      row = await DB.prepare(
        `SELECT c.credential_id, c.user_id, c.public_key, c.counter, u.nickname
         FROM webauthn_credentials c
         JOIN users u ON u.id = c.user_id
         WHERE c.credential_id = ?
         LIMIT 1`
      ).bind(credId).first();
    }

    if (!row) return json({ error: "credential_not_found", id: credId }, 404);

    // verify
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: assertion,
        expectedChallenge: ch.challenge,
        expectedOrigin,
        expectedRPID,
        credential: {
          id: row.credential_id,
          publicKey: fromB64u(row.public_key),
          counter: Number(row.counter || 0),
        },
        requireUserVerification: false,
      });
    } catch (e) {
      return json({ error: "verify_failed", message: String(e), name: e?.name || null }, 400);
    }

    const { verified, authenticationInfo } = verification;
    if (!verified || !authenticationInfo) return json({ error: "not_verified" }, 400);

    // update counter
    await DB.prepare(
      `UPDATE webauthn_credentials SET counter = ? WHERE credential_id = ?`
    ).bind(authenticationInfo.newCounter, row.credential_id).run();

    // delete used challenge (solo quella)
    await DB.prepare(`DELETE FROM webauthn_challenges WHERE id = ?`).bind(ch.id).run();

    // issue tokens
    const access_token = await issueSession(DB, row.user_id);
    const refresh_token = await issueRefreshSession(DB, row.user_id);

    return json({ token: access_token, access_token, refresh_token, nickname: row.nickname }, 200);
  } catch (e) {
    return json({ error: "worker_exception", message: String(e?.message || e) }, 500);
  }
}

function normalizeB64u(s) {
  return String(s || "").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
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