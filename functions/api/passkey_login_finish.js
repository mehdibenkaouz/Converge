const clientCh = (() => {
  try {
    const s = JSON.parse(atob((assertion.response.clientDataJSON||"").replace(/-/g,"+").replace(/_/g,"/") + "===".slice((assertion.response.clientDataJSON||"").length%4||4)));
    return s.challenge;
  } catch { return null; }
})();
if (clientCh !== ch.challenge) {
  return json({ error:"challenge_mismatch", expected: ch.challenge, got: clientCh }, 400);
}


import { verifyAuthenticationResponse } from "@simplewebauthn/server";

export async function onRequest(context) {
  if (context.request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  const DB = context.env.DB;

  const body = await context.request.json().catch(() => null);
  if (!body) return json({ error: "bad_json" }, 400);

  const assertion = body.credential;

  if (!assertion) return json({ error: "missing_credential" }, 400);

  // challenge più recente (se nickname dato, prova con user_id; altrimenti ultima login in generale)
  let nickname = (body.nickname || "").trim();
  let user = null;

  if (nickname) {
    user = await DB.prepare(`SELECT id FROM users WHERE nickname = ? COLLATE NOCASE`)
      .bind(nickname).first();
    if (!user) nickname = "";
  }

  // poi scegli challenge:
  const ch = nickname
    ? await DB.prepare(`SELECT id, challenge FROM webauthn_challenges
                        WHERE kind='login' AND (user_id = ? OR user_id IS NULL)
                        ORDER BY id DESC LIMIT 1`).bind(user.id).first()
    : await DB.prepare(`SELECT id, challenge FROM webauthn_challenges
                        WHERE kind='login'
                        ORDER BY id DESC LIMIT 1`).first();
                        

  

  if (!ch) return json({ error: "challenge_not_found" }, 400);

  // Recupera credenziale dal DB usando credential_id
  const credIdA = assertion?.rawId;
  const credIdB = assertion?.id;
  if (!credIdA && !credIdB) return json({ error: "missing_credential_id" }, 400);

  const row = await DB.prepare(
    `SELECT c.credential_id, c.user_id, c.public_key, c.counter, u.nickname
    FROM webauthn_credentials c
    JOIN users u ON u.id = c.user_id
    WHERE c.credential_id = ? OR c.credential_id = ?`
  ).bind(credIdA || credIdB, credIdB || credIdA).first();

  if (!row) return json({ error: "credential_not_found", rawId: credIdA || null, id: credIdB || null }, 404);

  const usedCredId = row.credential_id;


  const expectedOrigin = context.env.ORIGIN;
  const expectedRPID = context.env.RP_ID;

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge: ch.challenge,
      expectedOrigin,
      expectedRPID,
      authenticator: {
        credentialID: fromB64u(usedCredId),
        credentialPublicKey: fromB64u(row.public_key),
        counter: row.counter || 0,
      },
      requireUserVerification: false,
    });
  } catch (e) {
    return json({ error: "verify_failed" }, 400);
  }

  const { verified, authenticationInfo } = verification;
  if (!verified || !authenticationInfo) return json({ error: "not_verified" }, 400);

  // aggiorna counter
  await DB.prepare(
    `UPDATE webauthn_credentials SET counter = ? WHERE credential_id = ?`
  ).bind(authenticationInfo.newCounter, usedCredId).run();

  // elimina challenge usata
  await DB.prepare(`DELETE FROM webauthn_challenges WHERE id = ?`).bind(ch.id).run();

  // session token
  const token = await issueSession(DB, row.user_id);
  return json({ token, nickname: row.nickname }, 200);
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

function b64u(bytes) {
  let bin = "";
  bytes.forEach(b => bin += String.fromCharCode(b));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromB64u(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
}