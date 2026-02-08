import { generateAuthenticationOptions } from "@simplewebauthn/server";

export async function onRequest(context) {
  if (context.request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const DB = context.env.DB;

  const body = await context.request.json().catch(() => ({}));
  let nickname = String(body.nickname || "").trim();

  let user = null;
  let allowCredentials = [];

  if (nickname) {
    user = await DB.prepare(`SELECT id FROM users WHERE nickname = ? COLLATE NOCASE LIMIT 1`)
      .bind(nickname).first();

    if (!user) nickname = ""; // fallback: discoverable
  }

  if (nickname && user?.id) {
    const creds = await DB.prepare(
      `SELECT credential_id FROM webauthn_credentials WHERE user_id = ?`
    ).bind(user.id).all();

    allowCredentials = (creds.results || [])
      .filter(r => r.credential_id && String(r.credential_id).length > 0)
      .map(r => ({
        id: fromB64u(r.credential_id),
        type: "public-key",
      }));
  }

  const options = await generateAuthenticationOptions({
    rpID: String(context.env.RP_ID || "").trim(),
    timeout: 60000,
    userVerification: "preferred",
    allowCredentials, // se vuoto -> resident/discoverable
  });

  await DB.prepare(
    `INSERT INTO webauthn_challenges (kind, challenge, user_id) VALUES ('login', ?, ?)`
  ).bind(options.challenge, user?.id ?? null).run();

  return json({ options }, 200);
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

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
