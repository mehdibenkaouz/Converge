import { generateAuthenticationOptions } from "@simplewebauthn/server";

export async function onRequest(context) {
  if (context.request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  const DB = context.env.DB;

  const body = await context.request.json().catch(() => ({}));

  let nickname = (body.nickname || "").trim();
  let user = null;
  let allowCredentials = [];

  if (nickname) {
    user = await DB.prepare(`SELECT id FROM users WHERE nickname = ? COLLATE NOCASE`)
      .bind(nickname).first();

    if (user) {
      const creds = await DB.prepare(
        `SELECT credential_id FROM webauthn_credentials WHERE user_id = ?`
      ).bind(user.id).all();

      allowCredentials = (creds.results || []).map(r => ({
        id: fromB64u(r.credential_id),
        type: "public-key",
      }));
    } else {
      nickname = ""; // fallback
    }
  }


  const options = await generateAuthenticationOptions({
    rpID: context.env.RP_ID,
    timeout: 60000,
    userVerification: "preferred",
    allowCredentials, // se vuoto, tenta discoverable/resident
  });

  // salva challenge login (senza user_id se nickname vuoto)
  const userId = nickname ? (await DB.prepare(`SELECT id FROM users WHERE nickname = ?`).bind(nickname).first())?.id : null;

  await DB.prepare(
    `INSERT INTO webauthn_challenges (kind, challenge, user_id) VALUES ('login', ?, ?)`
  ).bind(options.challenge, userId ?? null).run();

  return json({ options }, 200);
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