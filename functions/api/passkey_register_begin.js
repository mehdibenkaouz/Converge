import { generateRegistrationOptions } from "@simplewebauthn/server";

export async function onRequest(context) {
  if (context.request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  const DB = context.env.DB;

  const body = await context.request.json().catch(() => null);
  if (!body) return json({ error: "bad_json" }, 400);

  const nickname = (body.nickname || "").trim();
  const referralCode = (body.referralCode || "").trim();

  if (!nickname || nickname.length < 3) return json({ error: "nickname_too_short" }, 400);

  // 1) Se esiste già un utente con questo nickname/username, gestisci i retry
  let user = await DB.prepare(
    `SELECT id, referral_code FROM users
     WHERE username = ? OR nickname = ?
     LIMIT 1`
  ).bind(nickname, nickname).first();

  if (user) {
    // Se ha già una credenziale registrata -> nickname già “occupato”
    const hasCred = await DB.prepare(
      `SELECT 1 FROM webauthn_credentials WHERE user_id = ? LIMIT 1`
    ).bind(user.id).first();

    if (hasCred) return json({ error: "nickname_taken" }, 409);
    // else: utente “pending” (creato da un tentativo precedente) -> ok, lo riusiamo
  } else {
    // 2) Crea un nuovo utente con referral_code realmente unico (retry su collisioni rare)
    let created = false;

    for (let i = 0; i < 8; i++) {
      const referral = randomCode(10);
      try {
        await DB.prepare(
          "INSERT INTO users (username, nickname, referral_code) VALUES (?, ?, ?)"
        ).bind(nickname, nickname, referral).run();
        created = true;
        break;
      } catch (e) {
        const msg = String(e?.message || e);

        // collisione referral_code -> riprova
        if (msg.includes("users.referral_code")) continue;

        // race condition: qualcuno ha creato lo stesso nickname mentre eri qui
        if (msg.includes("users.username") || msg.includes("users.nickname")) {
          return json({ error: "nickname_taken" }, 409);
        }

        return json({ error: "db_error", detail: msg }, 500);
      }
    }

    if (!created) return json({ error: "db_error", detail: "referral_collision" }, 500);

    user = await DB.prepare(
      `SELECT id, referral_code FROM users WHERE username = ? LIMIT 1`
    ).bind(nickname).first();

    if (!user) return json({ error: "db_error" }, 500);
  }

  // 3) referral (opzionale): lega invitee -> inviter e accredita wallet +10
  if (referralCode) {
    const inviter = await DB.prepare(`SELECT id FROM users WHERE referral_code = ?`)
      .bind(referralCode).first();

    if (inviter && inviter.id !== user.id) {
      try {
        await DB.prepare(`INSERT INTO referrals (inviter_user_id, invitee_user_id) VALUES (?, ?)`)
          .bind(inviter.id, user.id).run();
        await DB.prepare(`UPDATE users SET bonus_wallet = bonus_wallet + 10 WHERE id = ?`)
          .bind(inviter.id).run();
      } catch (_) {
        // ignore (già usato / vincoli)
      }
    }
  }

  // 4) prepara WebAuthn options
  const options = await generateRegistrationOptions({
    rpName: context.env.RP_NAME || "Puzzle Swipe Breaker",
    rpID: context.env.RP_ID,
    userID: String(user.id),
    userName: nickname,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    timeout: 60000,
  });

  // 5) salva challenge
  await DB.prepare(
    `INSERT INTO webauthn_challenges (kind, challenge, user_id) VALUES ('reg', ?, ?)`
  ).bind(options.challenge, user.id).run();

  return json({ options, referralCode: user.referral_code }, 200);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
}

function randomCode(len) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let out = "";
  for (let i = 0; i < len; i++) out += chars[bytes[i] % chars.length];
  return out;
}