import { generateRegistrationOptions } from "@simplewebauthn/server";

export async function onRequest(context) {
  try {
    if (context.request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const DB = context.env.DB;
    const RP_ID = String(context.env.RP_ID || "").trim();
    const RP_NAME = String(context.env.RP_NAME || "Puzzle Swipe Breaker");

    if (!RP_ID) return json({ error: "missing_env", detail: "RP_ID is not set" }, 500);

    const body = await context.request.json().catch(() => null);
    if (!body) return json({ error: "bad_json" }, 400);

    const nickname = String(body.nickname || "").trim();
    const referralCode = String(body.referralCode || "").trim();

    if (!nickname || nickname.length < 3) return json({ error: "nickname_too_short" }, 400);

    // 1) utente: se esiste già ma NON ha credenziali -> riusa (retry ok)
    let user = await DB.prepare(
      `SELECT id, referral_code FROM users
       WHERE nickname = ? COLLATE NOCASE
       LIMIT 1`
    ).bind(nickname).first();

    if (user) {
      const hasCred = await DB.prepare(
        `SELECT 1 FROM webauthn_credentials WHERE user_id = ? LIMIT 1`
      ).bind(user.id).first();

      if (hasCred) return json({ error: "nickname_taken" }, 409);
    } else {
      // crea user con referral_code unico (retry su collisione)
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
          if (msg.includes("users.referral_code")) continue;
          if (msg.includes("users.username") || msg.includes("users.nickname")) {
            return json({ error: "nickname_taken" }, 409);
          }
          return json({ error: "db_error", detail: msg }, 500);
        }
      }
      if (!created) return json({ error: "db_error", detail: "referral_collision" }, 500);

      user = await DB.prepare(`SELECT id, referral_code FROM users WHERE nickname = ? COLLATE NOCASE LIMIT 1`)
        .bind(nickname).first();

      if (!user) return json({ error: "db_error" }, 500);
    }

    // 2) referral opzionale
    if (referralCode) {
      const inviter = await DB.prepare(`SELECT id FROM users WHERE referral_code = ? LIMIT 1`)
        .bind(referralCode).first();

      if (inviter && inviter.id !== user.id) {
        try {
          await DB.prepare(
            `INSERT INTO referrals (inviter_user_id, invitee_user_id) VALUES (?, ?)`
          ).bind(inviter.id, user.id).run();

          await DB.prepare(
            `UPDATE users SET bonus_wallet = bonus_wallet + 10 WHERE id = ?`
          ).bind(inviter.id).run();
        } catch (_) {}
      }
    }

    // 3) options
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: intToUint8Array(user.id),
      userName: nickname,
      userDisplayName: nickname,
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      timeout: 60000,
    });

    // 4) salva challenge reg
    await DB.prepare(
      `INSERT INTO webauthn_challenges (kind, challenge, user_id) VALUES ('reg', ?, ?)`
    ).bind(options.challenge, user.id).run();

    return json({ options, referralCode: user.referral_code }, 200);
  } catch (e) {
    return json({ error: "exception", detail: String(e?.stack || e) }, 500);
  }
}

function intToUint8Array(n) {
  const v = Number(n) >>> 0;
  return new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
}

function randomCode(len) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let out = "";
  for (let i = 0; i < len; i++) out += chars[bytes[i] % chars.length];
  return out;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}