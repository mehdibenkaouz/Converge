export async function onRequest(context) {
  const DB = context.env.DB;

  const token = getCookie(context.request.headers.get("Cookie") || "", "session");
  if (!token) return json({ loggedIn: false }, 401);

  // Se nel DB salvi token_hash, devi hashare `token` qui con lo stesso metodo usato in login.
  // Se invece salvi il token in chiaro, usa direttamente token.
  // QUI metto in chiaro per il check minimo: adattalo al tuo schema.
  const row = await DB.prepare(
    `SELECT s.user_id, s.expires_at, u.username, u.nickname
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND datetime(s.expires_at) > datetime('now')
     LIMIT 1`
  ).bind(token).first();

  if (!row) return json({ loggedIn: false }, 401);

  return json({
    loggedIn: true,
    user: {
      id: row.user_id,
      username: row.username,
      nickname: row.nickname ?? row.username,
    },
  }, 200);
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function getCookie(cookieHeader, name) {
  const m = cookieHeader.match(new RegExp("(^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[2]) : null;
}