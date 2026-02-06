CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                 -- "reg" | "login"
  challenge TEXT NOT NULL,            -- base64url
  user_id INTEGER,                    -- nullable in login autofill
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_created ON webauthn_challenges(created_at);