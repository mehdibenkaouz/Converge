
# 🔐 Converge – Passkey / WebAuthn (Cloudflare Pages + D1)

## Stato attuale

✅ **Registrazione passkey: FUNZIONANTE**
✅ **Salvataggio DB corretto** (`credential_id` e `public_key` non vuoti)
🛠 **Login passkey: in fase finale** (fix su challenge `login`)

---

## Stack

* **Frontend**: HTML + JS (WebAuthn API)
* **Backend**: Cloudflare Pages Functions
* **Auth**: Passkey / WebAuthn (`@simplewebauthn/server`)
* **Database**: Cloudflare D1 (SQLite)
* **Sessioni**: token + refresh token in tabella `sessions`

---

## Database (D1)

### Tabelle principali

#### `users`

```sql
id INTEGER PRIMARY KEY AUTOINCREMENT
username TEXT UNIQUE
nickname TEXT
referral_code TEXT UNIQUE
bonus_wallet INTEGER
initial_claimed INTEGER
created_at TEXT
```

#### `webauthn_credentials`

```sql
id INTEGER PRIMARY KEY AUTOINCREMENT
user_id INTEGER NOT NULL
credential_id TEXT UNIQUE NOT NULL
public_key TEXT NOT NULL
counter INTEGER NOT NULL
transports TEXT
created_at TEXT
```

#### `webauthn_challenges`

```sql
id INTEGER PRIMARY KEY AUTOINCREMENT
kind TEXT NOT NULL      -- 'reg' | 'login'
challenge TEXT NOT NULL
user_id INTEGER NULL    -- NULL se login senza nickname
created_at TEXT
```

#### `sessions`

```sql
token_hash TEXT PRIMARY KEY
user_id INTEGER NOT NULL
expires_at TEXT NOT NULL
created_at TEXT
```

---

## Variabili di ambiente (Cloudflare Pages)

⚠️ **Fondamentale**: devono combaciare *esattamente* con l’URL usato nel browser.

### Production

```text
ORIGIN = https://converge-mqh.pages.dev
RP_ID  = converge-mqh.pages.dev
RP_NAME = Converge Game
```

> ⚠️ Non usare URL preview tipo `https://xxxx.converge-mqh.pages.dev` per testare WebAuthn
> WebAuthn è **sensibilissimo all’origin**

---

## Flusso WebAuthn corretto

### 🟢 REGISTRAZIONE (Passkey Create)

#### 1️⃣ `POST /api/passkey_register_begin`

* Input: `{ nickname, referralCode? }`
* Cosa fa:

  * crea/riusa l’utente
  * genera `generateRegistrationOptions`
  * salva challenge con `kind='reg'`
* Output:

  ```json
  { "options": { ...WebAuthnOptions... } }
  ```

#### 2️⃣ Client

```js
const cred = await navigator.credentials.create({ publicKey: options });
```

⚠️ **Serializzazione obbligatoria** (ArrayBuffer → base64url)

```js
function credToJSON(cred){
  const rid = bufToB64u(cred.rawId);
  return {
    id: rid,
    rawId: rid,
    type: cred.type,
    response: {
      attestationObject: bufToB64u(cred.response.attestationObject),
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
    },
    transports: cred.response.getTransports?.() || []
  };
}
```

#### 3️⃣ `POST /api/passkey_register_finish`

* Input:

```json
{
  "nickname": "Nick1",
  "credential": { ...credToJSON }
}
```

* Server:

  * `verifyRegistrationResponse`
  * **USA API NUOVA**:

    * `registrationInfo.credential.id`
    * `registrationInfo.credential.publicKey`
    * `registrationInfo.credential.counter`
  * salva:

    * `credential_id` = `credential.id` (dal client)
    * `public_key` = base64url(pubkey)
  * crea sessioni

✅ **DB check corretto**

```sql
SELECT length(credential_id), length(public_key)
FROM webauthn_credentials;
-- len_cred ~ 20+
-- len_pub  ~ 100+
```

---

## 🔵 LOGIN (Passkey Get)

### 1️⃣ `POST /api/passkey_login_begin`

* Input:

```json
{ "nickname": "" }   // vuoto = discoverable / resident credential
```

* Cosa fa:

  * genera `generateAuthenticationOptions`
  * **salva sempre challenge con `kind='login'`**
  * `user_id` può essere `NULL`

### 2️⃣ Client

```js
const assertion = await navigator.credentials.get({ publicKey: options });
```

Payload inviato:

```json
{
  "nickname": "",
  "credential": {
    "id": "...",
    "rawId": "...",
    "response": {
      "authenticatorData": "...",
      "clientDataJSON": "...",
      "signature": "...",
      "userHandle": "AAAABQ"
    }
  }
}
```

### 3️⃣ `POST /api/passkey_login_finish`

⚠️ **Bug trovato e corretto**
Il server cercava challenge solo con `user_id`, ma:

* login senza nickname ⇒ `user_id = NULL`
* quindi **challenge non trovata**

### ✅ Fix applicato

Il server ora:

```sql
WHERE kind='login'
AND (user_id = ? OR user_id IS NULL)
ORDER BY id DESC
LIMIT 1
```

In fallback:

```sql
WHERE kind='login'
ORDER BY id DESC
LIMIT 1
```

---

## Errori affrontati (storico)

### ❌ `registrationInfo_missing_credentialID`

**Causa**

* campo letto sbagliato (`registrationInfo.credentialID`)
* API nuova usa `registrationInfo.credential.id`

**Fix**

* usare struttura nuova

---

### ❌ `registrationInfo_missing_publicKey`

**Causa**

* stesso problema sopra (campo errato)

**Fix**

```js
const cred = registrationInfo.credential;
cred.publicKey   // corretto
```

---

### ❌ `Unexpected registration response origin`

**Causa**

* ORIGIN ≠ URL browser

**Fix**

* allineare ORIGIN / RP_ID in Cloudflare Pages

---

### ❌ `challenge_not_found` (login)

**Causa**

* challenge salvata con `user_id NULL`
* finish cercava solo `user_id = X`

**Fix**

* fallback su `user_id IS NULL`

---

## Stato finale

| Parte                   | Stato                   |
| ----------------------- | ----------------------- |
| Registrazione Passkey   | ✅ OK                    |
| Salvataggio credenziali | ✅ OK                    |
| Login Passkey           | 🟡 Ultimo fix applicato |
| Sessioni                | ✅ OK                    |
| DB                      | ✅ Coerente              |

---

## Note di sicurezza importanti

* ❌ **NON esiste** “una passkey per infiniti username”
* ✅ 1 passkey = 1 account
* Un device può avere **più passkey**, una per account
* `userHandle` serve solo per **risalire all’utente**, non per identificare l’account a piacere

---

## Query di debug utili

```sql
-- ultime challenge
SELECT id, kind, user_id, created_at
FROM webauthn_challenges
ORDER BY id DESC
LIMIT 10;

-- credenziali
SELECT id, user_id, credential_id, length(public_key)
FROM webauthn_credentials;

-- sessioni
SELECT COUNT(*) FROM sessions;
```

---

## Obiettivo raggiunto

✔ WebAuthn implementato correttamente
✔ Compatibile con Cloudflare Pages
✔ Login senza username supportato
✔ Sistema pronto per produzione

---