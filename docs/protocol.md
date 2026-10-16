# Bitwarden / Vaultwarden protocol notes

What Keyward implements, as verified against Vaultwarden 1.37.2 (server reports web-vault 2026.6.0).

## Headers

Every request: `Device-Type: 2` (Chrome extension) or `3` (Firefox extension),
`Bitwarden-Client-Name: browser`, `Bitwarden-Client-Version: 2026.9.3` (Vaultwarden gates some
features on the client version; keep it current).

## Login

1. `POST /identity/accounts/prelogin` `{email}` → `{kdf, kdfIterations, kdfMemory, kdfParallelism}`.
2. Master key:
   - PBKDF2-SHA256(password, lowercase(trim(email)), iterations) → 32 bytes, or
   - Argon2id(password, salt = SHA-256(lowercase email), t = iterations, m = memory MiB, p = parallelism).
3. Server hash = base64(PBKDF2-SHA256(masterKey, password, **1**)); local hash (offline unlock check) uses **2** iterations.
4. `POST /identity/connect/token` (form): `grant_type=password, username, password=<server hash>,
   scope=api offline_access, client_id=browser, deviceType, deviceIdentifier, deviceName`.
5. 2FA: HTTP 400 with `TwoFactorProviders2` → resubmit with `twoFactorToken`, `twoFactorProvider`,
   `twoFactorRemember=1`. Providers: 0 authenticator, 1 email, 3 YubiKey, 5 remember-token, 7 WebAuthn.
   - Email codes are sent by `POST /api/two-factor/send-email-login` `{email, masterPasswordHash}`.
   - WebAuthn's RP ID is the server `DOMAIN`, so the assertion runs in a tab on the server origin
     (`/404.html`, MAIN world via `scripting.executeScript`), never on the extension origin.
   - A successful 2FA with remember returns `TwoFactorToken`; send it as provider 5 next time.
6. Stretched master key = HKDF-Expand(masterKey, "enc", 32) ‖ HKDF-Expand(masterKey, "mac", 32);
   it decrypts the protected user key (`Key`, type 2 EncString; legacy type 0 uses the raw master key).

## Encryption

- EncString `"<type>.<iv>|<ct>|<mac>"` (base64). Types: 0 AES-CBC-256 (legacy, no MAC),
  2 AES-CBC-256 + HMAC-SHA256 (MAC = HMAC(macKey, iv ‖ ct), checked before decrypting),
  3/4 RSA-OAEP-SHA256/SHA1, 5/6 the same with HMAC (legacy), 7 COSE (not supported: fails that item only).
- Per-item key: `cipher.key` is the item key wrapped by the user (or organization) key.
- Organization keys: RSA-OAEP-SHA1 with the user's private key (`privateKey` from `/api/sync`
  profile, itself a type 2 EncString under the user key).
- URI checksum: `uriChecksum` = base64(SHA-256(uri)), encrypted; a mismatch drops that URI.
- Attachments v2: `POST /api/ciphers/{id}/attachment/v2` → upload URL; file bytes are an EncArrayBuffer
  `[type 1 B][iv 16][mac 32][ct]` under the attachment key (wrapped by the item key).
- Send: key material = HKDF(sendKey, "bitwarden-send", "send", 64).

## Sync

- `GET /api/accounts/revision-date` (milliseconds) is the cheap "anything changed?" check.
- `GET /api/sync?excludeDomains=false` returns profile, folders, collections, ciphers, sends,
  policies, domains. Field names are PascalCase or camelCase depending on server version: read
  case-insensitively.
- Live updates: SignalR hub `/notifications/hub` (Vaultwarden speaks MessagePack only).

## Writes

- Create: `POST /api/ciphers` (personal) or `/api/ciphers/create` (org, with `collectionIds`).
- Update: `PUT /api/ciphers/{id}` with `lastKnownRevisionDate` (server rejects stale edits).
- Soft delete `PUT /api/ciphers/{id}/delete`, restore `PUT .../restore`, hard delete `DELETE /api/ciphers/{id}`.
- Bulk import (used by tests): `POST /api/ciphers/import` `{ciphers, folders, folderRelationships}`.

## Passkeys (`login.fido2Credentials`)

All fields are EncStrings except `creationDate`. Keyward's AAGUID is Bitwarden's
`d548826e-79b4-db40-a3d8-11116f7e8349`, so passkeys interoperate with the official apps and Keyguard.

Stored fields, as the official clients write and read them (checked against `bw` 2026.6, tests/e2e/interop.test.ts):
- `credentialId`: a GUID string for the usual 16-byte ids (the site sees the 16 raw bytes);
  `b64.<base64url>` for any other length.
- `keyType` `public-key`, `keyAlgorithm` `ECDSA`, `keyCurve` `P-256`; `keyValue` is the private
  key as PKCS#8 in base64url. Only ES256 is possible.
- `rpId`, `rpName`, `userHandle` (base64url), `userName`, `userDisplayName`.
- `counter` and `discoverable` are strings inside the EncString (`"0"`, `"true"`); `bw` rejects
  numbers and booleans there. Synced passkeys keep counter 0; one that already counts keeps
  counting, and Keyward saves the new value after each sign-in.
- One passkey per login item: a new one on the same item replaces the old.

Authenticator: flags UP | UV | BE | BS (+ AT on create), attestation format `none`, DER ECDSA
signatures. UV means "the vault is unlocked and the user clicked in Keyward's own UI"; protected
items (re-prompt) ask for the master password first.

Relying party ID: the page's host or a parent of it, never a public suffix (tldts with private
domains); https only, plus `localhost` names over http; IP addresses go to the browser.
Discoverable follows Bitwarden: `residentKey` required or preferred (or legacy
`requireResidentKey`).

Keyward hands a request back to the browser (security keys, phones, the browser's own store)
for: cross-origin frames (their permission policy is the browser's to check), Keyward's own
two-step-login tab, sites in the passkey exceptions, a locked vault, no passkey for the site,
no ES256 in `pubKeyCredParams`, `authenticatorAttachment: "cross-platform"`, and the user's
"Use browser or security key".

Conditional mediation (`mediation: "conditional"`, passkeys in a sign-in field's autofill): the
page shim runs the browser's own conditional request and Keyward's side by side. Keyward's
passkeys show at the top of the inline menu on fields whose `autocomplete` has the `webauthn`
token; whichever the user picks first answers, and the other is withdrawn. One waiting request
per frame (a newer one replaces it); the page's abort, navigation or tab close drops it.
