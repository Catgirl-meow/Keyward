# Audit: official Bitwarden browser extension 2026.9.3

Measured on 2026-10-15 on the build installed in Helium (Chromium 154), using its shipped files and
source maps, with the `bitwarden/clients` repository as reference. Keyward's design answers each
finding (last column).

## Size and startup

| Finding | Evidence | Keyward |
|---|---|---|
| 84 MB unpacked | extension folder size | ~0.6 MB unpacked (budget ≤ 2 MB) |
| Popup parses ~6.7 MB of JavaScript and waits for a 7.5 MB WASM SDK; the SDK ships twice (popup + background) | file sizes, popup network panel | popup startup JS ~31 KB gz; no SDK; WebCrypto only; Argon2 WASM (~8 KB) loads only on unlock with Argon2 accounts |
| Background is 3.3 MB and constructs ~162 services in sequence on every service-worker wake | `background.js` bootstrap, service container | every listener registered synchronously; nothing runs on wake beyond the triggering event |
| 10 s timers (lock check, desktop-app reconnect) keep the worker busy | `setInterval` in background | no timers; one `chrome.alarms` deadline per account, 5 min sync alarm only while unlocked |

## Every page

| Finding | Evidence | Keyward |
|---|---|---|
| A 1.7 MB autofill bootstrap is injected into every frame at `document_start` | manifest `content_scripts` | ≤ 3 KB bootstrap at `document_idle`: one passive `focusin` listener |
| It runs a document-wide `MutationObserver` that rescans the whole page after changes (tab lag: bitwarden/clients#20172, #17090, #21453) | `collectAutofillContentService`, `domQueryService` | no page scans; the autofill script is injected into one frame on demand; a form-scoped observer only while a menu or save prompt is active |

## Vault and decryption

| Finding | Evidence | Keyward |
|---|---|---|
| The whole vault is decrypted eagerly and cached as one encrypted JSON blob | `CipherService.decryptedCiphers` cache | 32 AES-GCM sealed summary buckets; secrets decrypted only for a detail view or a fill |
| ~25 edit paths clear that cache, so any single edit re-decrypts and rewrites the whole vault | `clearCache()` call sites | an edit patches one bucket |
| URL matching scans every item (memory blow-up, #15899) | `getAllDecryptedForUrl` | domain → id index; O(1) lookup plus a short list of starts-with/exact/regex URIs |

## Vaultwarden compatibility

| Finding | Evidence | Keyward |
|---|---|---|
| Strict server-response parsing via the SDK broke vaults on Vaultwarden: 2026.7 showed an empty vault, 2026.8 failed with a `RangeError` when a policy lacked `revisionDate` | issue reports, SDK deserializers | tolerant parsing; each item decrypts on its own; one bad item shows as "can't decrypt" instead of hiding the vault |
| Core features gated on server feature flags (basic-auth fill hidden in 2026.9) | `ConfigService.getFeatureFlag` | no feature depends on a server flag |
| The official CLI 2026.10.0 cannot log in to Vaultwarden 1.37.2 at all: a post-login "user key id backfill" migration posts to an endpoint Vaultwarden lacks (404) and aborts the login. 2026.6.0 works. | reproduced 2026-10-15 in `tests/e2e/interop.test.ts` | Keyward runs no client-side migrations against the server; unknown endpoints are never on the login path |

## Autofill accuracy

| Finding | Evidence | Keyward |
|---|---|---|
| Spurious save/update prompts (#17405) | notification background | prompt only after a trusted input in a password field, a submit signal and a navigation or field removal; never when the password equals what we filled |
| Wrong-tab fills (#23529) | `tab` captured before an async gap | fill by `tabId` + `frameId`, re-checking the frame URL with `webNavigation.getFrame` right before filling |
| Multi-step logins and the TOTP step (mailfence.com) are missed | user report | per-tab login-flow record: the item chosen at the username step fills the password step and the TOTP step |

## Method

- Static: unpacked the installed extension, read `manifest.json`, measured files, followed the
  source maps for the services named above.
- Runtime: Chromium DevTools performance and memory panels on heavy pages with the extension on
  and off; REA (`observe_web_session`) for repeatable captures. The same harness runs Keyward
  (`npm run perf`) so the numbers stay comparable.
