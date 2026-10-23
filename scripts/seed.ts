// Seeds the local Vaultwarden (scripts/dev-server.sh up) with test accounts and items, and writes
// their credentials to tests/.env.test (git-ignored).
//   node scripts/seed.ts [--perf=2000]
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { decryptCipher, emptyView } from "../src/core/vault/cipher.ts";
import { CipherType, FieldType, type CipherView, type Fido2View } from "../src/core/vault/types.ts";
import { generateEd25519 } from "../src/core/ssh/keys.ts";
import { toB64Url } from "../src/core/util/bytes.ts";
import { ARGON2, PBKDF2, SERVER, importItems, login, randomPassword, register, sync } from "../tests/lib/vw.ts";

const root = new URL("..", import.meta.url).pathname;
const ENV = join(root, "tests/.env.test");
const args = new Map(process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=") as [string, string]));
const PERF = Number(args.get("perf") ?? 2000);

// Fixed TOTP secret so tests can compute the expected code (RFC 6238 test key, base32).
export const TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

// Small deterministic PRNG: the same seed gives the same vault on every run.
let state = 0x9e3779b9;
const rnd = () => ((state = Math.imul(state ^ (state >>> 15), 0x2c1b3c6d) ^ Math.imul(state ^ (state >>> 12), 0x297a2d39)) >>> 0) / 2 ** 32;
const pick = <T>(a: readonly T[]) => a[Math.floor(rnd() * a.length)];
const pw = (n = 18) => Array.from({ length: n }, () => pick([..."abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_"])).join("");

function loginItem(name: string, uris: [string, number | null][], username: string, extra: Partial<CipherView> = {}, totp: string | null = null): CipherView & { folder?: string } {
  return emptyView(CipherType.Login, {
    name,
    login: {
      username,
      password: pw(),
      passwordRevisionDate: null,
      totp,
      uris: uris.map(([uri, match]) => ({ uri, match: match as any })),
      autofillOnPageLoad: null,
      fido2Credentials: [],
    },
    ...extra,
  });
}

async function passkey(rpId: string, userName: string): Promise<Fido2View> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  return {
    credentialId: crypto.randomUUID(),
    keyType: "public-key",
    keyAlgorithm: "ECDSA",
    keyCurve: "P-256",
    keyValue: toB64Url(pkcs8),
    rpId,
    userHandle: toB64Url(crypto.getRandomValues(new Uint8Array(16))),
    userName,
    counter: 0,
    rpName: rpId,
    userDisplayName: userName,
    discoverable: true,
    creationDate: new Date().toISOString(),
  } as Fido2View;
}

const FOLDERS = ["Work", "Personal", "Finance", "Dev", "Shopping"];

async function mainVault(email: string): Promise<(CipherView & { folder?: string })[]> {
  const items: (CipherView & { folder?: string })[] = [];
  const add = (v: CipherView, folder?: string) => items.push(Object.assign(v, { folder }));
  // Logins chosen to exercise matching: base domain, host, starts-with, exact, regex, never, ports, IPs.
  add(loginItem("GitHub", [["https://github.com/login", null]], "octo-tester", { favorite: true }, `otpauth://totp/GitHub:octo-tester?secret=${TOTP_SECRET}&issuer=GitHub`), "Dev");
  add(loginItem("GitLab", [["https://gitlab.com", 0]], "tester@example.test"), "Dev");
  add(loginItem("Mailfence", [["https://mailfence.com", null]], "kw-tester", { favorite: true }, TOTP_SECRET), "Personal");
  add(loginItem("Google", [["https://accounts.google.com", 1], ["https://google.com", 0]], "kw.tester@gmail.com"), "Personal");
  add(loginItem("Microsoft", [["https://login.live.com", 1], ["https://login.microsoftonline.com", 1]], "kw.tester@outlook.com"), "Work");
  add(loginItem("Yandex", [["https://passport.yandex.ru", 0]], "kw-tester"), "Personal");
  add(loginItem("Router", [["http://192.168.1.1", null]], "admin"), "Personal");
  add(loginItem("Fixture site", [["http://localhost:8090", 1]], "fixture-user"), "Dev");
  add(loginItem("Fixture site (second user)", [["http://localhost:8090", 1]], "fixture-user-2"), "Dev");
  add(loginItem("Starts-with match", [["https://example.com/app/", 2]], "prefix-user"));
  add(loginItem("Exact match", [["https://example.com/exact?x=1", 3]], "exact-user"));
  add(loginItem("Regex match", [["^https://(www\\.)?example\\.org/.*$", 4]], "regex-user"));
  add(loginItem("Never match", [["https://example.net", 5]], "never-user"));
  add(loginItem("Bank (reprompt)", [["https://bank.example.test", null]], "kw-saver", { reprompt: 1, favorite: true }), "Finance");
  add(loginItem("Webauthn demo", [["https://webauthn.io", null]], "kw-passkey", {}), "Dev");
  items[items.length - 1].login!.fido2Credentials = [await passkey("webauthn.io", "kw-passkey")];
  const withFields = loginItem("Custom fields", [["https://fields.example.test", null]], "fields-user", {
    fields: [
      { type: FieldType.Text, name: "PIN hint", value: "birthday", linkedId: null },
      { type: FieldType.Hidden, name: "Security answer", value: "Blue whale", linkedId: null },
      { type: FieldType.Boolean, name: "Has 2FA", value: "true", linkedId: null },
      { type: FieldType.Linked, name: "login_field", value: null, linkedId: 100 },
    ],
    passwordHistory: [
      { password: "old-password-1", lastUsedDate: "2025-01-01T00:00:00.000Z" },
      { password: "old-password-2", lastUsedDate: "2024-06-01T00:00:00.000Z" },
    ],
    notes: "Login with every kind of custom field and some password history.",
  });
  add(withFields, "Work");
  add(loginItem("Weak and reused A", [["https://weak-a.example.test", null]], "weak", {}), "Shopping");
  items[items.length - 1].login!.password = "password123";
  add(loginItem("Weak and reused B", [["https://weak-b.example.test", null]], "weak", {}), "Shopping");
  items[items.length - 1].login!.password = "password123";
  add(loginItem("Plain HTTP site", [["http://insecure.example.test", null]], "http-user"));
  add(loginItem("Кириллица — Госуслуги", [["https://esia.gosuslugi.ru", null]], "+7 900 000-00-00"), "Personal");
  add(loginItem("No URL login", [], "nourl"));

  add(emptyView(CipherType.Card, { name: "Visa (test)", card: { cardholderName: "KW Tester", brand: "Visa", number: "4111111111111111", expMonth: "12", expYear: "2030", code: "123" } }), "Finance");
  add(emptyView(CipherType.Card, { name: "Mastercard (test)", card: { cardholderName: "KW Tester", brand: "Mastercard", number: "5555555555554444", expMonth: "03", expYear: "2029", code: "321" } }), "Finance");
  add(emptyView(CipherType.Card, { name: "Mir (test)", card: { cardholderName: "KW TESTER", brand: "Mir", number: "2200000000000004", expMonth: "07", expYear: "2028", code: "777" } }), "Finance");
  const id = emptyView(CipherType.Identity, { name: "Personal identity" });
  Object.assign(id.identity!, { title: "Mx", firstName: "Kay", lastName: "Ward", email, phone: "+1 555 0100", address1: "1 Test Street", city: "Testville", state: "TS", postalCode: "12345", country: "US", username: "kayward" });
  add(id, "Personal");
  for (let i = 1; i <= 3; i++) add(emptyView(CipherType.SecureNote, { name: `Note ${i}`, notes: `Secure note ${i}\nSecond line with a code: ${pw(8)}` }));
  for (const c of ["laptop", "server"]) {
    const k = await generateEd25519(`kw-${c}`);
    add(emptyView(CipherType.SshKey, { name: `SSH ${c}`, sshKey: { privateKey: k.privateKey, publicKey: k.publicKey, keyFingerprint: k.fingerprint } }), "Dev");
  }
  return items;
}

const WORDS = "alpha bravo cedar delta ember fable gamma harbor iris jade kilo lumen mango nova onyx pixel quartz raven sierra tango umbra vortex willow xenon yarrow zephyr".split(" ");
const TLDS = ["com", "net", "org", "io", "ru", "de", "dev", "app"];
function perfVault(n: number): CipherView[] {
  const out: CipherView[] = [];
  for (let i = 0; i < n; i++) {
    const w = `${pick(WORDS)}${pick(WORDS)}`;
    const r = rnd();
    if (r < 0.8) out.push(loginItem(`${w} ${i}`, [[`https://${rnd() < 0.3 ? "login." : ""}${w}.${pick(TLDS)}`, null]], `user${i}@${pick(WORDS)}.test`, { favorite: rnd() < 0.05 }, rnd() < 0.1 ? TOTP_SECRET : null));
    else if (r < 0.88) out.push(emptyView(CipherType.SecureNote, { name: `Note ${w} ${i}`, notes: pw(200) }));
    else if (r < 0.95) out.push(emptyView(CipherType.Card, { name: `Card ${w}`, card: { cardholderName: w, brand: "Visa", number: "4111111111111111", expMonth: "01", expYear: "2031", code: "000" } }));
    else out.push(emptyView(CipherType.Identity, { name: `Identity ${w}` }));
  }
  return out;
}

function readEnv(): Record<string, string> {
  if (!existsSync(ENV)) return {};
  return Object.fromEntries(readFileSync(ENV, "utf8").split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
}

const env = readEnv();
const accounts = [
  { key: "MAIN", email: "alice@keyward.test", kdf: PBKDF2, items: (e: string) => mainVault(e), folders: FOLDERS },
  { key: "ARGON", email: "bob@keyward.test", kdf: ARGON2, items: async (e: string) => (await mainVault(e)).slice(0, 8), folders: FOLDERS.slice(0, 2) },
  { key: "PERF", email: "perf@keyward.test", kdf: PBKDF2, items: async () => perfVault(PERF), folders: ["Bulk"] },
];

const t0 = Date.now();
for (const a of accounts) {
  const password = env[`KW_${a.key}_PASSWORD`] && env[`KW_${a.key}_EMAIL`] === a.email ? env[`KW_${a.key}_PASSWORD`] : randomPassword();
  const created = await register(a.email, password, a.kdf);
  if (!created) {
    console.log(`${a.email}: exists, skipped (restart the dev server for a fresh vault)`);
    continue;
  }
  const s = await login(a.email, password);
  const items = await a.items(a.email);
  await importItems(s, items, a.folders);
  const data = await sync(s);
  // A couple of trashed items so Trash and restore have something to show.
  if (a.key === "MAIN") {
    for (const raw of data.ciphers) {
      const v = await decryptCipher(raw, s.ring);
      if (v.name === "Note 3" || v.name === "No URL login") await s.api.put(`/ciphers/${raw.id}/delete`);
    }
  }
  env[`KW_${a.key}_EMAIL`] = a.email;
  env[`KW_${a.key}_PASSWORD`] = password;
  console.log(`${a.email}: ${data.ciphers.length} items, ${data.folders.length} folders (${a.kdf.type === 1 ? "Argon2id" : "PBKDF2"})`);
}
env.KW_SERVER = SERVER;
env.KW_TOTP_SECRET = TOTP_SECRET;
writeFileSync(ENV, Object.entries(env).map(([k, v]) => `${k}=${v}`).join("\n") + "\n", { mode: 0o600 });
console.log(`wrote ${ENV} in ${((Date.now() - t0) / 1000).toFixed(1)} s`);
