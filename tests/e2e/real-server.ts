// Smoke test against the real server (pass.catg1rl.com, behind BunkerWeb) with a dedicated test
// account. Deliberately small (one API login, then one extension login per browser) so the WAF
// has nothing to ban. Not part of `npm run e2e`.
//   node tests/e2e/real-server.ts [--create] [chromium|firefox]
// The account's credentials live in tests/.env.test (git-ignored) as KW_REAL_*; --create
// registers it first (sign-ups must be open on the server).
import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { clickText, fill, findItem, login, sel, waitForItems, waitForText, click } from "./flows.ts";
import { launch, testEnv, type Target } from "./launch.ts";
import { emptyView } from "../../src/core/vault/cipher.ts";
import { CipherType } from "../../src/core/vault/types.ts";

const args = process.argv.slice(2);
const env = testEnv();
const SERVER = env.KW_REAL_SERVER ?? "https://pass.catg1rl.com";
process.env.KW_SERVER = SERVER; // tests/lib/vw.ts reads it at import
const vw = await import("../lib/vw.ts");

let email = env.KW_REAL_EMAIL;
let password = env.KW_REAL_PASSWORD;
if (args.includes("--create")) {
  if (email) throw new Error(`tests/.env.test already has KW_REAL_EMAIL=${email}`);
  email = "keyward-test@catg1rl.com";
  password = vw.randomPassword();
  if (!(await vw.register(email, password, vw.ARGON2, "Keyward test"))) throw new Error("registration refused (account exists, or sign-ups are closed)");
  appendFileSync(join(new URL("../..", import.meta.url).pathname, "tests/.env.test"), `KW_REAL_SERVER=${SERVER}\nKW_REAL_EMAIL=${email}\nKW_REAL_PASSWORD=${password}\n`);
  console.log(`registered ${email} on ${SERVER} (credentials in tests/.env.test)`);
}
if (!email || !password) throw new Error("no KW_REAL_EMAIL / KW_REAL_PASSWORD in tests/.env.test (run with --create)");

// API: login, and one item so the extension has something to sync.
const s = await vw.login(email, password);
const data = await vw.sync(s);
if (!data.ciphers.length) await vw.importItems(s, [emptyView(CipherType.Login, { name: "Keyward smoke", login: { username: "smoke", password: "Smoke-Pass-1", passwordRevisionDate: null, totp: null, uris: [{ uri: "https://example.com", match: null }], autofillOnPageLoad: null, fido2Credentials: [] } })]);
console.log(`api: login + sync ok (${data.ciphers.length} items)`);

const targets = (args.filter((a) => !a.startsWith("--")) as Target[]).length ? (args.filter((a) => !a.startsWith("--")) as Target[]) : (["chromium", "firefox"] as Target[]);
let failed = 0;
for (const t of targets) {
  const kw = await launch(t);
  const t0 = Date.now();
  try {
    const page = await kw.openPopup();
    await login(kw, page, SERVER, email, password);
    await waitForItems(page, 1, 30_000);
    assert.ok(await findItem(kw, page, "Keyward smoke"), "synced item shows");
    const synced = Date.now() - t0;
    await click(kw, page, 'button[aria-label="Account and vault menu"]');
    await clickText(kw, page, "Lock", '[role="menuitem"]');
    await waitForText(page, "Vault is locked");
    await fill(kw, page, sel.field("Master password"), password);
    await clickText(kw, page, "Unlock");
    await waitForItems(page, 1, 15_000);
    // A write round trip through the WAF.
    const r: any = await page.evaluate(
      (v) => chrome.runtime.sendMessage({ kw: "rpc", name: "vault.save", arg: { view: v } }),
      emptyView(CipherType.SecureNote, { name: "Keyward smoke note", notes: "written by tests/e2e/real-server.ts" }) as any,
    );
    assert.ok(r?.ok, `vault.save: ${r?.error}`);
    const del: any = await page.evaluate((id) => chrome.runtime.sendMessage({ kw: "rpc", name: "vault.delete", arg: { ids: [id], permanent: true } }), r.value.id);
    assert.ok(del?.ok, `vault.delete: ${del?.error}`);
    console.log(`PASS ${t}: login + sync ${synced} ms, lock/unlock, save + delete`);
  } catch (e) {
    failed++;
    console.log(`FAIL ${t}: ${(e as Error).message}`);
  } finally {
    await kw.close();
  }
}
process.exit(failed ? 1 : 0);
