// P7: GPG key items and the GPG tools, checked against the real gpg (a throwaway home dir):
// a key Keyward makes works in gpg and is stored the way Keyguard stores it; gpg's keys,
// signatures and messages open in Keyward; what Keyward signs and encrypts opens in gpg.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test as nodeTest } from "node:test";
import type { Page } from "puppeteer-core";
import { click, clickText, fill, login, sel, settle, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { importItems, login as apiLogin, randomPassword, register, uniqueEmail, type Session } from "../lib/vw.ts";
import { decodeGpgFields, encodeGpgFields, GPG_FIELD } from "../../src/core/gpg/fields.ts";
import { decryptCipher, emptyView } from "../../src/core/vault/cipher.ts";
import { CipherType, type CipherView } from "../../src/core/vault/types.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
let kw: Keyward;
let page: Page;
let api: Session;
const email = uniqueEmail("gpg");
const password = randomPassword();
const home = mkdtempSync(join(tmpdir(), "keyward-e2e-gpg-"));

function test(name: string, fn: () => Promise<void>) {
  nodeTest(name, async () => {
    try {
      await fn();
    } catch (e) {
      await kw.screenshot(page, `tests/.artifacts/gpg-${target}-FAIL-${name.replace(/\W+/g, "-").slice(0, 40)}.png`).catch(() => {});
      console.log(`--- page text (${name}):\n${String(await page.evaluate("document.body.innerText").catch(() => "")).slice(0, 800)}`);
      throw e;
    }
  });
}

/** gpg in the throwaway home; `pass` unlocks protected keys without a pinentry window. */
const gpg = (args: string[], input?: string, pass = "") =>
  execFileSync("gpg", ["--homedir", home, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", pass, ...args], { input, stdio: ["pipe", "pipe", "pipe"] }).toString();
const gpgStatus = (args: string[], input?: string) => {
  try {
    return execFileSync("gpg", ["--homedir", home, "--batch", "--status-fd", "1", ...args], { input, stdio: ["pipe", "pipe", "pipe"] }).toString();
  } catch (e: any) {
    return String(e.stdout) + String(e.stderr);
  }
};
const fingerprintOf = (who: string) => /fpr:::::::::([0-9A-F]{40}):/.exec(gpg(["--with-colons", "--fingerprint", who]))![1];

const area = (label: string) => `textarea[aria-label="${label}"]`;
const valueOf = (selector: string) => page.$eval(selector, (e) => (e as HTMLTextAreaElement).value);
async function choose(label: string, text: string) {
  await page.$eval(`select[aria-label="${label}"]`, (el, t) => {
    const s = el as HTMLSelectElement;
    s.value = [...s.options].find((o) => o.text.includes(t))!.value;
    s.dispatchEvent(new Event("change", { bubbles: true }));
  }, text);
}
async function serverItem(name: string): Promise<CipherView | undefined> {
  const data = await api.api.get("/sync?excludeDomains=true");
  const views: CipherView[] = await Promise.all(data.ciphers.map((c: any) => decryptCipher(c, api.ring)));
  return views.find((v) => v.name === name);
}
async function until<T>(fn: () => Promise<T | undefined | false>, ms = 15_000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v as T;
    if (Date.now() > end) throw new Error("condition not met");
    await new Promise((r) => setTimeout(r, 250));
  }
}
async function newGpgItem() {
  await clickText(kw, page, "Vault", "nav button");
  await clickText(kw, page, "New", "button.fab");
  await clickText(kw, page, "GPG key", '[role="menuitem"]');
  await page.waitForSelector(".item-edit", { timeout: 8000 });
}
async function openTools(mode: string) {
  if (!(await page.$(".gpg-tools"))) {
    await clickText(kw, page, "Settings", "nav button");
    await clickText(kw, page, "GPG tools", ".settings .item");
    await page.waitForSelector(".gpg-tools", { timeout: 8000 });
  }
  await clickText(kw, page, mode, ".gpg-tools .chip");
  await settle(page);
}
async function toolsBack() {
  await clickText(kw, page, "Vault", "nav button");
}

describe(`gpg (${target})`, () => {
  before(async () => {
    // gpg makes an RSA 4096 key: too long for one field, so it is stored in Keyguard's chunks.
    gpg(["--quick-generate-key", "Gee <gee@example.test>", "rsa4096", "default", "never"]);
    const fp = fingerprintOf("gee@example.test");
    gpg(["--quick-add-key", fp, "rsa4096", "encr", "never"]);
    const fields = await encodeGpgFields({ privateKey: gpg(["--armor", "--export-secret-keys", fp]), publicKey: gpg(["--armor", "--export", fp]), fingerprint: fp }, [{ type: 0, name: "Owner", value: "gee", linkedId: null }]);
    assert.ok(fields.some((f) => f.name === `${GPG_FIELD.privateKey}.v1.part.2`), "the seeded key is chunked");
    await register(email, password);
    api = await apiLogin(email, password);
    await importItems(api, [emptyView(CipherType.SecureNote, { name: "Gee's key", fields })]);
    kw = await launch(target);
    page = await kw.openPopup();
    page.on("pageerror", (e) => console.log("PAGEERROR", (e as Error).message));
    await login(kw, page, env.KW_SERVER, email, password);
    await waitForText(page, "Gee's key", 30_000);
  });
  after(async () => {
    await kw?.close();
    try {
      execFileSync("gpgconf", ["--homedir", home, "--kill", "all"]);
    } catch {}
    rmSync(home, { recursive: true, force: true });
  });

  test("a Keyguard GPG key item shows as a GPG key, chunked fields and all", async () => {
    await clickText(kw, page, "Gee's key", ".vault-list .item");
    await waitForText(page, "Gee <gee@example.test>");
    const text = await page.evaluate(() => document.body.innerText);
    assert.match(text, /RSA 4096/);
    assert.ok(text.includes(fingerprintOf("gee@example.test").replace(/(.{4})(?=.)/g, "$1 ")), "spaced fingerprint");
    assert.match(text, /GPG key/);
    assert.ok(text.includes("Owner"), "the user's own field stays");
    assert.ok(!text.includes("keyguard.gpg"), "the key fields are not shown as custom fields");
    await click(kw, page, '.topbar button[aria-label="Back"]');
  });

  test("a generated key is saved in Keyguard's fields and works in gpg", async () => {
    await newGpgItem();
    await fill(kw, page, sel.field("Your name"), "Kay");
    await fill(kw, page, sel.field("Email"), "kay@example.test");
    await clickText(kw, page, "Generate key", ".item-edit button");
    await waitForText(page, "Remove key", 20_000);
    assert.equal(await page.$eval(sel.field("Name"), (e) => (e as HTMLInputElement).value), "Kay <kay@example.test>");
    await clickText(kw, page, "Save", ".topbar button");
    await page.waitForSelector(".item-view", { timeout: 10_000 });
    await waitForText(page, "Ed25519");
    await settle(page);
    await new Promise((r) => setTimeout(r, 2500)); // let the "Item created" toast go
    await kw.screenshot(page, `tests/.artifacts/gpg-${target}-item.png`);
    const v = await until(() => serverItem("Kay <kay@example.test>"));
    assert.equal(v.type, CipherType.SecureNote);
    assert.deepEqual(v.fields.map((f) => [f.name, f.type]), [[GPG_FIELD.privateKey, 1], [GPG_FIELD.publicKey, 0], [GPG_FIELD.fingerprint, 0]]);
    const key = (await decodeGpgFields(v.fields))!.key;
    gpg(["--import"], key.privateKey!);
    assert.equal(fingerprintOf("kay@example.test"), key.fingerprint);
    assert.match(gpg(["--with-colons", "--list-keys", "kay@example.test"]), /^pub:[^:]*:255:22:.*\nfpr[\s\S]*^sub:[^:]*:255:18:/m);
  });

  test("an imported key with its own passphrase asks for it before signing", async () => {
    gpg(["--quick-generate-key", "Pat <pat@example.test>", "default", "default", "never"], undefined, "pat-pass");
    const armored = gpg(["--armor", "--export-secret-keys", fingerprintOf("pat@example.test")], undefined, "pat-pass");
    await newGpgItem();
    await clickText(kw, page, "Import", ".item-edit .chip");
    await fill(kw, page, area("Armored key"), armored);
    await clickText(kw, page, "Import key", ".item-edit button");
    await waitForText(page, "passphrase-protected", 15_000);
    await clickText(kw, page, "Save", ".topbar button");
    await page.waitForSelector(".item-view", { timeout: 10_000 });

    await openTools("Sign");
    await choose("Sign with", "Pat");
    await fill(kw, page, area("Text to sign"), "signed with a protected key\n");
    await clickText(kw, page, "Sign", ".gpg-tools button.btn");
    await page.waitForSelector(sel.field("Key passphrase"), { timeout: 10_000 });
    await fill(kw, page, sel.field("Key passphrase"), "wrong");
    await clickText(kw, page, "Sign", ".gpg-tools button.btn");
    await waitForText(page, "Wrong passphrase");
    await fill(kw, page, sel.field("Key passphrase"), "pat-pass");
    await clickText(kw, page, "Sign", ".gpg-tools button.btn");
    await page.waitForSelector(area("Signed text"), { timeout: 15_000 });
    assert.match(gpgStatus(["--verify"], await valueOf(area("Signed text"))), new RegExp(`GOODSIG ${fingerprintOf("pat@example.test").slice(-16)}`));
    await toolsBack();
  });

  test("GPG tools: sign, verify, encrypt and decrypt with gpg on the other side", async () => {
    const kay = fingerprintOf("kay@example.test");
    const gee = fingerprintOf("gee@example.test");

    await openTools("Sign");
    await choose("Sign with", "Kay");
    await choose("Signature", "Detached");
    await fill(kw, page, area("Text to sign"), "detached body");
    await clickText(kw, page, "Sign", ".gpg-tools button.btn");
    await page.waitForSelector(area("Signature"), { timeout: 15_000 });
    writeFileSync(join(home, "body.txt"), "detached body");
    writeFileSync(join(home, "body.txt.asc"), await valueOf(area("Signature")));
    assert.match(gpgStatus(["--verify", join(home, "body.txt.asc"), join(home, "body.txt")]), new RegExp(`GOODSIG ${kay.slice(-16)}`));

    await openTools("Verify");
    await fill(kw, page, area("Signed text or signature"), gpg(["--clearsign", "--local-user", gee], "signed by gpg\n"));
    await clickText(kw, page, "Verify", ".gpg-tools button.btn");
    await waitForText(page, "Good signature from Gee <gee@example.test>");
    await fill(kw, page, area("Signed text or signature"), gpg(["--clearsign", "--local-user", gee], "signed by gpg\n").replace("signed by gpg", "signed by gpG"));
    await clickText(kw, page, "Verify", ".gpg-tools button.btn");
    await waitForText(page, "Bad signature from Gee");

    await openTools("Encrypt");
    await clickText(kw, page, "Gee's key", ".gpg-tools .item");
    await choose("Sign with", "Kay");
    await fill(kw, page, area("Text to encrypt"), "for gee, from kay");
    await clickText(kw, page, "Encrypt", ".gpg-tools button.btn");
    await page.waitForSelector(area("Encrypted message"), { timeout: 15_000 });
    const enc = await valueOf(area("Encrypted message"));
    assert.equal(gpg(["--decrypt"], enc), "for gee, from kay");
    assert.match(gpgStatus(["--decrypt"], enc), new RegExp(`GOODSIG ${kay.slice(-16)}`));

    await openTools("Decrypt");
    await fill(kw, page, area("Encrypted message"), gpg(["--trust-model", "always", "--armor", "--encrypt", "--sign", "--local-user", gee, "--recipient", kay], "for kay, from gee"));
    await clickText(kw, page, "Decrypt", ".gpg-tools button.btn");
    await page.waitForSelector(area("Decrypted text"), { timeout: 15_000 });
    assert.equal(await valueOf(area("Decrypted text")), "for kay, from gee");
    await waitForText(page, "Good signature from Gee <gee@example.test>");
    await kw.screenshot(page, `tests/.artifacts/gpg-${target}-tools.png`);
    await toolsBack();
  });

  test("GPG keys have their own filter", async () => {
    await page.waitForSelector(".vault-list", { timeout: 8000 });
    await fill(kw, page, 'input[aria-label="Search vault"]', "type:gpg");
    await page.waitForFunction(() => document.querySelectorAll(".vault-list .item").length === 3, { timeout: 8000 });
    const names = await page.$$eval(".vault-list .item .title", (els) => els.map((e) => e.textContent ?? "").sort());
    assert.deepEqual(names.map((n) => n.split(" ")[0]), ["Gee's", "Kay", "Pat"]);
  });
});
