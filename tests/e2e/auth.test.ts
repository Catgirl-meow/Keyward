// P1: login (PBKDF2, Argon2id), wrong password, lock/unlock, PIN, browser restart, TOTP and email 2FA.
// Runs against the local Vaultwarden (scripts/dev-server.sh up && node scripts/seed.ts).
//   KW_TARGET=chromium|firefox node --test tests/e2e/auth.test.ts
import assert from "node:assert/strict";
import { after, before, describe, test as nodeTest } from "node:test";
import type { Page } from "puppeteer-core";
import { click, clickText, fill, findItem, login, sel, waitForItems, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { enableAuthenticator, enableEmail2fa, latestMailTo, login as apiLogin, randomPassword, register, totpNow, uniqueEmail } from "../lib/vw.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
const SERVER = env.KW_SERVER;
const shot = (kw: Keyward, page: Page, name: string) => kw.screenshot(page, `tests/.artifacts/auth-${target}-${name}.png`).catch(() => {});

async function lockViaMenu(kw: Keyward, page: Page) {
  await click(kw, page, 'button[aria-label="Account and vault menu"]');
  await clickText(kw, page, "Lock", '[role="menuitem"]');
  await waitForText(page, "Vault is locked");
}

async function unlock(kw: Keyward, page: Page, secret: string, label = "Master password") {
  await fill(kw, page, sel.field(label), secret);
  await clickText(kw, page, "Unlock");
}

let kw: Keyward;
let page: Page;

/** node:test `test` that leaves a screenshot and the page text behind when it fails. */
function test(name: string, fn: () => Promise<void> | void) {
  nodeTest(name, async () => {
    try {
      await fn();
    } catch (e) {
      const slug = name.replace(/\W+/g, "-").slice(0, 40);
      await shot(kw, page, `FAIL-${slug}`);
      const text = await page?.evaluate("document.body.innerText").catch(() => "");
      console.log(`--- page text at failure (${name}):\n${String(text).slice(0, 800)}`);
      throw e;
    }
  });
}

describe(`auth (${target})`, () => {
  const errors: string[] = [];

  before(async () => {
    kw = await launch(target);
    page = await kw.openPopup();
    page.on("pageerror", (e) => errors.push(String(e)));
  });
  after(async () => {
    await kw?.close();
  });

  test("wrong master password is rejected", async () => {
    await login(kw, page, SERVER, env.KW_MAIN_EMAIL, "definitely-wrong");
    await page.waitForSelector(".banner.error", { timeout: 20_000 });
    const msg = await page.$eval(".banner.error", (e) => e.textContent ?? "");
    assert.match(msg, /password is incorrect|invalid/i);
  });

  test("PBKDF2 login shows the seeded vault", async () => {
    await fill(kw, page, sel.field("Master password"), env.KW_MAIN_PASSWORD);
    await clickText(kw, page, "Log in");
    assert.equal(await waitForItems(page, 20), 28, "28 live items (30 seeded, 2 in trash)");
    for (const n of ["GitHub", "Mailfence", "Visa (test)", "SSH laptop", "Кириллица — Госуслуги"]) assert.ok(await findItem(kw, page, n), `missing ${n}`);
    assert.ok(!(await findItem(kw, page, "Note 3")), "trashed item listed");
    await shot(kw, page, "vault");
  });

  test("lock and unlock with the master password", async () => {
    await lockViaMenu(kw, page);
    await unlock(kw, page, "wrong-password");
    await page.waitForSelector(".banner.error");
    await unlock(kw, page, env.KW_MAIN_PASSWORD);
    await waitForItems(page, 20, 10_000);
  });

  test("PIN unlock", async () => {
    await clickText(kw, page, "Settings", ".navbar button");
    await clickText(kw, page, "Security");
    await clickText(kw, page, "Unlock with PIN", ".item");
    await fill(kw, page, sel.field("PIN"), "2468");
    await fill(kw, page, sel.field("Repeat PIN"), "2468");
    await clickText(kw, page, "Save");
    await waitForText(page, "Change PIN");
    await clickText(kw, page, "Vault", ".navbar button");
    await lockViaMenu(kw, page);
    await page.waitForSelector(sel.field("PIN"));
    await unlock(kw, page, "1111", "PIN");
    await waitForText(page, "attempts left");
    await unlock(kw, page, "2468", "PIN");
    await waitForItems(page, 20, 10_000);
  });

  test("browser restart locks the vault; unlock works", async () => {
    const profile = kw.profile;
    await kw.close();
    kw = await launch(target, { profile });
    page = await kw.openPopup();
    await waitForText(page, "Vault is locked");
    // Session-only PIN: after a restart the master password is required.
    assert.equal(await page.$(sel.field("PIN")), null, "PIN offered after restart without 'survive restart'");
    await unlock(kw, page, env.KW_MAIN_PASSWORD);
    await waitForItems(page, 20, 15_000);
    assert.ok(await findItem(kw, page, "GitHub"));
  });

  test("Argon2id login", async () => {
    await click(kw, page, 'button[aria-label="Account and vault menu"]');
    await clickText(kw, page, "Add account", '[role="menuitem"]');
    await login(kw, page, SERVER, env.KW_ARGON_EMAIL, env.KW_ARGON_PASSWORD);
    await waitForItems(page, 5, 40_000);
    assert.ok(await findItem(kw, page, "GitHub"));
  });

  test("authenticator (TOTP) two-step login", async () => {
    const email = uniqueEmail("totp");
    const pw = randomPassword();
    const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    await register(email, pw);
    await enableAuthenticator(await apiLogin(email, pw).catch(() => { throw new Error("api login"); }), pw, secret);
    await click(kw, page, 'button[aria-label="Account and vault menu"]');
    await clickText(kw, page, "Add account", '[role="menuitem"]');
    await login(kw, page, SERVER, email, pw);
    await waitForText(page, "Two-step login", 20_000);
    // The setup code used this time step; Vaultwarden rejects reuse, so answer with the next one.
    await fill(kw, page, sel.field("Code"), await totpNow(secret, 30));
    await waitForText(page, "Your vault is empty", 20_000);
  });

  test("email two-step login (code read from mailpit)", async () => {
    const email = uniqueEmail("mail");
    const pw = randomPassword();
    await register(email, pw);
    await enableEmail2fa(await apiLogin(email, pw), pw, email);
    await click(kw, page, 'button[aria-label="Account and vault menu"]');
    await clickText(kw, page, "Add account", '[role="menuitem"]');
    const since = Date.now() - 500;
    await login(kw, page, SERVER, email, pw);
    await waitForText(page, "Two-step login", 20_000);
    const mail = await latestMailTo(email, since);
    const code = mail?.text.match(/\b(\d{6})\b/)?.[1];
    assert.ok(code, "no login code mail");
    await fill(kw, page, sel.field("Code"), code!);
    await waitForText(page, "Your vault is empty", 20_000);
    await shot(kw, page, "email-2fa-done");
  });

  test("timed lock sets a single alarm at the deadline", async () => {
    await page.evaluate(`chrome.storage.local.get("settings").then(({ settings }) => chrome.storage.local.set({ settings: { ...settings, lockTimeout: 5 } }))`);
    await new Promise((r) => setTimeout(r, 300));
    const alarms = await kw.bg<{ name: string; scheduledTime: number }[]>("chrome.alarms.getAll()");
    const lock = alarms.filter((a) => a.name.startsWith("lock:"));
    assert.equal(lock.length, 1, JSON.stringify(alarms));
    const mins = (lock[0].scheduledTime - Date.now()) / 60_000;
    assert.ok(mins > 4.5 && mins <= 5.01, `deadline in ${mins} min`);
    assert.ok(alarms.some((a) => a.name === "sync"), "5-minute sync alarm missing");
  });

  test("'Never' keeps the vault unlocked across a restart", async () => {
    await page.evaluate(`chrome.storage.local.get("settings").then(({ settings }) => chrome.storage.local.set({ settings: { ...settings, lockTimeout: -2 } }))`);
    await new Promise((r) => setTimeout(r, 500));
    const profile = kw.profile;
    await kw.close();
    kw = await launch(target, { profile });
    page = await kw.openPopup();
    // The active account is the last one added (empty vault): unlocked means the vault list renders.
    await page.waitForSelector(".vault-list", { timeout: 15_000 });
    // Back to the default so later runs start locked.
    await page.evaluate(`chrome.storage.local.get("settings").then(({ settings }) => chrome.storage.local.set({ settings: { ...settings, lockTimeout: -1 } }))`);
    // Leaving "Never" drops the keys once the unlocks still writing them are done: poll, don't sleep.
    let persisted = -1;
    for (const end = Date.now() + 10_000; Date.now() < end; await new Promise((r) => setTimeout(r, 200))) {
      persisted = (await page.evaluate(`chrome.storage.local.get(null).then((all) => Object.keys(all).filter((k) => k.startsWith("persistKey:")).length)`)) as number;
      if (persisted === 0) break;
    }
    assert.equal(persisted, 0, "persisted key left behind after leaving 'Never'");
  });

  test("no uncaught page errors", () => {
    assert.deepEqual(errors, []);
  });
});
