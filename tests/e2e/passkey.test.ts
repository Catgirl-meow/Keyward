// P5: Keyward as a passkey provider. A relying party (tests/fixtures/rp.ts, verified by
// @simplewebauthn/server) creates and uses passkeys; Keyward's dialog answers, saves them to the
// vault in Bitwarden's format, and hands requests it shouldn't answer to the browser.
//   KW_TARGET=chromium|firefox node --test tests/e2e/passkey.test.ts
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { after, before, describe, test as nodeTest } from "node:test";
import type { CDPSession, Frame, Page } from "puppeteer-core";
import { clickText, fill, login, sel, waitForItems } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { FX, HOSTS, startFixtures } from "../fixtures/server.ts";
import { rpAddUser } from "../fixtures/rp.ts";
import { createPasskey } from "../../src/core/passkey/authenticator.ts";
import { importItems, login as apiLogin, randomPassword, register, sync, uniqueEmail, type Session } from "../lib/vw.ts";
import { decryptCipher, emptyView } from "../../src/core/vault/cipher.ts";
import { CipherType, type CipherView } from "../../src/core/vault/types.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
const email = uniqueEmail("passkey");
const password = randomPassword();
let kw: Keyward;
let ext: Page;
let api: Session;
let fixtures: Server;
const pages: Page[] = [];

function test(name: string, fn: () => Promise<void>, opts: { skip?: string | false } = {}) {
  nodeTest(name, { skip: opts.skip }, async () => {
    const first = pages.length;
    try {
      await fn();
    } catch (e) {
      const p = pages[pages.length - 1];
      if (p) await kw.screenshot(p, `tests/.artifacts/passkey-${target}-FAIL-${name.replace(/\W+/g, "-").slice(0, 40)}.png`).catch(() => {});
      throw e;
    } finally {
      // Each test's tabs go away with it: a request one of them left waiting would skew the
      // next test's counts (closing the tab drops it).
      for (const p of pages.splice(first)) await p.close().catch(() => {});
      for (let i = 0; i < 40 && (await pendingCount(true).catch(() => 0)); i++) await new Promise((r) => setTimeout(r, 50));
    }
  });
}

async function open(url: string): Promise<Page> {
  const want = new URL(url).href;
  const before = new Set(await kw.browser.pages());
  await ext.evaluate((u) => chrome.tabs.create({ url: u, active: true }), want);
  // Polls the browser's pages (LibreWolf's BiDi now and then misses a new tab's target event).
  let page: Page | undefined;
  for (const end = Date.now() + 30_000; !page && Date.now() < end; await new Promise((r) => setTimeout(r, 100)))
    page = (await kw.browser.pages()).find((p) => !before.has(p) && p.url() === want) as Page | undefined;
  if (!page) throw new Error(`tab for ${want} did not appear`);
  pages.push(page);
  await page.waitForFunction((u) => location.href === u && document.readyState === "complete", { timeout: 30_000, polling: 50 }, want);
  await page.bringToFront();
  return page;
}

const result = (p: Page, re: RegExp, timeout = 15_000) =>
  p.waitForFunction((src) => new RegExp(src).test(document.getElementById("result")!.textContent ?? ""), { timeout, polling: 100 }, re.source).then(() => p.$eval("#result", (e) => e.textContent ?? ""));

/** Requests waiting in the background; autofill (conditional) ones only with `all`. */
const pendingCount = (all = false) =>
  ext.evaluate((all) => chrome.storage.session.get(null).then((o) => Object.keys(o).filter((k) => k.startsWith("pk:") && (all || !(o[k] as any).conditional)).length), all);

const isDialog = (f: Frame) => f.url().startsWith("chrome-extension://") && f.url().includes("/passkey.html");

/** Keyward's overlay (a kw-… element) has the page's focus: its frame took the keyboard. */
const overlayFocused = (page: Page) => page.evaluate(() => document.activeElement?.localName.startsWith("kw-") ?? false);

/** The passkey dialog. Helium: its frame. LibreWolf (BiDi can't see extension frames): the
 * dialog taking the keyboard (its frame focuses itself when it loads); it is driven by keyboard
 * there, and a key pressed before that would land on the page. */
async function dialog(page: Page, timeout = 10_000): Promise<Frame | null> {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (target === "firefox") {
      if (await overlayFocused(page)) {
        await new Promise((r) => setTimeout(r, 600));
        return null;
      }
    } else {
      const f = page.frames().find(isDialog);
      if (f) {
        await f.waitForSelector(".kwp", { timeout: Math.max(8000, end - Date.now()) });
        await new Promise((r) => setTimeout(r, 350)); // clicks in the first 300 ms are ignored
        return f;
      }
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("passkey dialog did not appear");
}
const noDialog = async (page: Page) => {
  await new Promise((r) => setTimeout(r, 800));
  assert.equal(page.frames().some(isDialog), false, "no dialog");
  assert.equal(await pendingCount(), 0, "nothing pending");
};

/** The inline menu under a focused field. Helium: its frame, rows rendered. LibreWolf: the
 * background's menu record for the tab, then time to render (driven by keyboard). */
async function menuReady(page: Page, timeout = 10_000): Promise<Frame | null> {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (target === "firefox") {
      const tabId = await ext.evaluate(() => chrome.tabs.query({ active: true }).then((t) => t.find((x) => /^https?:/.test(x.url ?? ""))?.id));
      if (tabId != null && Object.keys(await ext.evaluate((id) => chrome.storage.session.get(`menu:${id}`), tabId)).length) {
        await new Promise((r) => setTimeout(r, 1200));
        return null;
      }
    } else {
      const f = page.frames().find((x) => x.url().includes("/menu.html"));
      if (f) {
        await f.waitForSelector(".kwm-row", { timeout: Math.max(8000, end - Date.now()) });
        await new Promise((r) => setTimeout(r, 350)); // clicks in the first 300 ms are ignored
        return f;
      }
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("inline menu did not open");
}

/** Presses the dialog's default button (Save / OK / the first passkey). By keyboard, again if
 * the dialog still has the keyboard and nothing happened (it may not have rendered yet). */
async function confirmDefault(page: Page, f: Frame | null, selector: string) {
  if (f) return void (await f.click(selector));
  const before = await page.$eval("#result", (e) => e.textContent ?? "");
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press("Enter");
    const changed = await page
      .waitForFunction((b) => document.getElementById("result")!.textContent !== b, { timeout: 2500, polling: 100 }, before)
      .then(() => true, () => false);
    if (changed || !(await overlayFocused(page))) return;
  }
}

/** Logins holding a passkey for the login.localhost fixture site (the shop item is set up apart). */
async function vaultPasskeys(): Promise<CipherView[]> {
  const data = await sync(api);
  const views = await Promise.all(data.ciphers.map((c: any) => decryptCipher(c, api.ring)));
  return (views as CipherView[]).filter((v) => v.login?.fido2Credentials.some((f) => f.rpId === HOSTS.login));
}

async function virtualAuthenticator(page: Page): Promise<CDPSession> {
  const cdp = await page.createCDPSession();
  await cdp.send("WebAuthn.enable", { enableUI: false });
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "usb", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  return cdp;
}

const native = (p: Page) => p.evaluate(() => Function.prototype.toString.call(CredentialsContainer.prototype.create).includes("[native code]"));

describe(`passkeys (${target})`, () => {
  before(async () => {
    fixtures = await startFixtures();
    await register(email, password);
    api = await apiLogin(email, password);
    // A protected item (master-password re-prompt) with a passkey the shop site already knows.
    const handle = crypto.getRandomValues(new Uint8Array(16));
    const k = await createPasskey({ rpId: HOSTS.shop, rpName: "Shop", userHandle: handle, userName: "rita", userDisplayName: "Rita", discoverable: true });
    rpAddUser(HOSTS.shop, "rita", Buffer.from(handle).toString("base64url"), { id: Buffer.from(k.rawId).toString("base64url"), publicKey: new Uint8Array(k.pub.cose), counter: 0, transports: ["internal"] });
    const loginOf = (name: string, uri: string, fido2Credentials: typeof k.fido2[]) => ({ username: name, password: "p", passwordRevisionDate: null, totp: null, uris: [{ uri, match: null }], autofillOnPageLoad: null, fido2Credentials });
    await importItems(api, [
      emptyView(CipherType.Login, { name: "Unrelated", login: loginOf("u", "https://example.com", []) }),
      emptyView(CipherType.Login, { name: "Shop", reprompt: 1, login: loginOf("rita", FX.url("shop", "/"), [k.fido2]) }),
    ]);
    kw = await launch(target);
    ext = await kw.openPopup();
    await login(kw, ext, process.env.KW_SERVER ?? env.KW_SERVER, email, password);
    await waitForItems(ext, 2, 30_000);
  });
  after(async () => {
    await kw?.close();
    fixtures?.close();
  });

  test("create(): the dialog saves a passkey to a new login, and the site verifies it", async () => {
    const page = await open(FX.url("login", "/passkey.html"));
    assert.equal(await native(page), false, "the shim is in the page while unlocked");
    await page.click("#reg");
    const d = await dialog(page);
    await confirmDefault(page, d, ".kws-actions .btn:not(.text)");
    const r = await result(page, /^(registered|error)/);
    assert.match(r, /^registered \S+ keyward backedUp=true$/);
    const [v] = await vaultPasskeys();
    assert.ok(v, "a login with a passkey is in the vault");
    assert.equal(v.name, "Keyward fixtures");
    assert.equal(v.login!.username, "kay");
    assert.deepEqual(v.login!.uris.map((u) => u.uri), [`http://login.localhost:${FX.port}`]);
    const f = v.login!.fido2Credentials[0];
    assert.equal(f.rpId, "login.localhost");
    assert.equal(f.userName, "kay");
    assert.equal(f.discoverable, true);
    assert.match(f.credentialId, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    assert.equal(r.split(" ")[1], Buffer.from(f.credentialId.replace(/-/g, ""), "hex").toString("base64url"), "the site got the GUID's 16 bytes as the id");
  });

  test("get(): a discoverable sign-in picks the passkey in the dialog", async () => {
    const page = await open(FX.url("login", "/passkey.html"));
    await page.click("#login");
    await confirmDefault(page, await dialog(page), ".kwp-row");
    assert.equal(await result(page, /^(signed|sign-in|error)/), "signed in as kay");
  });

  test("get() with allowCredentials", async () => {
    const page = await open(FX.url("login", "/passkey.html"));
    await page.click("#login-user");
    await confirmDefault(page, await dialog(page), ".kwp-row");
    assert.equal(await result(page, /^(signed|sign-in|error)/), "signed in as kay");
  });

  test("conditional get(): the field's inline menu offers the passkey and signs in", async () => {
    const page = await open(FX.url("login", "/passkey.html?conditional=1"));
    await result(page, /^waiting/);
    await page.focus("#user");
    const f = await menuReady(page);
    if (f) {
      assert.match(await f.$eval(".kwm-row .sub", (e) => e.textContent ?? ""), /^Passkey · /);
      await f.click(".kwm-row");
    } else {
      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("Enter");
    }
    assert.equal(await result(page, /^(signed|sign-in|error)/), "signed in as kay (autofill)");
    assert.equal(await pendingCount(true), 0, "nothing left waiting");
  });

  test("conditional get(): a menu the page has restyled signs nothing", async () => {
    const page = await open(FX.url("login", "/passkey.html?conditional=1"));
    await result(page, /^waiting/);
    await page.focus("#user");
    const m = await menuReady(page);
    // The page can't reach into the menu, but it can style its host (here: make it invisible).
    await page.evaluate(() => [...document.documentElement.children].find((e) => e.localName.startsWith("kw-"))!.setAttribute("style", "opacity:0"));
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    if (m) await m.waitForSelector(".kwm-error", { timeout: 5000 });
    else await new Promise((r) => setTimeout(r, 2000));
    if (m) assert.match(await m.$eval(".kwm-error", (e) => e.textContent ?? ""), /hidden or covered/);
    assert.equal(await page.$eval("#result", (e) => e.textContent), "waiting", "not signed in");
    assert.equal(await pendingCount(true), 1, "the page's request still waits");
    await page.evaluate(() => (globalThis as any).eval("conditional.abort()"));
    for (let i = 0; i < 40 && (await pendingCount(true)); i++) await new Promise((r) => setTimeout(r, 50));
    assert.equal(await pendingCount(true), 0, "the abort withdrew it");
  });

  test("conditional get() of a protected item: the master password first, then signed in", async () => {
    const page = await open(FX.url("shop", "/passkey.html?conditional=1"));
    await result(page, /^waiting/);
    await page.focus("#user");
    const m = await menuReady(page);
    if (m) {
      assert.equal(await m.$eval(".kwm-row .title", (e) => e.textContent), "rita");
      await m.click(".kwm-row");
    } else {
      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("Enter");
    }
    const d = await dialog(page);
    if (d) await d.waitForSelector("input[type=password]");
    await new Promise((r) => setTimeout(r, 500));
    assert.equal(await page.$eval("#result", (e) => e.textContent), "waiting", "nothing signed before the master password");
    if (d) {
      await d.type("input[type=password]", password);
      await d.click("button[type=submit]");
    } else {
      await page.keyboard.type(password);
      await page.keyboard.press("Enter");
    }
    assert.equal(await result(page, /^(signed|sign-in|error)/), "signed in as rita (autofill)");
    assert.equal(await pendingCount(true), 0);
  });

  test("conditional get(), then a sign-in button: the page's abort leaves the dialog alone", async () => {
    const page = await open(FX.url("login", "/passkey.html?conditional=1"));
    await result(page, /^waiting/);
    await page.click("#login");
    await confirmDefault(page, await dialog(page), ".kwp-row");
    assert.equal(await result(page, /^(signed|sign-in|error)/), "signed in as kay");
    assert.equal(await pendingCount(true), 0, "the aborted autofill request is gone too");
  });

  test("create() for an account that already has the passkey: InvalidStateError", async () => {
    const page = await open(FX.url("login", "/passkey.html"));
    await page.click("#reg");
    await confirmDefault(page, await dialog(page), ".kws-actions .btn");
    assert.match(await result(page, /^(registered|error)/), /^error InvalidStateError/);
    assert.equal((await vaultPasskeys()).length, 1, "nothing new saved");
  });

  test("Escape cancels: NotAllowedError, nothing saved", async () => {
    const page = await open(FX.url("login", "/passkey.html"));
    await page.$eval("#user", (e) => ((e as HTMLInputElement).value = "zed"));
    await page.click("#reg");
    const f = await dialog(page);
    if (f) await f.focus(".kws-actions .btn:not(.text)");
    await page.keyboard.press("Escape");
    assert.match(await result(page, /^(registered|error)/), /^error NotAllowedError/);
    assert.equal(await pendingCount(), 0);
    assert.equal((await vaultPasskeys()).length, 1);
  });

  test("\"Use browser or security key\" hands the request to the browser", async () => {
    const page = await open(FX.url("login", "/passkey.html"));
    await virtualAuthenticator(page);
    await page.$eval("#user", (e) => ((e as HTMLInputElement).value = "bob"));
    await page.click("#reg");
    const f = (await dialog(page))!;
    await f.click(".kws-actions .btn.text");
    assert.match(await result(page, /^(registered|error)/), /^registered \S+ browser/);
    assert.equal((await vaultPasskeys()).length, 1, "the browser's passkey is not in the vault");
  }, { skip: target !== "chromium" && "virtual authenticator is CDP-only" });

  test("a site Keyward has no passkey for goes straight to the browser", async () => {
    const page = await open(FX.url("other", "/passkey.html?timeout=3000"));
    if (target === "chromium") await virtualAuthenticator(page);
    await page.click("#login");
    await noDialog(page);
    if (target === "chromium") assert.match(await result(page, /^(signed|sign-in|error)/), /^error NotAllowedError/);
  });

  test("passkeys off for a site: no dialog", async () => {
    await ext.evaluate(async () => {
      const s: any = (await chrome.storage.local.get("settings")).settings ?? {};
      await chrome.storage.local.set({ settings: { ...s, passkeys: { enabled: true, excluded: ["login.localhost"] } } });
    });
    try {
      const page = await open(FX.url("login", "/passkey.html?timeout=3000"));
      if (target === "chromium") await virtualAuthenticator(page);
      await page.click("#login");
      await noDialog(page);
    } finally {
      await ext.evaluate(async () => {
        const s: any = (await chrome.storage.local.get("settings")).settings ?? {};
        await chrome.storage.local.set({ settings: { ...s, passkeys: { enabled: true, excluded: [] } } });
      });
    }
  });

  test("locked: pages get the browser's own WebAuthn; unlocked: Keyward's again", async () => {
    await ext.evaluate(() => chrome.runtime.sendMessage({ kw: "rpc", name: "session.lock", arg: { all: true } }));
    await new Promise((r) => setTimeout(r, 500));
    assert.equal(await native(await open(FX.url("login", "/passkey.html"))), true, "no shim while locked");
    // The popup switches to its unlock screen by itself (clicks need its tab in front; the
    // extension's own tabs API does that in both browsers).
    await ext.evaluate(async () => {
      const t = await chrome.tabs.getCurrent();
      if (t?.id != null) await chrome.tabs.update(t.id, { active: true });
    });
    if (target === "chromium") await ext.bringToFront();
    await fill(kw, ext, sel.field("Master password"), password);
    await clickText(kw, ext, "Unlock");
    await waitForItems(ext, 1, 20_000).catch(async (e) => {
      const screen = await ext.evaluate(() => document.body.innerText.replace(/\s+/g, " ").slice(0, 300)).catch((x) => String(x));
      throw new Error(`${e.message}; the popup shows: ${screen}`);
    });
    await new Promise((r) => setTimeout(r, 500));
    assert.equal(await native(await open(FX.url("login", "/passkey.html"))), false, "shim back after unlock");
  });
});
