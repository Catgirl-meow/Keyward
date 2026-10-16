// P4: autofill against the fixture corpus (tests/fixtures/forms). Fills are started the way the
// popup starts them (RPC with the page's tab id), from the popup's own UI (popup.html?tab=<id>),
// or from the page itself (focus → inline menu → keys), and checked by reading the page's fields.
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { after, before, describe, test as nodeTest } from "node:test";
import type { Frame, Page } from "puppeteer-core";
import { click, clickText, fill as setField, login, waitForItems } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { FX, startFixtures } from "../fixtures/server.ts";
import { importItems, login as apiLogin, randomPassword, register, sync, totpNow, uniqueEmail, type Session } from "../lib/vw.ts";
import { decryptCipher, emptyView } from "../../src/core/vault/cipher.ts";
import { CipherType } from "../../src/core/vault/types.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
const email = uniqueEmail("autofill");
const password = randomPassword();
let kw: Keyward;
let ext: Page;
let api: Session;
let fixtures: Server;
const ids: Record<string, string> = {};
const pages: Page[] = [];
// An https login for a site the fixtures serve over http (the popup asks before filling it).
const SECURE = { user: "secure", pass: "Secure-Pass-6" };
// A login with master-password re-prompt on the login site (sorts after "Login site").
const PROTECTED = { user: "guarded@example.test", pass: "Protected-Pass-7" };

function test(name: string, fn: () => Promise<void>, opts: { skip?: string | false } = {}) {
  nodeTest(name, { skip: opts.skip }, async () => {
    try {
      await fn();
    } catch (e) {
      const p = pages[pages.length - 1];
      if (p) await kw.screenshot(p, `tests/.artifacts/autofill-${target}-FAIL-${name.replace(/\W+/g, "-").slice(0, 40)}.png`).catch(() => {});
      throw e;
    }
  });
}

const login1 = (name: string, uri: string, user: string, pass: string, totp: string | null = null) =>
  emptyView(CipherType.Login, {
    name,
    login: { username: user, password: pass, passwordRevisionDate: null, totp, uris: [{ uri, match: null }], autofillOnPageLoad: null, fido2Credentials: [] },
  });

async function call<T = any>(name: string, arg?: unknown): Promise<T> {
  const r: any = await ext.evaluate((n, a) => chrome.runtime.sendMessage({ kw: "rpc", name: n, arg: a }), name, arg as any);
  if (!r?.ok) throw new Error(`${name}: ${r?.error}`);
  return r.value as T;
}

/** Opens a tab the way a user does (tabs.create), not puppeteer's newPage()+goto: with an
 * extension that injects into about:blank, the new tab's initial blank document can commit
 * after the navigation and replace it.
 * Late in a long LibreWolf run, the first cross-site iframe of a new tab can stay at about:blank
 * (its request never leaves the browser; it happens with Keyward uninstalled too). A second tab
 * loads it, so a page that doesn't finish loading gets one more try. */
async function open(url: string, retry = true): Promise<{ page: Page; tabId: number }> {
  const want = new URL(url).href;
  const existing = new Set(kw.browser.targets());
  const created = kw.browser.waitForTarget((t) => !existing.has(t) && t.type() === "page" && t.url() === want, { timeout: 15_000 });
  const tabId: number = await ext.evaluate((u) => chrome.tabs.create({ url: u, active: true }).then((t) => t.id!), want);
  const page = (await (await created).asPage()) as Page;
  pages.push(page);
  if (process.env.KW_DEBUG) page.on("console", (m) => m.text().startsWith("[kw]") && console.log(m.text()));
  try {
    await page.waitForFunction((u) => location.href === u && document.readyState === "complete", { timeout: retry ? 10_000 : 15_000, polling: 50 }, want);
  } catch (e) {
    if (retry) return open(url, false);
    const state = await page.evaluate(() => `${location.href} (${document.readyState})`).catch(() => "?");
    throw new Error(`${(e as Error).message}: tab ${tabId} is at ${state}`);
  }
  return { page, tabId };
}
const newTab = async (url: string) => (await open(url)).page;

const fillItem = (tabId: number, name: string, force?: boolean, verified?: boolean) =>
  call<{ filled: boolean; error?: string; confirm?: string; totpCopied?: boolean; reprompt?: boolean }>("autofill.fill", { tabId, itemId: ids[name], force, verified });
const val = (p: Page | Frame, sel: string) => p.$eval(sel, (e) => (e as HTMLInputElement).value);
const waitVal = (p: Page | Frame, sel: string, want: string, timeout = 10_000) =>
  p.waitForFunction((s, w) => (document.querySelector(s) as HTMLInputElement | null)?.value === w, { timeout, polling: 50 }, sel, want);

/** Waits for the inline menu. Helium: its frame (the page can't see it; the browser's frame tree
 * can). LibreWolf's WebDriver BiDi doesn't expose extension frames: there the background's record
 * of the open menu is checked, then the menu gets time to render. */
async function menuReady(page: Page, tabId: number, timeout = 8000): Promise<Frame | null> {
  const end = Date.now() + timeout;
  if (target === "firefox") {
    while (Date.now() < end) {
      const s = await ext.evaluate((id) => chrome.storage.session.get(`menu:${id}`), tabId);
      if (Object.keys(s).length) {
        await new Promise((r) => setTimeout(r, 900));
        return null;
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error("inline menu did not open");
  }
  while (Date.now() < end) {
    const f = page.frames().find((x) => x.url().includes("/menu.html"));
    if (f) {
      await f.waitForSelector(".kwm-row", { timeout: Math.max(500, end - Date.now()) });
      return f;
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  const diag = await page.evaluate(() => ({ host: [...document.documentElement.children].map((e) => e.localName), active: document.activeElement?.id, focus: document.hasFocus() }));
  throw new Error(`inline menu did not appear: frames=${page.frames().map((f) => f.url()).join(",")} ${JSON.stringify(diag)}`);
}
const overlayShown = (page: Page) => page.evaluate(() => [...document.documentElement.children].some((e) => e.localName.startsWith("kw-")));

/** The popup in its own tab, filling `tabId` (popup.html?tab=…), once it has the page's matches. */
async function popupFor(tabId: number, host: string): Promise<Page> {
  const p = await kw.browser.newPage();
  await p.setViewport({ width: 400, height: 600 });
  await kw.goto(p, `${kw.base}popup.html?tab=${tabId}`);
  pages.push(p);
  await p.waitForFunction((h) => [...document.querySelectorAll(".section-label")].some((e) => e.textContent === `On ${h}`), { timeout: 15_000, polling: 50 }, host);
  return p;
}
/** A button in the popup's "This site" row for `name`. */
async function siteRowButton(popup: Page, name: string, button: string) {
  const h = await popup.waitForFunction(
    (n, b) => [...document.querySelectorAll(".site-row")].find((r) => r.querySelector(".title")?.textContent === n)?.querySelector(b) ?? null,
    { timeout: 10_000 }, name, button,
  );
  return h.asElement() as unknown as import("puppeteer-core").ElementHandle<HTMLElement>;
}
/** A real press: pointerdown, then click (LibreWolf's BiDi can't send input to our pages). */
const press = async (b: import("puppeteer-core").ElementHandle<HTMLElement>) =>
  target === "chromium" ? b.click() : b.evaluate((e) => (e.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true })), e.click()));
/** Fills from a row of the popup's "This site" list (its Fill button). */
const clickSiteRow = async (popup: Page, name: string) => press(await siteRowButton(popup, name, ".fill-btn"));
const menuLabels = (popup: Page) => popup.$$eval('.menu [role="menuitem"]', (els) => els.map((e) => e.textContent?.trim()));
/** Text of the open confirm dialog. */
const dialogText = async (popup: Page) => (await popup.waitForSelector(".dialog p", { visible: true, timeout: 10_000 }))!.evaluate((e) => e.textContent ?? "");
const settingsNow = async () => (await ext.evaluate(() => chrome.storage.local.get("settings"))).settings as any;

describe(`autofill (${target})`, () => {
  before(async () => {
    fixtures = await startFixtures();
    await register(email, password);
    api = await apiLogin(email, password);
    const ident = emptyView(CipherType.Identity, { name: "Kay at home" });
    Object.assign(ident.identity!, { firstName: "Kay", lastName: "Ward", address1: "1 Main St", address2: "Apt 4", city: "Springfield", state: "WA", postalCode: "98101", country: "US", phone: "+1 555 0100", email: "kay@example.test" });
    await importItems(api, [
      login1("Login site", FX.url("login"), FX.login.user, FX.login.pass, FX.login.totp),
      login1("Mailfence", FX.url("mailfence"), FX.mailfence.user, FX.mailfence.pass, FX.mailfence.totp),
      login1("Framed site", FX.url("other"), FX.other.user, FX.other.pass),
      login1("Basic site", FX.url("shop", "/basic"), FX.basic.user, FX.basic.pass),
      login1("Secure other", "https://other.localhost", SECURE.user, SECURE.pass),
      { ...login1("Protected login", FX.url("login"), PROTECTED.user, PROTECTED.pass), reprompt: 1 },
      emptyView(CipherType.Card, { name: "Visa", card: { cardholderName: "Kay Ward", brand: "Visa", number: "4111111111111111", expMonth: "7", expYear: "2031", code: "123" } }),
      ident,
    ]);
    const data = await sync(api);
    for (const c of data.ciphers) ids[(await decryptCipher(c, api.ring)).name] = c.id;
    kw = await launch(target);
    ext = await kw.openPopup();
    await login(kw, ext, env.KW_SERVER, email, password);
    await waitForItems(ext, 8, 30_000);
  });
  after(async () => {
    await kw?.close();
    fixtures?.close();
  });

  test("popup fill: plain login form", async () => {
    const { page, tabId } = await open(FX.url("login", "/plain.html"));
    const r = await fillItem(tabId, "Login site");
    assert.equal(r.filled, true, r.error ?? r.confirm ?? "not filled");
    assert.equal(await val(page, "#u"), FX.login.user);
    assert.equal(await val(page, "#p"), FX.login.pass);
    assert.equal(await val(page, "#search"), "", "search box untouched");
  });

  test("React-style controlled inputs register the fill", async () => {
    const { page, tabId } = await open(FX.url("login", "/react.html"));
    const r = await fillItem(tabId, "Login site");
    assert.equal(r.filled, true, JSON.stringify(r));
    const state = JSON.parse(await page.$eval("#state", (e) => e.textContent ?? "{}"));
    assert.deepEqual(state, { username: FX.login.user, password: FX.login.pass });
    assert.equal(await page.$eval("#go", (b) => (b as HTMLButtonElement).disabled), false);
  });

  test("fields with no hints, no form, no autocomplete", async () => {
    const { page, tabId } = await open(FX.url("login", "/noattrs.html"));
    assert.equal((await fillItem(tabId, "Login site")).filled, true);
    assert.equal(await val(page, "input[name=j_username]"), FX.login.user);
    assert.equal(await val(page, "input[name=j_password]"), FX.login.pass);
  });

  for (const mode of ["open", "closed"]) {
    test(`${mode} shadow DOM`, async () => {
      const { page, tabId } = await open(FX.url("login", `/shadow.html?mode=${mode}`));
      assert.equal((await fillItem(tabId, "Login site")).filled, true);
      const v = await page.evaluate(() => [(window as any).__shadow.querySelector("#u").value, (window as any).__shadow.querySelector("#p").value]);
      assert.deepEqual(v, [FX.login.user, FX.login.pass]);
    });
  }

  test("same-site frame fills; a cross-site frame only with its own item", async () => {
    const same = await open(FX.url("login", "/iframe.html?src=/plain.html"));
    assert.equal((await fillItem(same.tabId, "Login site")).filled, true);
    const f1 = same.page.frames().find((f) => f !== same.page.mainFrame() && f.url().endsWith("/plain.html"))!;
    assert.equal(await val(f1, "#p"), FX.login.pass);

    const cross = await open(FX.url("login", "/iframe.html?src=" + encodeURIComponent(FX.url("other", "/plain.html"))));
    const denied = await fillItem(cross.tabId, "Login site");
    assert.equal(denied.filled, false);
    assert.match(denied.confirm ?? "", /other\.localhost/);
    const f2 = cross.page.frames().find((f) => f !== cross.page.mainFrame() && f.url().includes("other.localhost"))!;
    assert.equal(await val(f2, "#p"), "", "nothing leaked into the cross-site frame");
    assert.equal((await fillItem(cross.tabId, "Framed site")).filled, true);
    assert.equal(await val(f2, "#p"), FX.other.pass);
  });

  test("multi-step pages: username, then password and code fill themselves", async () => {
    const { page, tabId } = await open(FX.url("login", "/ms-user.html"));
    assert.equal((await fillItem(tabId, "Login site")).filled, true);
    assert.equal(await val(page, "#u"), FX.login.user);
    await Promise.all([page.waitForNavigation(), page.$eval("form", (f) => (f as HTMLFormElement).requestSubmit())]);
    await waitVal(page, "#p", FX.login.pass);
    await Promise.all([page.waitForNavigation(), page.$eval("form", (f) => (f as HTMLFormElement).requestSubmit())]);
    await page.waitForFunction(() => (document.querySelector("#c") as HTMLInputElement)?.value.length === 6, { timeout: 10_000 });
    await Promise.all([page.waitForNavigation(), page.$eval("form", (f) => (f as HTMLFormElement).requestSubmit())]);
    assert.match(await page.$eval("h1", (h) => h.textContent ?? ""), /Welcome/);
  });

  test("mailfence replica: login fill, then the 2FA code fills itself", async () => {
    const { page, tabId } = await open(FX.url("mailfence", "/mailfence/login.html"));
    const r = await fillItem(tabId, "Mailfence");
    assert.equal(r.filled, true, r.error ?? "not filled");
    assert.equal(await val(page, "#UserID"), FX.mailfence.user);
    assert.equal(await val(page, "#Password"), FX.mailfence.pass);
    // The 2FA step is the login POST's response, at the URL the form posted to.
    await Promise.all([page.waitForNavigation(), page.click("input[type=submit]")]);
    assert.match(page.url(), /\/mailfence\/usw\?type=L&state=1$/);
    await page.waitForFunction(() => /^\d{6}$/.test((document.querySelector("input[name=totp]") as HTMLInputElement).value), { timeout: 10_000 });
    const boxes = await page.$$eval("#totp-inputs .code-input", (els) => els.map((e) => (e as HTMLInputElement).value).join(""));
    // Compared with the filled code, not a fresh one: the 30 s window can roll over in between.
    assert.equal(boxes, await val(page, "input[name=totp]"), "one digit per box");
    assert.equal(await page.$eval("#submit-btn", (b) => (b as HTMLButtonElement).disabled), false, "the site's script saw the code");
    await Promise.all([page.waitForNavigation(), page.click("#submit-btn")]);
    assert.equal(await page.$eval("h1", (h) => h.textContent), "Inbox");
  });

  test("mailfence replica: logged in by hand, the code comes from the menu; recovery field left alone", async () => {
    const { page, tabId } = await open(FX.url("mailfence", "/mailfence/login.html"));
    await page.$eval("#UserID", (e, v) => ((e as HTMLInputElement).value = v), FX.mailfence.user);
    await page.$eval("#Password", (e, v) => ((e as HTMLInputElement).value = v), FX.mailfence.pass);
    await Promise.all([page.waitForNavigation(), page.$eval("#authForm", (f) => (f as HTMLFormElement).submit())]);
    await page.bringToFront();
    // The page focuses the first box itself; with no Keyward login nothing fills, but the menu
    // offers the code (the boxes are too narrow for the field icon).
    const f = await menuReady(page, tabId);
    assert.equal(await val(page, "input[name=totp]"), "");
    if (f) assert.match(await f.$eval(".kwm-row .title", (e) => e.textContent ?? ""), /Mailfence/);
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => /^\d{6}$/.test((document.querySelector("input[name=totp]") as HTMLInputElement).value), { timeout: 8000 });
    assert.equal(await val(page, "input[name=totp]"), await totpNow(FX.mailfence.totp));
    // The recovery-code alternative is not a TOTP field.
    await page.click("#toggle-mode-link");
    await new Promise((r) => setTimeout(r, 600));
    assert.equal(await val(page, "#backup-code"), "");
    assert.equal(await overlayShown(page), false, "no menu on the recovery-code field");
  });

  test("single-page multi-step (username → password → code in one document)", async () => {
    const { page, tabId } = await open(FX.url("login", "/spa.html"));
    assert.equal((await fillItem(tabId, "Login site")).filled, true);
    assert.equal(await val(page, "#identifierId"), FX.login.user);
    await page.click("#n1");
    await waitVal(page, "#pw", FX.login.pass);
    await page.click("#n2");
    await page.waitForFunction(() => (document.querySelector("#totpPin") as HTMLInputElement).value.length === 6, { timeout: 10_000 });
    await page.click("#n3");
    await page.waitForFunction(() => /Welcome/.test(document.querySelector("#done")?.textContent ?? ""), { timeout: 10_000 });
  });

  test("split code boxes", async () => {
    const { page, tabId } = await open(FX.url("login", "/split-otp.html"));
    assert.equal((await fillItem(tabId, "Login site")).filled, true);
    const code = await page.$$eval(".boxes input", (els) => els.map((e) => (e as HTMLInputElement).value).join(""));
    assert.equal(code, await totpNow(FX.login.totp));
  });

  test("inline menu: opens on focus, arrow + Enter fills", async () => {
    const { page, tabId } = await open(FX.url("login", "/plain.html"));
    await page.bringToFront();
    await page.click("#u");
    const f = await menuReady(page, tabId);
    if (f) assert.match(await f.$eval(".kwm-row .title", (e) => e.textContent ?? ""), /Login site/);
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    await waitVal(page, "#p", FX.login.pass);
    assert.equal(await val(page, "#u"), FX.login.user);
    await page.waitForFunction(() => ![...document.documentElement.children].some((e) => e.localName.startsWith("kw-") && (e as any).matches?.(":popover-open") && e.getBoundingClientRect), { timeout: 3000 }).catch(() => {});
  });

  test("inline menu: a click on an item fills", async () => {
    const { page, tabId } = await open(FX.url("login", "/noattrs.html"));
    await page.bringToFront();
    await page.click("input[name=j_username]");
    const f = await menuReady(page, tabId);
    await new Promise((r) => setTimeout(r, 350)); // clicks in the first 300 ms are ignored (clickjacking guard)
    if (f) await f.click(".kwm-row");
    else {
      // The first row sits ~65 px below the field (head 32 px + half a 48 px row + padding).
      const r = await page.$eval("input[name=j_username]", (e) => JSON.parse(JSON.stringify(e.getBoundingClientRect())));
      await page.mouse.click(r.left + 100, r.bottom + 66);
    }
    await waitVal(page, "input[name=j_password]", FX.login.pass);
  });

  test("inline menu: verification-code field offers the code", async () => {
    const { page, tabId } = await open(FX.url("login", "/otp-only.html"));
    await page.bringToFront();
    await page.click("#c");
    // A code field on a site with a TOTP login opens the menu by itself.
    await menuReady(page, tabId);
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => /^\d{6}$/.test((document.querySelector("#c") as HTMLInputElement).value), { timeout: 8000 });
    assert.equal(await val(page, "#c"), await totpNow(FX.login.totp));
  });

  test("card: one form, and a card split over cross-site frames", async () => {
    const one = await open(FX.url("shop", "/card.html"));
    assert.equal((await fillItem(one.tabId, "Visa")).filled, true);
    assert.deepEqual(
      await one.page.evaluate(() => ["#cn", "#nm", "#em", "#ey", "#cv"].map((s) => (document.querySelector(s) as HTMLInputElement).value)),
      ["4111111111111111", "Kay Ward", "07", "2031", "123"],
    );
    const split = await open(FX.url("shop", "/card-frames.html"));
    assert.equal((await fillItem(split.tabId, "Visa")).filled, true);
    const fr = (q: string) => split.page.frames().find((f) => f.url().includes(q))!;
    await waitVal(fr("f=number"), "#x", "4111111111111111");
    assert.equal(await val(fr("f=exp"), "#x"), "07/31");
    assert.equal(await val(fr("f=cvc"), "#x"), "123");
    assert.equal(await val(split.page, "#nm"), "Kay Ward");
  });

  test("identity: address form with selects", async () => {
    const { page, tabId } = await open(FX.url("shop", "/identity.html"));
    assert.equal((await fillItem(tabId, "Kay at home")).filled, true);
    assert.deepEqual(
      await page.evaluate(() => ["#fn", "#ln", "#a1", "#a2", "#ci", "#st", "#zp", "#co", "#ph", "#em"].map((s) => (document.querySelector(s) as HTMLInputElement).value)),
      ["Kay", "Ward", "1 Main St", "Apt 4", "Springfield", "WA", "98101", "US", "+1 555 0100", "kay@example.test"],
    );
  });

  test("popup UI: a cross-site frame asks first; Cancel leaves it empty, Fill fills it", async () => {
    const { page, tabId } = await open(FX.url("login", "/iframe.html?src=" + encodeURIComponent(FX.url("other", "/plain.html"))));
    const frame = page.frames().find((f) => f !== page.mainFrame() && f.url().includes("other.localhost"))!;
    const popup = await popupFor(tabId, "login.localhost");
    await clickSiteRow(popup, "Login site");
    assert.match(await dialogText(popup), /saved for login\.localhost, but this form is on other\.localhost/);
    await clickText(kw, popup, "Cancel", ".dialog button");
    await popup.waitForSelector(".dialog", { hidden: true, timeout: 5000 });
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(await val(frame, "#p"), "", "Cancel filled nothing");
    await clickSiteRow(popup, "Login site");
    await dialogText(popup);
    await clickText(kw, popup, "Fill", ".dialog button");
    await waitVal(frame, "#p", FX.login.pass);
    assert.equal(await val(frame, "#u"), FX.login.user);
    await popup.close().catch(() => {});
  });

  test("popup UI: an https login on an http page asks first", async () => {
    const { page, tabId } = await open(FX.url("other", "/plain.html"));
    const popup = await popupFor(tabId, "other.localhost");
    await clickSiteRow(popup, "Secure other");
    assert.match(await dialogText(popup), /other\.localhost isn't using a secure connection \(http\)/);
    await clickText(kw, popup, "Fill", ".dialog button");
    await waitVal(page, "#p", SECURE.pass);
    assert.equal(await val(page, "#u"), SECURE.user);
    await popup.close().catch(() => {});
  });

  test("popup UI: a suggested login opens on click; its menu fills, edits and copies", async () => {
    const { tabId } = await open(FX.url("login", "/plain.html"));
    const popup = await popupFor(tabId, "login.localhost");
    await clickText(kw, popup, "Login site", ".site-row .title");
    await popup.waitForSelector(".item-view", { timeout: 8000 });
    await popup.waitForFunction((u) => document.body.innerText.includes(u), { timeout: 8000 }, FX.login.user);
    await click(kw, popup, '.topbar button[aria-label="Back"]');
    await press(await siteRowButton(popup, "Login site", 'button[aria-label="More"]'));
    await popup.waitForSelector(".menu", { timeout: 5000 });
    assert.deepEqual(await menuLabels(popup), ["Fill", "View", "Edit", "Copy username", "Copy password", "Copy verification code"]);
    // The button closes its own menu.
    await press(await siteRowButton(popup, "Login site", 'button[aria-label="More"]'));
    await popup.waitForSelector(".menu", { hidden: true, timeout: 5000 });
    // A protected item copies its secrets from the item view, after the master password.
    await press(await siteRowButton(popup, "Protected login", 'button[aria-label="More"]'));
    await popup.waitForSelector(".menu", { timeout: 5000 });
    assert.deepEqual(await menuLabels(popup), ["Fill", "View", "Edit", "Copy username"]);
    await clickText(kw, popup, "Edit", '[role="menuitem"]');
    await popup.waitForSelector(".item-edit", { timeout: 8000 });
    assert.equal(await popup.$eval('input[aria-label="Name"]', (e) => (e as HTMLInputElement).value), "Protected login");
    await popup.close().catch(() => {});
  });

  test("re-prompt: the background fills a protected item only when the caller verified", async () => {
    const { page, tabId } = await open(FX.url("login", "/plain.html"));
    const r = await fillItem(tabId, "Protected login");
    assert.deepEqual([r.filled, r.reprompt], [false, true], JSON.stringify(r));
    await new Promise((r) => setTimeout(r, 300));
    assert.deepEqual([await val(page, "#u"), await val(page, "#p")], ["", ""], "nothing filled without the master password");
    assert.equal((await fillItem(tabId, "Protected login", false, true)).filled, true);
    assert.equal(await val(page, "#p"), PROTECTED.pass);
  });

  test("popup UI: a protected item in the site list asks for the master password", async () => {
    const { page, tabId } = await open(FX.url("login", "/plain.html"));
    const popup = await popupFor(tabId, "login.localhost");
    const sheet = async () => (await popup.waitForSelector(".dialog h2", { visible: true, timeout: 10_000 }))!.evaluate((e) => e.textContent ?? "");
    const pw = 'input[aria-label="Master password"]';
    await clickSiteRow(popup, "Protected login");
    assert.equal(await sheet(), "Confirm it's you");
    await clickText(kw, popup, "Cancel", ".dialog button");
    await popup.waitForSelector(".dialog", { hidden: true, timeout: 5000 });
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(await val(page, "#p"), "", "Cancel filled nothing");

    await clickSiteRow(popup, "Protected login");
    await sheet();
    await setField(kw, popup, pw, "not-the-password");
    await clickText(kw, popup, "Confirm", ".dialog button");
    await popup.waitForFunction(() => /Invalid master password/.test(document.querySelector(".dialog")?.textContent ?? ""), { timeout: 30_000, polling: 100 });
    assert.equal(await val(page, "#p"), "", "a wrong password filled nothing");
    await setField(kw, popup, pw, password);
    await clickText(kw, popup, "Confirm", ".dialog button");
    await waitVal(page, "#p", PROTECTED.pass, 30_000);
    assert.equal(await val(page, "#u"), PROTECTED.user);
    await popup.close().catch(() => {});
  });

  test("popup UI: Fill on a protected item after unlocking it in its view", async () => {
    const { page, tabId } = await open(FX.url("login", "/plain.html"));
    const popup = await popupFor(tabId, "login.localhost");
    await setField(kw, popup, 'input[aria-label="Search vault"]', "Protected login");
    await clickText(kw, popup, "Protected login", ".vault-list .list-section .item");
    await clickText(kw, popup, "Show item", ".item-view button");
    assert.equal(await popup.$(".item-view .fab"), null, "no Fill before the master password");
    await setField(kw, popup, 'input[aria-label="Master password"]', password);
    await clickText(kw, popup, "Confirm", ".dialog button");
    await clickText(kw, popup, "Fill", ".item-view .fab");
    await waitVal(page, "#p", PROTECTED.pass, 30_000);
    await popup.close().catch(() => {});
  });

  test("inline menu: an https login on an http page asks in the menu; Cancel goes back, Fill anyway fills", async () => {
    const { page, tabId } = await open(FX.url("other", "/plain.html"));
    await page.bringToFront();
    await page.click("#u");
    const f = await menuReady(page, tabId);
    const titles = () => f!.$$eval(".kwm-row .title", (els) => els.map((e) => e.textContent ?? ""));
    // LibreWolf can't see the menu frame: there the rows are known from the sort (favorites, then name).
    if (f) assert.deepEqual((await titles()).slice(0, 2), ["Framed site", "Secure other"]);
    const keys = async (...k: string[]) => {
      for (const x of k) await page.keyboard.press(x as any);
    };
    /** Picks "Secure other" and waits until the menu shows the warning. */
    const pickSecure = async () => {
      await keys("ArrowDown", "ArrowDown", "Enter");
      if (f) {
        await f.waitForSelector(".kwm-ask", { timeout: 5000 });
        assert.match(await f.$eval(".kwm-ask", (e) => e.textContent ?? ""), /other\.localhost isn't using a secure connection \(http\)/);
        assert.deepEqual(await titles(), ["Fill anyway", "Cancel"]);
      } else await new Promise((r) => setTimeout(r, 1000));
      assert.equal(await val(page, "#p"), "", "nothing filled before the yes");
    };
    await pickSecure();
    // The warning starts with no row selected, so a second Enter can't accept it by accident.
    if (f) assert.equal(await f.$(".kwm-row.sel"), null);
    await keys("ArrowDown", "ArrowDown", "Enter"); // Cancel
    if (f) await f.waitForFunction(() => !document.querySelector(".kwm-ask") && [...document.querySelectorAll(".kwm-row .title")].some((e) => e.textContent === "Framed site"), { timeout: 5000 });
    else await new Promise((r) => setTimeout(r, 600));
    assert.equal(await val(page, "#p"), "");
    await pickSecure();
    await keys("ArrowDown", "Enter"); // Fill anyway
    await waitVal(page, "#p", SECURE.pass);
    assert.equal(await val(page, "#u"), SECURE.user);
  });

  /** Opens `name` from the popup's list and presses its Fill button. */
  async function fillFromItemView(popup: Page, name: string) {
    await setField(kw, popup, 'input[aria-label="Search vault"]', name);
    await clickText(kw, popup, name, ".vault-list .list-section .item");
    await clickText(kw, popup, "Fill", ".item-view .fab");
  }

  test("popup UI: Fill on a card item", async () => {
    const { page, tabId } = await open(FX.url("shop", "/card.html"));
    const popup = await popupFor(tabId, "shop.localhost");
    await fillFromItemView(popup, "Visa");
    await waitVal(page, "#cv", "123");
    assert.deepEqual(
      await page.evaluate(() => ["#cn", "#nm", "#em", "#ey", "#cv"].map((s) => (document.querySelector(s) as HTMLInputElement).value)),
      ["4111111111111111", "Kay Ward", "07", "2031", "123"],
    );
    await popup.close().catch(() => {});
  });

  test("popup UI: Fill on an identity item", async () => {
    const { page, tabId } = await open(FX.url("shop", "/identity.html"));
    const popup = await popupFor(tabId, "shop.localhost");
    await fillFromItemView(popup, "Kay at home");
    await waitVal(page, "#em", "kay@example.test");
    assert.deepEqual(
      await page.evaluate(() => ["#fn", "#ln", "#a1", "#ci", "#zp", "#ph"].map((s) => (document.querySelector(s) as HTMLInputElement).value)),
      ["Kay", "Ward", "1 Main St", "Springfield", "98101", "+1 555 0100"],
    );
    await popup.close().catch(() => {});
  });

  test("search, newsletter and coupon fields are left alone", async () => {
    const { page, tabId } = await open(FX.url("login", "/negatives.html"));
    await page.bringToFront();
    await page.click("#search");
    await new Promise((r) => setTimeout(r, 600));
    assert.equal(await overlayShown(page), false, "no inline-menu icon on a search box");
    assert.equal((await fillItem(tabId, "Login site")).filled, true);
    assert.deepEqual(await page.evaluate(() => ["#search", "#nl", "#cp", "#u", "#p"].map((s) => (document.querySelector(s) as HTMLInputElement).value)), [
      "",
      "",
      "",
      FX.login.user,
      FX.login.pass,
    ]);
  });

  test("save prompt after sign-up saves the login", async () => {
    const { page, tabId } = await open(FX.url("shop", "/signup.html"));
    await page.bringToFront();
    await page.type("#u", "new-user");
    await page.type("#p", "Signup-Pass-5!");
    await page.type("#r", "Signup-Pass-5!");
    await Promise.all([page.waitForNavigation(), page.click("button")]);
    const end = Date.now() + 10_000;
    if (target === "firefox") {
      // The bar's frame isn't visible to BiDi: check the shown prompt, then answer it as its Save button does.
      let p: any;
      while (!p?.shown && Date.now() < end) {
        p = (await ext.evaluate((id) => chrome.storage.session.get(`save:${id}`), tabId))[`save:${tabId}`];
        if (!p?.shown) await new Promise((r) => setTimeout(r, 100));
      }
      assert.equal(p?.kind, "save", "save prompt not shown");
      await kw.screenshot(page, `tests/.artifacts/autofill-${target}-savebar.png`).catch(() => {});
      await call("save.decide", { token: p.token, action: "save" });
    } else {
      let bar: Frame | undefined;
      while (!bar && Date.now() < end) {
        bar = page.frames().find((f) => f.url().includes("/savebar.html"));
        if (!bar) await new Promise((r) => setTimeout(r, 100));
      }
      assert.ok(bar, "save bar did not appear");
      await bar.waitForFunction(() => /Save login/.test(document.body.textContent ?? ""), { timeout: 5000 });
      await bar.evaluate(() => [...document.querySelectorAll("button")].find((b) => b.textContent?.trim() === "Save")!.click());
    }
    const saved = await (async () => {
      for (let i = 0; i < 50; i++) {
        const data = await sync(api);
        for (const c of data.ciphers) {
          const v = await decryptCipher(c, api.ring);
          if (v.login?.username === "new-user") return v;
        }
        await new Promise((r) => setTimeout(r, 200));
      }
    })();
    assert.ok(saved, "item not on the server");
    assert.equal(saved.login?.password, "Signup-Pass-5!");
    assert.equal(saved.login?.uris[0]?.uri, FX.url("shop", ""));
  });

  test("no save prompt when the login form comes back (wrong password)", async () => {
    const { page, tabId } = await open(FX.url("login", "/plain.html"));
    await page.$eval("form", (f) => ((f as HTMLFormElement).action = "/check"));
    await page.bringToFront();
    await page.type("#u", FX.login.user);
    await page.type("#p", "wrong-password");
    await Promise.all([page.waitForNavigation(), page.click("button")]);
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal(page.frames().some((f) => f.url().includes("/savebar.html")), false);
    assert.equal(Object.keys(await ext.evaluate((id) => chrome.storage.session.get(`save:${id}`), tabId)).length, 0, "a save prompt is pending");
  });

  test("basic auth answers with the only matching login", async () => {
    const page = await newTab(FX.url("login", "/welcome.html"));
    const res = await page.goto(FX.url("shop", "/basic"));
    assert.equal(res?.status(), 200);
    assert.equal(await page.$eval("h1", (h) => h.textContent), "Authorized");
  });

  /** Runs an extension command (a headless browser can't press its shortcut) for `tabId`. */
  const runCommand = (cmd: string, tabId: number) =>
    kw.bg(target === "chromium" ? `kwCommand(${JSON.stringify(cmd)}, ${tabId})` : `browser.runtime.getBackgroundPage().then((b) => b.kwCommand(${JSON.stringify(cmd)}, ${tabId}))`);
  const setAutofill = (patch: Record<string, unknown>) =>
    ext.evaluate(async (p) => {
      const { settings = {} } = (await chrome.storage.local.get("settings")) as any;
      await chrome.storage.local.set({ settings: { ...settings, autofill: { ...settings.autofill, ...p } } });
    }, patch);

  test("Ctrl+Shift+L (autofill_login) fills this site's login", async () => {
    const { page, tabId } = await open(FX.url("login", "/plain.html"));
    await runCommand("autofill_login", tabId);
    await waitVal(page, "#p", FX.login.pass);
    assert.equal(await val(page, "#u"), FX.login.user);
  });

  test("fill on page load: off by default; on, it fills forms drawn late and after in-page navigation", async () => {
    let { page } = await open(FX.url("login", "/plain.html"));
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal(await val(page, "#p"), "", "filled with the setting off");
    await setAutofill({ onPageLoad: true });
    try {
      ({ page } = await open(FX.url("login", "/plain.html")));
      await waitVal(page, "#p", FX.login.pass);
      assert.equal(await val(page, "#u"), FX.login.user);
      ({ page } = await open(FX.url("login", "/late.html")));
      await waitVal(page, "#p", FX.login.pass, 8000);
      ({ page } = await open(FX.url("login", "/route.html")));
      await page.click("#go");
      await waitVal(page, "#p", FX.login.pass, 8000);
      // Two logins for the site ("Framed site", "Secure other"): nothing without asking which.
      ({ page } = await open(FX.url("other", "/plain.html")));
      await new Promise((r) => setTimeout(r, 2000));
      assert.equal(await val(page, "#p"), "", "filled one of two logins");
    } finally {
      await setAutofill({ onPageLoad: false });
    }
  });

  test("settings: menu-on-focus and next-step toggles, the never-save list", async () => {
    const popup = await kw.openPopup();
    pages.push(popup);
    const sw = (title: string) => `button[role=switch][aria-label="${title}"]`;
    const checked = (title: string) => popup.$eval(sw(title), (e) => e.getAttribute("aria-checked"));
    const waitSetting = (fn: (a: any) => boolean) =>
      (async () => {
        for (let i = 0; i < 100; i++) {
          if (fn((await settingsNow())?.autofill ?? {})) return;
          await new Promise((r) => setTimeout(r, 50));
        }
        throw new Error(`setting not saved: ${JSON.stringify((await settingsNow())?.autofill)}`);
      })();
    await clickText(kw, popup, "Settings", ".navbar button");
    await clickText(kw, popup, "Autofill", ".settings .item");

    const MENU = "Open the menu when a field is focused";
    const STEPS = "Fill the next login step";
    await popup.waitForSelector(sw(MENU), { timeout: 10_000 }); // the page slides in
    assert.equal(await checked(MENU), "true");
    assert.equal(await checked(STEPS), "true");
    await click(kw, popup, sw(STEPS));
    await waitSetting((a) => a.continueSteps === false);
    await click(kw, popup, sw(STEPS));
    await waitSetting((a) => a.continueSteps === true);
    await click(kw, popup, sw(MENU));
    await waitSetting((a) => a.menuOnFocus === false);
    assert.equal(await checked(MENU), "false");

    // With menu-on-focus off, focusing a login field shows no menu.
    const { page, tabId } = await open(FX.url("login", "/plain.html"));
    await page.bringToFront();
    await page.click("#u");
    await new Promise((r) => setTimeout(r, 1200));
    assert.equal(Object.keys(await ext.evaluate((id) => chrome.storage.session.get(`menu:${id}`), tabId)).length, 0, "the menu opened on focus");
    await page.close();

    // The save bar's "Never for this site" adds hosts; the list shows them and removes one.
    await ext.evaluate(async () => {
      const { settings } = await chrome.storage.local.get("settings");
      (settings as any).autofill.neverSave = ["drop.example", "keep.example"];
      await chrome.storage.local.set({ settings });
    });
    await clickText(kw, popup, "Sites never saved", ".settings .item");
    await popup.waitForSelector('button[aria-label="Remove drop.example"]', { timeout: 10_000 });
    await click(kw, popup, 'button[aria-label="Remove drop.example"]');
    await waitSetting((a) => JSON.stringify(a.neverSave) === '["keep.example"]');
    await popup.waitForSelector('button[aria-label="Remove drop.example"]', { hidden: true, timeout: 5000 });

    // Put the defaults back for anything that runs after this.
    await ext.evaluate(async () => {
      const { settings } = await chrome.storage.local.get("settings");
      Object.assign((settings as any).autofill, { neverSave: [], menuOnFocus: true, continueSteps: true });
      await chrome.storage.local.set({ settings });
    });
    await popup.close().catch(() => {});
  });
});
