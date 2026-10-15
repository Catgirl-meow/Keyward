// P4: autofill against the fixture corpus (tests/fixtures/forms). Fills are started the way the
// popup starts them (RPC with the page's tab id) or from the page itself (focus → inline menu →
// keys), and checked by reading the page's fields.
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { after, before, describe, test as nodeTest } from "node:test";
import type { Frame, Page } from "puppeteer-core";
import { login, waitForItems } from "./flows.ts";
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
 * after the navigation and replace it. */
async function open(url: string): Promise<{ page: Page; tabId: number }> {
  const want = new URL(url).href;
  const existing = new Set(kw.browser.targets());
  const created = kw.browser.waitForTarget((t) => !existing.has(t) && t.type() === "page" && t.url() === want, { timeout: 15_000 });
  const tabId: number = await ext.evaluate((u) => chrome.tabs.create({ url: u, active: true }).then((t) => t.id!), want);
  const page = (await (await created).asPage()) as Page;
  pages.push(page);
  if (process.env.KW_DEBUG) page.on("console", (m) => m.text().startsWith("[kw]") && console.log(m.text()));
  await page.waitForFunction((u) => location.href === u && document.readyState === "complete", { timeout: 15_000, polling: 50 }, want);
  return { page, tabId };
}
const newTab = async (url: string) => (await open(url)).page;

const fillItem = (tabId: number, name: string, force?: boolean) => call<{ filled: boolean; error?: string; confirm?: string; totpCopied?: boolean }>("autofill.fill", { tabId, itemId: ids[name], force });
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
      emptyView(CipherType.Card, { name: "Visa", card: { cardholderName: "Kay Ward", brand: "Visa", number: "4111111111111111", expMonth: "7", expYear: "2031", code: "123" } }),
      ident,
    ]);
    const data = await sync(api);
    for (const c of data.ciphers) ids[(await decryptCipher(c, api.ring)).name] = c.id;
    kw = await launch(target);
    ext = await kw.openPopup();
    await login(kw, ext, env.KW_SERVER, email, password);
    await waitForItems(ext, 6, 30_000);
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
    assert.equal(boxes, await totpNow(FX.mailfence.totp), "one digit per box");
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
    assert.equal(saved.login?.uris[0]?.uri, "http://shop.localhost:8090");
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
});
