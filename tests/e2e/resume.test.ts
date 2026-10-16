// The popup closes whenever it loses focus (copying from a terminal, a file dialog on Linux).
// It keeps its screen and unsaved forms in storage.session, so reopening it carries on; locking
// throws them away; and choosing a file moves the screen to the full tab (src/ui/data/resume.ts).
import assert from "node:assert/strict";
import { after, before, describe, test as nodeTest } from "node:test";
import type { Page } from "puppeteer-core";
import { click, clickText, fill, login, sel, settle, waitForItems, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { login as apiLogin, randomPassword, register, sync, uniqueEmail, type Session } from "../lib/vw.ts";
import { decryptCipher } from "../../src/core/vault/cipher.ts";
import { decryptSend, SendType, type RawSend } from "../../src/core/send/send.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
let kw: Keyward;
let page: Page;
let api: Session;
const email = uniqueEmail("resume");
const password = randomPassword();

function test(name: string, fn: () => Promise<void>) {
  nodeTest(name, async () => {
    try {
      await fn();
    } catch (e) {
      await kw.screenshot(page, `tests/.artifacts/resume-${target}-FAIL-${name.replace(/\W+/g, "-").slice(0, 40)}.png`).catch(() => {});
      console.log(`--- page text (${name}):\n${String(await page.evaluate("document.body.innerText").catch(() => "")).slice(0, 800)}`);
      throw e;
    }
  });
}

const until = async <T>(fn: () => Promise<T | undefined | false>, ms = 10_000): Promise<T> => {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v as T;
    if (Date.now() > end) throw new Error("condition not met");
    await new Promise((r) => setTimeout(r, 200));
  }
};
const value = (p: Page, label: string) => p.$eval(sel.field(label), (e) => (e as HTMLInputElement).value);
/** What the popup keeps for the account, straight from storage.session. */
const kept = (p: Page) => p.evaluate(async () => Object.entries(await chrome.storage.session.get(null)).filter(([k]) => k.startsWith("ui:")).map(([, v]) => v as any));

/** The popup closes (here: its page) and opens again. */
async function reopen() {
  await settle(page);
  await page.close();
  page = await kw.openPopup();
}

describe(`popup keeps its screen (${target})`, () => {
  before(async () => {
    await register(email, password);
    api = await apiLogin(email, password);
    kw = await launch(target);
    page = await kw.openPopup();
    await login(kw, page, env.KW_SERVER, email, password);
    await page.waitForSelector(".vault-list", { timeout: 30_000 });
  });
  after(async () => kw?.close());

  test("a half-typed login survives the popup closing; saving it drops the kept copy", async () => {
    await click(kw, page, "button.fab");
    await clickText(kw, page, "Login", '[role="menuitem"]');
    await fill(kw, page, sel.field("Name"), "Half-typed");
    await fill(kw, page, sel.field("Username"), "kay@example.com");
    await fill(kw, page, sel.field("Password"), "Typed-Before-Closing-1");
    await reopen();
    await page.waitForSelector(".item-edit", { timeout: 15_000 });
    assert.deepEqual([await value(page, "Name"), await value(page, "Username"), await value(page, "Password")], ["Half-typed", "kay@example.com", "Typed-Before-Closing-1"]);
    await clickText(kw, page, "Save", ".topbar button");
    await page.waitForSelector(".item-view", { timeout: 15_000 });
    const saved = await until(async () => {
      for (const raw of (await sync(api)).ciphers) {
        const v = await decryptCipher(raw, api.ring);
        if (v.name === "Half-typed") return v;
      }
    });
    assert.equal(saved.login?.password, "Typed-Before-Closing-1");
    // Reopened, the popup shows the saved item, not the form.
    await reopen();
    await page.waitForSelector(".item-view", { timeout: 15_000 });
    await waitForText(page, "kay@example.com");
    assert.equal(await page.$(".item-edit"), null);
    assert.deepEqual((await kept(page))[0]?.drafts, {});
  });

  test("locking throws the kept form away", async () => {
    await click(kw, page, '.topbar button[aria-label="Back"]');
    await waitForItems(page, 1);
    await click(kw, page, "button.fab");
    await clickText(kw, page, "Note", '[role="menuitem"]');
    await fill(kw, page, sel.field("Name"), "Never saved");
    await settle(page);
    assert.equal(Object.keys((await kept(page))[0]?.drafts ?? {}).length, 1);
    await page.close();
    // Locked from the full tab while the popup is closed.
    const vault = await kw.openVault();
    await click(kw, vault, 'button[aria-label="Account and vault menu"]');
    await clickText(kw, vault, "Lock", '[role="menuitem"]');
    await waitForText(vault, "Vault is locked");
    await vault.close();
    page = await kw.openPopup();
    await waitForText(page, "Vault is locked");
    assert.deepEqual(await kept(page), []);
    await fill(kw, page, sel.field("Master password"), password);
    await clickText(kw, page, "Unlock");
    await waitForItems(page, 1);
    assert.equal(await page.$(".item-edit"), null);
  });

  test("choosing a file in the popup moves the Send to the full tab, which creates it", async () => {
    await clickText(kw, page, "Send", "nav button");
    await click(kw, page, "button.fab");
    await clickText(kw, page, "File", '[role="menuitem"]');
    await fill(kw, page, sel.field("Name"), "Moved to the tab");
    await settle(page);
    // A real click on the picker, as the user makes it: no file dialog opens in the popup.
    await click(kw, page, "label.file-pick");
    // Polled: over BiDi, puppeteer's waitForTarget misses a new tab's URL.
    const tab = await until(async () => (await kw.browser.pages()).find((p) => p.url().includes("/vault.html")), 15_000);
    await tab.waitForSelector(".send-edit", { timeout: 15_000 });
    assert.equal(await value(tab, "Name"), "Moved to the tab");
    assert.ok(!(await tab.evaluate(() => location.hash)), "the tab drops #resume once it took over");
    // The tab took the screen over: the popup won't bring it back too.
    await until(async () => (await kept(tab)).length === 0);
    const body = "picked in the full tab " + Date.now();
    await tab.$eval('input[type="file"]', (el, text) => {
      const dt = new DataTransfer();
      dt.items.add(new File([text], "picked.txt", { type: "text/plain" }));
      (el as HTMLInputElement).files = dt.files;
      el.dispatchEvent(new Event("change", { bubbles: true }));
    }, body);
    await waitForText(tab, "picked.txt");
    await clickText(kw, tab, "Save", ".topbar button");
    const s = await until(async () => {
      for (const r of (await sync(api)).sends as RawSend[]) {
        const v = await decryptSend(r, api.ring.user);
        if (v.name === "Moved to the tab") return v;
      }
    }, 20_000);
    assert.equal(s.type, SendType.File);
    assert.equal(s.file?.fileName, "picked.txt");
    page = tab;
  });
});
