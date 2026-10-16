// The popup's frame while its list scrolls: the search bar and the New button stay where they
// are and only the rows move; a mouse wheel scrolls the filter chips sideways; a menu's button
// closes the menu it opened.
import assert from "node:assert/strict";
import { after, before, describe, test as nodeTest } from "node:test";
import type { Page } from "puppeteer-core";
import { click, login, waitForItems } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { importItems, login as apiLogin, randomPassword, register, uniqueEmail } from "../lib/vw.ts";
import { emptyView } from "../../src/core/vault/cipher.ts";
import { CipherType } from "../../src/core/vault/types.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
let kw: Keyward;
let page: Page;
const email = uniqueEmail("layout");
const password = randomPassword();

function test(name: string, fn: () => Promise<void>) {
  nodeTest(name, async () => {
    try {
      await fn();
    } catch (e) {
      await kw.screenshot(page, `tests/.artifacts/layout-${target}-FAIL-${name.replace(/\W+/g, "-").slice(0, 40)}.png`).catch(() => {});
      throw e;
    }
  });
}

/** Top edges of the parts that must not move, and how far the rows are scrolled. */
const frame = () =>
  page.evaluate(() => {
    const top = (s: string) => Math.round(document.querySelector(s)!.getBoundingClientRect().top);
    return { search: top(".searchbar"), chips: top(".list-head .chips"), fab: top(".fab"), scrolled: Math.round(document.querySelector(".list-scroll")!.scrollTop) };
  });

describe(`popup layout (${target})`, () => {
  before(async () => {
    await register(email, password);
    const api = await apiLogin(email, password);
    await importItems(api, Array.from({ length: 40 }, (_, i) => emptyView(CipherType.SecureNote, { name: `Note ${String(i).padStart(2, "0")}`, notes: "x" })));
    kw = await launch(target);
    page = await kw.openPopup();
    await login(kw, page, env.KW_SERVER, email, password);
    await waitForItems(page, 40);
  });
  after(async () => kw?.close());

  test("scrolling moves the rows only: the search bar and New stay put", async () => {
    const before = await frame();
    for (const y of [3, 8, 600]) {
      await page.$eval(".list-scroll", (e, y) => ((e as HTMLElement).scrollTop = y), y);
      await new Promise((r) => setTimeout(r, 100));
      const now = await frame();
      assert.ok(now.scrolled > 0, "the rows scrolled");
      assert.deepEqual([now.search, now.chips, now.fab], [before.search, before.chips, before.fab], `scrolled to ${y}`);
    }
    // The page itself doesn't scroll: the scrollbar belongs to the rows.
    assert.equal(await page.$eval(".scroll", (e) => e.scrollHeight - e.clientHeight), 0);
  });

  test("a mouse wheel scrolls the filter chips sideways, then the list", async () => {
    const chips = ".list-head .chips";
    const wheel = (dy: number) =>
      page.$eval(chips, (e, dy) => {
        const ev = new WheelEvent("wheel", { deltaY: dy, bubbles: true, cancelable: true });
        e.firstElementChild!.dispatchEvent(ev);
        return ev.defaultPrevented;
      }, dy);
    assert.ok(await page.$eval(chips, (e) => e.scrollWidth > e.clientWidth), "the chips overflow the popup");
    assert.equal(await wheel(120), true, "the wheel went to the chips");
    assert.ok((await page.$eval(chips, (e) => e.scrollLeft)) > 0);
    // At the end of the row the wheel is left to scroll the page.
    await page.$eval(chips, (e) => (e.scrollLeft = e.scrollWidth));
    assert.equal(await wheel(120), false);
  });

  test("a menu's button closes the menu it opened", async () => {
    const button = 'button[aria-label="Account and vault menu"]';
    // A real press: pointerdown, then click (LibreWolf's BiDi can't send input to our pages).
    const press = () =>
      target === "chromium"
        ? click(kw, page, button)
        : page.$eval(button, (e) => {
            e.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true }));
            (e as HTMLElement).click();
          });
    await press();
    await page.waitForSelector(".menu", { timeout: 5000 });
    await press();
    await page.waitForSelector(".menu", { hidden: true, timeout: 5000 });
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(await page.$(".menu"), null, "it stays closed");
    // And opens again on the next press.
    await press();
    await page.waitForSelector(".menu", { timeout: 5000 });
  });
});
