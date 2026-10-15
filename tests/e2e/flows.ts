// UI flows shared by the E2E tests. Inputs are found by their aria-label (the field label).
import type { Page } from "puppeteer-core";
import type { Keyward } from "./launch.ts";

export const sel = {
  field: (label: string) => `input[aria-label="${label}"]`,
};

/** Sets a field's value through the native setter and fires `input` (what Preact listens to).
 * Firefox BiDi can't send key events to privileged pages, and per-key typing into pre-filled
 * fields was flaky in Helium, so both browsers use this path for our own UI. */
export async function fill(_kw: Keyward, page: Page, selector: string, value: string) {
  await page.waitForSelector(selector, { visible: true, timeout: 10_000 });
  await page.$eval(
    selector,
    (el, v) => {
      const input = el as HTMLInputElement;
      input.focus();
      Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value")!.set!.call(input, v);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    },
    value,
  );
}

export async function click(kw: Keyward, page: Page, selector: string) {
  await page.waitForSelector(selector, { visible: true, timeout: 10_000 });
  if (kw.target === "chromium") return page.click(selector);
  await page.$eval(selector, (el) => (el as HTMLElement).click());
}

/** Clicks the first button/menu item whose text matches. */
export async function clickText(kw: Keyward, page: Page, text: string, scope = "button, [role=button], [role=menuitem]") {
  const handle = await page.waitForFunction(
    (t, s) => [...document.querySelectorAll<HTMLElement>(s)].find((e) => e.textContent?.trim().includes(t) && e.offsetParent !== null) ?? null,
    { timeout: 10_000 },
    text,
    scope,
  );
  await settle(page);
  // Centre it first: a row at the edge of the list can sit under the FAB or the bottom bar.
  await (handle as any).evaluate((e: HTMLElement) => e.scrollIntoView({ block: "center", behavior: "instant" }));
  // Real clicks in Helium; fall back to element.click() if the target is mid-transition.
  if (kw.target === "chromium") await (handle as any).click().catch(() => (handle as any).evaluate((e: HTMLElement) => e.click()));
  else await (handle as any).evaluate((e: HTMLElement) => e.click());
}

/** Waits until page transitions finish (infinite animations like spinners are ignored). */
export async function settle(page: Page) {
  await page
    .waitForFunction("document.getAnimations().every((a) => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity)", { timeout: 3000, polling: 30 })
    .catch(() => {});
}

export async function login(kw: Keyward, page: Page, server: string, email: string, password: string) {
  await page.waitForSelector(".auth-head h1");
  const host = new URL(server).host;
  const shown = await page.evaluate(() => document.querySelector(".auth-body .item .sub")?.textContent ?? "");
  if (shown !== host) {
    if (!(await page.$(sel.field("Server URL")))) await clickText(kw, page, "Server");
    await fill(kw, page, sel.field("Server URL"), server);
  }
  await fill(kw, page, sel.field("Email"), email);
  await fill(kw, page, sel.field("Master password"), password);
  await clickText(kw, page, "Log in");
}

/** Names of the rows currently rendered (the list is windowed: use findItem for a specific one). */
export async function itemNames(page: Page): Promise<string[]> {
  return page.$$eval(".vault-list .list-section .item .title", (els) => els.map((e) => e.textContent ?? ""));
}

/** Waits until the vault list reports at least `min` items (rendered or not) and returns the count. */
export async function waitForItems(page: Page, min = 1, timeout = 30_000): Promise<number> {
  await page.waitForFunction((n) => Number(document.querySelector(".vlist")?.getAttribute("data-count") ?? 0) >= n, { timeout, polling: 100 }, min);
  return page.$eval(".vlist", (e) => Number(e.getAttribute("data-count")));
}

/** Searches the vault for `name` and reports whether a row with exactly that title shows up. */
export async function findItem(kw: Keyward, page: Page, name: string): Promise<boolean> {
  await fill(kw, page, 'input[aria-label="Search vault"]', name);
  const found = await page
    .waitForFunction((n) => [...document.querySelectorAll(".vault-list .item .title")].some((e) => e.textContent === n), { timeout: 3000, polling: 50 }, name)
    .then(() => true, () => false);
  await fill(kw, page, 'input[aria-label="Search vault"]', "");
  return found;
}

export async function waitForText(page: Page, text: string, timeout = 15_000) {
  await page.waitForFunction((t) => document.body.innerText.includes(t), { timeout, polling: 100 }, text);
}
