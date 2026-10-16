// P6: two accounts in one browser. Each sees only its own vault, Sends and Watchtower; locking
// and unlocking go per account; logging one out leaves the other and removes everything the
// logged-out one kept.
import assert from "node:assert/strict";
import { after, before, describe, test as nodeTest } from "node:test";
import type { Page } from "puppeteer-core";
import { click, clickText, fill, login, sel, settle, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { importItems, login as apiLogin, randomPassword, register, uniqueEmail } from "../lib/vw.ts";
import { emptyView } from "../../src/core/vault/cipher.ts";
import { CipherType } from "../../src/core/vault/types.ts";
import { encryptSend, inDays, SendType } from "../../src/core/send/send.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
let kw: Keyward;
let page: Page;
const A = { email: uniqueEmail("alpha"), password: randomPassword(), id: "" };
const B = { email: uniqueEmail("bravo"), password: randomPassword(), id: "" };

function test(name: string, fn: () => Promise<void>) {
  nodeTest(name, async () => {
    try {
      await fn();
    } catch (e) {
      await kw.screenshot(page, `tests/.artifacts/accounts-${target}-FAIL-${name.replace(/\W+/g, "-").slice(0, 40)}.png`).catch(() => {});
      console.log(`--- page text (${name}):\n${String(await page.evaluate("document.body.innerText").catch(() => "")).slice(0, 800)}`);
      throw e;
    }
  });
}

const note = (name: string) => emptyView(CipherType.Login, { name, login: { username: "u", password: "Pw-" + name + "-9!x", passwordRevisionDate: null, totp: null, uris: [{ uri: `https://${name.toLowerCase().replace(/\W/g, "")}.example`, match: null }], autofillOnPageLoad: null, fido2Credentials: [] } });
const bodyText = () => page.evaluate(() => document.body.innerText);
async function menu(item: string) {
  await click(kw, page, 'button[aria-label="Account and vault menu"]');
  await clickText(kw, page, item, '[role="menuitem"]');
}
async function tab(name: string) {
  await clickText(kw, page, name, "nav button");
  await settle(page);
}
async function unlock(password: string) {
  await fill(kw, page, sel.field("Master password"), password);
  await clickText(kw, page, "Unlock");
}
/** Storage keys, IndexedDB names and accounts, as the extension holds them. */
const held = () =>
  page.evaluate(async () => ({
    local: Object.keys(await chrome.storage.local.get(null)),
    session: Object.keys(await chrome.storage.session.get(null)),
    dbs: (await indexedDB.databases()).map((d) => d.name ?? ""),
    accounts: (((await chrome.storage.local.get("accounts")) as any).accounts?.list ?? []).map((a: any) => [a.email, a.id]) as [string, string][],
  }));

describe(`accounts (${target})`, () => {
  before(async () => {
    for (const [who, item] of [[A, "Alpha mail"], [B, "Bravo bank"]] as const) {
      await register(who.email, who.password);
      const s = await apiLogin(who.email, who.password);
      await importItems(s, [note(item)]);
      if (who === A) {
        const { body } = await encryptSend({ type: SendType.Text, name: "Alpha send", notes: null, text: { text: "a", hidden: false }, maxAccessCount: null, expirationDate: null, deletionDate: inDays(2), disabled: false, hideEmail: false }, s.ring.user);
        await s.api.post("/sends", body);
      }
    }
    kw = await launch(target);
    page = await kw.openPopup();
    page.on("pageerror", (e) => console.log("PAGEERROR", (e as Error).message));
    await login(kw, page, env.KW_SERVER, A.email, A.password);
    await waitForText(page, "Alpha mail", 30_000);
  });
  after(async () => kw?.close());

  test("a second account has its own vault, Sends and Watchtower", async () => {
    await menu("Add account");
    await login(kw, page, env.KW_SERVER, B.email, B.password);
    await waitForText(page, "Bravo bank", 30_000);
    assert.ok(!(await bodyText()).includes("Alpha mail"));
    await tab("Send");
    await waitForText(page, "Only people with the link can open it");
    await tab("Watchtower");
    await waitForText(page, "1 item checked");
    // Something only B keeps: a generated password in its history.
    await tab("Generator");
    await click(kw, page, '.gen-output button[aria-label="Copy"]');
    const ids = Object.fromEntries((await held()).accounts);
    A.id = ids[A.email];
    B.id = ids[B.email];
    assert.ok(A.id && B.id && A.id !== B.id);
    await page.waitForFunction(async (id) => !!(await chrome.storage.local.get(`genHistory:${id}`))[`genHistory:${id}`], { timeout: 5000 }, B.id);
  });

  test("switching shows the other account's vault, Sends and Watchtower", async () => {
    await tab("Vault");
    await menu(A.email);
    await waitForText(page, "Alpha mail", 15_000);
    assert.ok(!(await bodyText()).includes("Bravo bank"));
    await tab("Send");
    await waitForText(page, "Alpha send");
    await tab("Watchtower");
    await waitForText(page, "1 item checked");
    await tab("Vault");
  });

  test("lock locks both; each unlocks with its own password", async () => {
    await menu("Lock");
    await waitForText(page, "Vault is locked");
    assert.ok((await bodyText()).includes(A.email));
    await click(kw, page, 'button[aria-label="Account options"]');
    await clickText(kw, page, `Switch to ${B.email}`, '[role="menuitem"]');
    await page.waitForFunction((e) => document.body.innerText.includes(e), { timeout: 8000 }, B.email);
    await unlock(A.password); // the other account's password
    await page.waitForSelector(".banner.error", { timeout: 15_000 });
    assert.match(await page.$eval(".banner.error", (e) => e.textContent ?? ""), /invalid master password/i);
    await unlock(B.password);
    await waitForText(page, "Bravo bank", 20_000);
  });

  test("logging out removes that account and everything it kept, and leaves the other", async () => {
    const before = await held();
    assert.ok(before.local.some((k) => k.endsWith(`:${B.id}`)), "B keeps data before logout");
    await menu("Log out");
    await clickText(kw, page, "Log out", ".dialog button");
    // A is the active account again, still locked from before.
    await waitForText(page, "Vault is locked", 15_000);
    assert.ok((await bodyText()).includes(A.email));
    const now = await held();
    assert.deepEqual(now.accounts.map(([e]) => e), [A.email]);
    const leftovers = [...now.local, ...now.session, ...now.dbs].filter((k) => k.includes(B.id));
    assert.deepEqual(leftovers, [], "nothing of the logged-out account stays");
    assert.ok(now.dbs.some((d) => d.includes(A.id)), "A's offline copy stays");
    await unlock(A.password);
    await waitForText(page, "Alpha mail", 20_000);
  });
});
