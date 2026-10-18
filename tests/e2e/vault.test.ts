// P3: writes. Every change made in the UI is checked on the server by decrypting it with the
// API session, and server-side changes are checked in the UI.
import assert from "node:assert/strict";
import { after, before, describe, test as nodeTest } from "node:test";
import type { Page } from "puppeteer-core";
import { click, clickText, fill, findItem, login, sel, settle, waitForItems, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { login as apiLogin, randomPassword, register, uniqueEmail, type Session } from "../lib/vw.ts";
import { decryptCipher, encryptCipher } from "../../src/core/vault/cipher.ts";
import { decryptString } from "../../src/core/crypto/encstring.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
let kw: Keyward;
let page: Page;
let api: Session;
const email = uniqueEmail("crud");
const password = randomPassword();

function test(name: string, fn: () => Promise<void>) {
  nodeTest(name, async () => {
    try {
      await fn();
    } catch (e) {
      await kw.screenshot(page, `tests/.artifacts/vault-${target}-FAIL-${name.replace(/\W+/g, "-").slice(0, 40)}.png`).catch(() => {});
      console.log(`--- page text (${name}):\n${String(await page.evaluate("document.body.innerText").catch(() => "")).slice(0, 600)}`);
      throw e;
    }
  });
}

/** Server state, decrypted with the API session's keys. */
async function serverItems() {
  const data = await api.api.get("/sync?excludeDomains=true");
  const views = await Promise.all(data.ciphers.map((c: any) => decryptCipher(c, api.ring)));
  return { views, raw: data.ciphers as any[], folders: await Promise.all(data.folders.map(async (f: any) => ({ id: f.id, name: await decryptString(f.name, api.ring.user) }))) };
}
const byName = async (name: string) => (await serverItems()).views.find((v) => v.name === name);
const until = async <T>(fn: () => Promise<T | undefined | false>, ms = 10_000): Promise<T> => {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v as T;
    if (Date.now() > end) throw new Error("condition not met on the server");
    await new Promise((r) => setTimeout(r, 200));
  }
};

async function openItem(name: string) {
  await fill(kw, page, 'input[aria-label="Search vault"]', name);
  await clickText(kw, page, name, ".vault-list .item");
  await page.waitForSelector(".item-view .topbar", { timeout: 5000 });
  await settle(page);
}
async function back() {
  for (let i = 0; i < 4 && !(await page.$(".vault-list")); i++) {
    await click(kw, page, '.topbar button[aria-label="Back"]');
    await settle(page);
  }
  await page.waitForSelector(".vault-list", { timeout: 5000 });
  await fill(kw, page, 'input[aria-label="Search vault"]', "");
}
async function menu(label: string) {
  await click(kw, page, '.item-view .topbar button[aria-label="More"]');
  await clickText(kw, page, label, '[role="menuitem"]');
}

describe(`vault writes (${target})`, () => {
  before(async () => {
    await register(email, password);
    api = await apiLogin(email, password);
    kw = await launch(target);
    page = await kw.openPopup();
    await login(kw, page, env.KW_SERVER, email, password);
    await waitForText(page, "Your vault is empty", 30_000);
  });
  after(async () => kw?.close());

  test("create a login", async () => {
    await clickText(kw, page, "New", "button.fab");
    await clickText(kw, page, "Login", '[role="menuitem"]');
    await fill(kw, page, sel.field("Name"), "Created in Keyward");
    await fill(kw, page, sel.field("Username"), "kw-user");
    await fill(kw, page, sel.field("Password"), "first-Password-1");
    await clickText(kw, page, "Add website");
    await fill(kw, page, sel.field("Website"), "https://created.example.test/login");
    await clickText(kw, page, "Save", ".topbar button");
    await page.waitForSelector(".item-view", { timeout: 10_000 });
    const v = await until(() => byName("Created in Keyward"));
    assert.equal(v.login?.username, "kw-user");
    assert.equal(v.login?.password, "first-Password-1");
    assert.equal(v.login?.uris[0]?.uri, "https://created.example.test/login");
    assert.ok(v.hasItemKey, "new items get their own item key");
  });

  test("edit keeps password history", async () => {
    await click(kw, page, '.item-view .topbar button[aria-label="Edit"]');
    await fill(kw, page, sel.field("Password"), "second-Password-2");
    await clickText(kw, page, "Save", ".topbar button");
    await page.waitForSelector(".item-view", { timeout: 10_000 });
    const v = await until(async () => {
      const x = await byName("Created in Keyward");
      return x?.login?.password === "second-Password-2" && x;
    });
    assert.equal(v.passwordHistory[0]?.password, "first-Password-1");
    await waitForText(page, "Password history (1)");
  });

  test("favorite", async () => {
    await click(kw, page, '.item-view .topbar button[aria-label="Add to favorites"]');
    await until(async () => (await byName("Created in Keyward"))?.favorite);
    await back();
  });

  test("other item types round-trip", async () => {
    for (const [type, name, fields] of [
      ["Card", "Test card", [["Cardholder name", "Kay Ward"], ["Number", "4111111111111111"], ["Exp. month", "12"], ["Exp. year", "2031"], ["Security code", "123"]]],
      ["Note", "Test note", [["Notes", "line one"]]],
    ] as const) {
      await clickText(kw, page, "New", "button.fab");
      await clickText(kw, page, type, '[role="menuitem"]');
      await fill(kw, page, sel.field("Name"), name);
      for (const [label, value] of fields) {
        const s = label === "Notes" ? `textarea[aria-label="Notes"]` : sel.field(label);
        await fill(kw, page, s, value);
      }
      await clickText(kw, page, "Save", ".topbar button");
      await page.waitForSelector(".item-view", { timeout: 10_000 });
      await back();
    }
    const card = await until(() => byName("Test card"));
    assert.equal(card.card?.number, "4111111111111111");
    assert.equal(card.card?.brand, "Visa", "brand detected from the number");
    assert.equal((await byName("Test note"))?.notes, "line one");
  });

  test("trash, restore, delete forever", async () => {
    await openItem("Test note");
    await menu("Move to trash");
    await clickText(kw, page, "Move to trash", ".dialog button");
    await page.waitForSelector(".vault-list", { timeout: 10_000 });
    await until(async () => !!(await byName("Test note"))?.deletedDate);
    assert.equal(await findItem(kw, page, "Test note"), false, "trashed item still listed");
    // Restore from trash (Settings → Trash shows the trash filter).
    await clickText(kw, page, "Settings", ".navbar button");
    await clickText(kw, page, "Trash", ".item");
    await clickText(kw, page, "Test note", ".vault-list .item");
    await page.waitForSelector(".item-view .topbar");
    await menu("Restore");
    await until(async () => (await byName("Test note"))?.deletedDate === null);
    // And delete forever: trash it again, then delete from the trash.
    await menu("Move to trash");
    await clickText(kw, page, "Move to trash", ".dialog button");
    await until(async () => !!(await byName("Test note"))?.deletedDate);
    await clickText(kw, page, "Test note", ".vault-list .item");
    await page.waitForSelector(".item-view .topbar");
    await menu("Delete forever");
    await clickText(kw, page, "Delete", ".dialog button");
    await until(async () => !(await byName("Test note")));
    await clickText(kw, page, "Trash", '.chip[aria-pressed="true"]');
    await page.waitForFunction(() => !document.querySelector('.chip[aria-pressed="true"]'), { timeout: 3000 });
  });

  test("folders: create, file an item, delete", async () => {
    await clickText(kw, page, "Settings", ".navbar button");
    await clickText(kw, page, "Folders", ".item");
    await fill(kw, page, sel.field("New folder"), "Projects");
    await click(kw, page, 'button[aria-label="Add folder"]');
    const folder = await until(async () => (await serverItems()).folders.find((f) => f.name === "Projects"));
    await waitForText(page, "Projects");
    await clickText(kw, page, "Vault", ".navbar button");
    await openItem("Created in Keyward");
    await menu("Move to folder…");
    await clickText(kw, page, "Projects", '[role="menuitem"]');
    await until(async () => (await byName("Created in Keyward"))?.folderId === folder.id);
    await back();
  });

  test("an item changed elsewhere is kept, our edit becomes a copy", async () => {
    await openItem("Created in Keyward");
    await click(kw, page, '.item-view .topbar button[aria-label="Edit"]');
    // Meanwhile another device edits the same item.
    const data = await serverItems();
    const raw = data.raw.find((r: any) => data.views.find((v) => v.id === r.id)?.name === "Created in Keyward");
    const theirs = { ...(await decryptCipher(raw, api.ring)) };
    theirs.login = { ...theirs.login!, username: "changed-elsewhere" };
    const { body } = await encryptCipher(theirs, api.ring, { base: raw, encryptedFor: api.login.userId });
    await new Promise((r) => setTimeout(r, 1100)); // revision dates have 1 s resolution in some servers
    await api.api.put(`/ciphers/${raw.id}`, body);
    // Our edit, based on the stale copy.
    await fill(kw, page, sel.field("Username"), "changed-here");
    await clickText(kw, page, "Save", ".topbar button");
    await waitForText(page, "saved as a copy", 10_000);
    const after = await serverItems();
    assert.equal(after.views.find((v) => v.name === "Created in Keyward")?.login?.username, "changed-elsewhere");
    assert.equal(after.views.find((v) => v.name === "Created in Keyward (conflict copy)")?.login?.username, "changed-here");
    await back();
  });

  test("a change made on the server shows up after sync", async () => {
    const v = await byName("Test card");
    const raw = (await serverItems()).raw.find((r: any) => r.id === v!.id);
    const { body } = await encryptCipher({ ...v!, name: "Renamed on server" }, api.ring, { base: raw, encryptedFor: api.login.userId });
    await api.api.put(`/ciphers/${v!.id}`, body);
    await click(kw, page, 'button[aria-label="Account and vault menu"]');
    await clickText(kw, page, "Sync now", '[role="menuitem"]');
    assert.ok(await findItem(kw, page, "Renamed on server"));
    assert.equal(await waitForItems(page, 1), 3);
  });
});
