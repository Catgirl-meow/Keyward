// P3: organizations (shared items, collections) and attachments.
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { after, before, describe, test } from "node:test";
import type { Page } from "puppeteer-core";
import { click, clickText, fill, login, sel, settle, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { createOrg, createOrgItem, login as apiLogin, randomPassword, register, uniqueEmail, type Session } from "../lib/vw.ts";
import { decryptCipher, emptyView, itemKey } from "../../src/core/vault/cipher.ts";
import { decryptBuffer, decryptBytes } from "../../src/core/crypto/encstring.ts";
import { SymKey } from "../../src/core/crypto/symkey.ts";
import { CipherType } from "../../src/core/vault/types.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
let kw: Keyward;
let page: Page;
let s: Session;
let org: Awaited<ReturnType<typeof createOrg>>;
const email = uniqueEmail("org");
const password = randomPassword();

const sync = () => s.api.get("/sync?excludeDomains=true");

describe(`organizations and attachments (${target})`, () => {
  before(async () => {
    await register(email, password);
    s = await apiLogin(email, password);
    org = await createOrg(s, "Family", "Shared");
    const v = emptyView(CipherType.Login, { name: "Family Netflix" });
    v.login!.username = "family@example.test";
    v.login!.password = "shared-Pass-1";
    await createOrgItem(s, v, org.orgId, [org.collectionId]);
    kw = await launch(target);
    page = await kw.openPopup();
    await login(kw, page, env.KW_SERVER, email, password);
    await page.waitForSelector(".vault-list .list-section .item", { timeout: 30_000 });
  });
  after(async () => kw?.close());

  test("organization items decrypt and show their organization", async () => {
    await clickText(kw, page, "Family Netflix", ".vault-list .item");
    await page.waitForSelector(".item-view .topbar");
    await waitForText(page, "family@example.test");
    await waitForText(page, "Family");
    await click(kw, page, '.topbar button[aria-label="Back"]');
  });

  test("create an item in an organization collection", async () => {
    await settle(page);
    await clickText(kw, page, "New", "button.fab");
    await clickText(kw, page, "Login", '[role="menuitem"]');
    await fill(kw, page, sel.field("Name"), "Family router");
    await fill(kw, page, sel.field("Username"), "admin");
    await page.$eval('select[aria-label="Owner"]', (el, id) => {
      const s = el as HTMLSelectElement;
      s.value = id;
      s.dispatchEvent(new Event("change", { bubbles: true }));
    }, org.orgId);
    await clickText(kw, page, "Shared", ".item");
    await clickText(kw, page, "Save", ".topbar button");
    await page.waitForSelector(".item-view", { timeout: 10_000 }).catch(async (e) => {
      console.log("banner:", await page.evaluate(() => document.querySelector(".banner")?.textContent ?? document.body.innerText.slice(0, 400)));
      throw e;
    });
    const data = await sync();
    const raw = data.ciphers.find((c: any) => c.organizationId === org.orgId && c.collectionIds?.includes(org.collectionId) && c.login?.username);
    const views = await Promise.all(data.ciphers.filter((c: any) => c.organizationId === org.orgId).map((c: any) => decryptCipher(c, s.ring)));
    const mine = views.find((v) => v.name === "Family router");
    assert.ok(raw && mine, "org item not on the server");
    assert.equal(mine.login?.username, "admin");
    assert.deepEqual(mine.collectionIds, [org.collectionId]);
    await click(kw, page, '.topbar button[aria-label="Back"]');
  });

  test("attachment upload, server copy decrypts", { skip: target !== "chromium" && "file inputs aren't scriptable over BiDi on privileged pages" }, async () => {
    const file = "tests/.artifacts/attachment.txt";
    writeFileSync(file, "Keyward attachment ✓ " + Date.now());
    await settle(page);
    await clickText(kw, page, "Family Netflix", ".vault-list .item");
    await click(kw, page, '.item-view .topbar button[aria-label="Edit"]');
    const input = await page.waitForSelector('input[type="file"]');
    await input!.uploadFile(file);
    await waitForText(page, "Attachment added", 15_000);
    const data = await sync();
    const raw = data.ciphers.find((c: any) => c.attachments?.length);
    assert.ok(raw, "no attachment on the server");
    const view = await decryptCipher(raw, s.ring);
    const a = view.attachments[0];
    assert.equal(a.fileName, "attachment.txt");
    const meta = await s.api.get(`/ciphers/${raw.id}/attachment/${a.id}`);
    const res = await s.api.request<Response>("GET", meta.url, undefined, { base: "abs", raw: true, auth: !/token=/.test(meta.url) });
    const key = new SymKey(await decryptBytes(meta.key ?? a.key!, await itemKey(raw, s.ring)));
    const plain = new TextDecoder().decode(await decryptBuffer(new Uint8Array(await res.arrayBuffer()), key));
    assert.match(plain, /^Keyward attachment ✓ \d+$/);
  });
});
