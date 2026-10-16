// P6: export and import through the Settings pages. Exported files are caught in the page and
// read back with Keyward's parser (the bw interop test checks them against the official CLI).
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { after, before, describe, test as nodeTest } from "node:test";
import type { Page } from "puppeteer-core";
import { click, clickText, fill, login, sel, settle, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { importItems, login as apiLogin, PBKDF2, randomPassword, register, sync, uniqueEmail, type Session } from "../lib/vw.ts";
import { exportJson, exportPasswordProtected } from "../../src/core/export/export.ts";
import { parseImport } from "../../src/core/export/import.ts";
import { decryptString } from "../../src/core/crypto/encstring.ts";
import { decryptCipher, emptyView } from "../../src/core/vault/cipher.ts";
import { CipherType, type CipherView } from "../../src/core/vault/types.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
let kw: Keyward;
let page: Page;
let api: Session;
const email = uniqueEmail("transfer");
const password = randomPassword();

function test(name: string, fn: () => Promise<void>) {
  nodeTest(name, async () => {
    try {
      await fn();
    } catch (e) {
      await kw.screenshot(page, `tests/.artifacts/transfer-${target}-FAIL-${name.replace(/\W+/g, "-").slice(0, 40)}.png`).catch(() => {});
      console.log(`--- page text (${name}):\n${String(await page.evaluate("document.body.innerText").catch(() => "")).slice(0, 800)}`);
      throw e;
    }
  });
}

const loginItem = (name: string, user: string, pw: string, uri: string, more: Partial<CipherView> = {}) =>
  emptyView(CipherType.Login, { name, ...more, login: { username: user, password: pw, passwordRevisionDate: null, totp: null, uris: [{ uri, match: null }], autofillOnPageLoad: null, fido2Credentials: [] } });
const SEED: (CipherView & { folder?: string })[] = [
  { ...loginItem("Mail", "kay", "mail-pass-1", "https://mail.example"), folder: "Work" },
  emptyView(CipherType.SecureNote, { name: "Wi-Fi", notes: "Кириллица 🔑" }),
  emptyView(CipherType.Card, { name: "Visa", card: { cardholderName: "Kay", brand: "Visa", number: "4111111111111111", expMonth: "7", expYear: "2031", code: "123" } }),
];

const serverViews = async () => {
  const data = await sync(api);
  const folders = new Map<string, string>(await Promise.all(data.folders.map(async (f: any) => [f.id, await decryptString(f.name, api.ring.user)] as [string, string])));
  const views = await Promise.all(data.ciphers.map((c: any) => decryptCipher(c, api.ring)));
  return { views, folders, folderNames: [...folders.values()].sort() };
};
const until = async <T>(fn: () => Promise<T | undefined | false>, ms = 15_000): Promise<T> => {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v as T;
    if (Date.now() > end) throw new Error("condition not met on the server");
    await new Promise((r) => setTimeout(r, 250));
  }
};

/** Catches what the page saves (blob downloads) instead of letting the browser download it. */
async function catchDownloads() {
  await page.evaluate(() => {
    const w = window as any;
    if (w.__saved) return;
    w.__saved = [];
    const blobs = new Map<string, Blob>();
    const make = URL.createObjectURL;
    URL.createObjectURL = (b: Blob) => {
      const u = make.call(URL, b);
      blobs.set(u, b);
      return u;
    };
    const click = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
      if (this.download && blobs.has(this.href)) return void w.__saved.push({ name: this.download, blob: blobs.get(this.href) });
      return click.call(this);
    };
  });
}
async function lastSaved(count: number): Promise<{ name: string; text: string }> {
  await page.waitForFunction((n) => (window as any).__saved.length >= n, { timeout: 30_000 }, count);
  return page.evaluate(async () => {
    const s = (window as any).__saved.at(-1);
    return { name: s.name, text: await s.blob.text() };
  });
}
async function choose(selector: string, value: string) {
  await page.$eval(selector, (el, v) => {
    (el as HTMLSelectElement).value = v;
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }, value);
}
async function pickFile(name: string, text: string) {
  const input = await page.waitForSelector('input[type="file"]');
  if (target === "chromium") {
    const path = `tests/.artifacts/${name}`;
    writeFileSync(path, text);
    await input!.uploadFile(path);
  } else {
    // BiDi can't set files on an extension page's input; the page's own DataTransfer can.
    await input!.evaluate((el, n, t) => {
      const dt = new DataTransfer();
      dt.items.add(new File([t], n));
      (el as HTMLInputElement).files = dt.files;
      el.dispatchEvent(new Event("change", { bubbles: true }));
    }, name, text);
  }
}
async function openSettingsPage(title: string) {
  await clickText(kw, page, "Settings", "nav button");
  await clickText(kw, page, title, ".settings .item");
  await page.waitForSelector(".transfer", { timeout: 8000 });
  await settle(page);
}
async function exportAs(format: string, extra?: () => Promise<void>) {
  await choose('select[aria-label="File format"]', format);
  await extra?.();
  await fill(kw, page, sel.field("Master password"), password);
  await clickText(kw, page, "Export ", ".transfer button");
}
const names = (vs: CipherView[]) => vs.map((v) => v.name).sort();

describe(`import and export (${target})`, () => {
  before(async () => {
    await register(email, password);
    api = await apiLogin(email, password);
    await importItems(api, SEED, ["Work"]);
    kw = await launch(target);
    page = await kw.openPopup();
    page.on("pageerror", (e) => console.log("PAGEERROR", (e as Error).message));
    await login(kw, page, env.KW_SERVER, email, password);
    await waitForText(page, "Mail", 30_000);
  });
  after(async () => kw?.close());

  test("export asks for the master password", async () => {
    await openSettingsPage("Export vault");
    await catchDownloads();
    await fill(kw, page, sel.field("Master password"), "not it");
    await clickText(kw, page, "Export 3 items", ".transfer button");
    await waitForText(page, "Wrong master password");
    assert.equal(await page.evaluate(() => (window as any).__saved.length), 0);
  });

  test("every export format reads back with all the items", async () => {
    await exportAs("json");
    const plain = await lastSaved(1);
    assert.match(plain.name, /^keyward_export_\d{14}\.json$/);
    const r1 = await parseImport(plain.text);
    assert.deepEqual(names(r1.items), ["Mail", "Visa", "Wi-Fi"]);
    assert.deepEqual(r1.folders, ["Work"]);
    assert.equal(r1.items.find((v) => v.name === "Wi-Fi")?.notes, "Кириллица 🔑");

    await exportAs("password_json", async () => {
      await fill(kw, page, sel.field("File password"), "file pass");
      await fill(kw, page, sel.field("File password again"), "file pass");
    });
    const prot = await lastSaved(2);
    assert.ok(!prot.text.includes("mail-pass-1"));
    assert.deepEqual(names((await parseImport(prot.text, { password: "file pass" })).items), ["Mail", "Visa", "Wi-Fi"]);

    await exportAs("encrypted_json");
    const acct = await lastSaved(3);
    assert.ok(!acct.text.includes("mail-pass-1"));
    const r3 = await parseImport(acct.text, { userKey: api.ring.user });
    assert.equal(r3.items.find((v) => v.name === "Mail")?.login?.password, "mail-pass-1");

    await exportAs("csv");
    const csv = await lastSaved(4);
    assert.match(csv.name, /\.csv$/);
    assert.deepEqual(names((await parseImport(csv.text)).items), ["Mail", "Wi-Fi"]);
  });

  test("a browser's password CSV imports as logins", async () => {
    await click(kw, page, '.topbar button[aria-label="Back"]');
    await openSettingsPage("Import items");
    await pickFile("Chrome Passwords.csv", "name,url,username,password,note\nshop.example,https://shop.example/login,kay,shop-pass,\n,https://forum.example/,kay2,forum-pass,old account\n");
    await waitForText(page, "Chrome / Chromium / Helium CSV");
    await waitForText(page, "Import 2 items");
    await clickText(kw, page, "Import 2 items", ".transfer button");
    await waitForText(page, "Imported 2 items", 20_000);
    await page.waitForSelector(".vault-list", { timeout: 8000 });
    const s = await until(async () => {
      const v = await serverViews();
      return v.views.some((x) => x.name === "forum.example") && v;
    });
    const forum = s.views.find((x) => x.name === "forum.example")!;
    assert.deepEqual([forum.login?.username, forum.login?.password, forum.login?.uris[0]?.uri, forum.notes], ["kay2", "forum-pass", "https://forum.example/", "old account"]);
    await waitForText(page, "shop.example", 15_000);
  });

  test("a password-protected Bitwarden export: folders kept, an existing one reused", async () => {
    const views = [
      { ...loginItem("Bank", "me", "bank-pass", "https://bank.example"), id: crypto.randomUUID(), folderId: "f-work" },
      { ...emptyView(CipherType.SecureNote, { name: "Recovery codes", notes: "1111 2222" }), id: crypto.randomUUID(), folderId: "f-new" },
    ];
    const file = await exportPasswordProtected(exportJson(views, [{ id: "f-work", name: "Work" }, { id: "f-new", name: "Imported folder" }]), "open it", PBKDF2);
    await openSettingsPage("Import items");
    await pickFile("bitwarden_export.json", file);
    await waitForText(page, "protected by a password");
    await fill(kw, page, sel.field("File password"), "wrong");
    await clickText(kw, page, "Open file", ".transfer button");
    await waitForText(page, "Wrong password for this file", 20_000);
    await fill(kw, page, sel.field("File password"), "open it");
    await clickText(kw, page, "Open file", ".transfer button");
    await waitForText(page, "Import 2 items", 20_000);
    await clickText(kw, page, "Import 2 items", ".transfer button");
    await waitForText(page, "Imported 2 items", 20_000);
    const s = await until(async () => {
      const v = await serverViews();
      return v.views.some((x) => x.name === "Recovery codes") && v;
    });
    assert.deepEqual(s.folderNames, ["Imported folder", "Work"], "Work is reused, not made twice");
    assert.equal(s.folders.get(s.views.find((x) => x.name === "Bank")!.folderId!), "Work");
    assert.equal(s.folders.get(s.views.find((x) => x.name === "Recovery codes")!.folderId!), "Imported folder");
    await waitForText(page, "Recovery codes", 15_000);
  });
});
