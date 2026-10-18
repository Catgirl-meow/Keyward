// P6: Send. Sends made in the UI are opened the way a recipient would (the access API and the
// key in the link); Sends made elsewhere show up in the UI.
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { after, before, describe, test as nodeTest } from "node:test";
import type { Page } from "puppeteer-core";
import { click, clickText, fill, login, sel, settle, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { login as apiLogin, randomPassword, register, sync, uniqueEmail, type Session } from "../lib/vw.ts";
import { decryptBuffer } from "../../src/core/crypto/encstring.ts";
import { decryptSend, decryptSendAccess, encryptSend, inDays, parseSendLink, sendPasswordHash, SendType, type RawSend } from "../../src/core/send/send.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
let kw: Keyward;
let page: Page;
let api: Session;
const email = uniqueEmail("send");
const password = randomPassword();

function test(name: string, fn: () => Promise<void>) {
  nodeTest(name, async () => {
    try {
      await fn();
    } catch (e) {
      await kw.screenshot(page, `tests/.artifacts/send-${target}-FAIL-${name.replace(/\W+/g, "-").slice(0, 40)}.png`).catch(() => {});
      console.log(`--- page text (${name}):\n${String(await page.evaluate("document.body.innerText").catch(() => "")).slice(0, 800)}`);
      throw e;
    }
  });
}

const serverSends = async () => {
  const raws = (await sync(api)).sends as RawSend[];
  return Promise.all(raws.map(async (r) => ({ raw: r, view: await decryptSend(r, api.ring.user) })));
};
const byName = async (name: string) => (await serverSends()).find((s) => s.view.name === name);
const until = async <T>(fn: () => Promise<T | undefined | false>, ms = 10_000): Promise<T> => {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v as T;
    if (Date.now() > end) throw new Error("condition not met on the server");
    await new Promise((r) => setTimeout(r, 200));
  }
};

/**
 * Opens a Send the way a recipient does: only the link and, if set, the password. The current
 * flow (the only one since Vaultwarden 1.37.4): a send-access token from the identity endpoint,
 * then the Send with that token.
 */
async function receive(link: string, pw?: string) {
  const p = parseSendLink(link);
  assert.ok(p, `not a Send link: ${link}`);
  const server = env.KW_SERVER.replace(/\/$/, "");
  const form = new URLSearchParams({ grant_type: "send_access", client_id: "send", scope: "api.send.access", send_id: p.accessId });
  if (pw) form.set("password_hash_b64", await sendPasswordHash(pw, p.material));
  const t = await fetch(`${server}/identity/connect/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form });
  if (!t.ok) throw new Error(`send access token: ${t.status} ${(await t.text()).slice(0, 200)}`);
  const headers = { Authorization: `Bearer ${(await t.json()).access_token}`, "Content-Type": "application/json" };
  const call = async (path: string) => {
    const r = await fetch(`${server}/api${path}`, { method: "POST", headers, body: "{}" });
    if (!r.ok) throw new Error(`${path}: ${r.status} ${(await r.text()).slice(0, 200)}`);
    return r.json();
  };
  const raw = await call("/sends/access");
  const seen = await decryptSendAccess(raw, p.material);
  let bytes: Uint8Array | null = null;
  if (seen.file) {
    const dl = await call(`/sends/access/file/${seen.file.id}`);
    const res = await fetch(new URL(dl.url, server + "/"));
    bytes = await decryptBuffer(new Uint8Array(await res.arrayBuffer()), seen.key);
  }
  return { ...seen, bytes };
}

async function openSend(name: string) {
  await clickText(kw, page, name, ".send-list .item");
  await page.waitForSelector(".send-edit .send-link", { timeout: 8000 });
  await settle(page);
}
const shownLink = () => page.$eval(".send-link .mono", (e) => e.textContent ?? "");
async function save() {
  await clickText(kw, page, "Save", ".topbar button");
  await page.waitForSelector(".send-list", { timeout: 10_000 });
  await settle(page);
}

describe(`send (${target})`, () => {
  before(async () => {
    await register(email, password);
    api = await apiLogin(email, password);
    kw = await launch(target);
    page = await kw.openPopup();
    page.on("pageerror", (e) => console.log("PAGEERROR", (e as Error).message));
    await login(kw, page, env.KW_SERVER, email, password);
    await waitForText(page, "Your vault is empty", 30_000);
    await clickText(kw, page, "Send", "nav button");
    await waitForText(page, "Only people with the link can open it");
  });
  after(async () => kw?.close());

  test("a text Send with a password and a view limit opens for a recipient", async () => {
    await click(kw, page, "button.fab");
    await clickText(kw, page, "Text", '[role="menuitem"]');
    await fill(kw, page, sel.field("Name"), "Wi-Fi for guests");
    await fill(kw, page, 'textarea[aria-label="Text"]', "network: kw-guest\npass: Кириллица 🔑");
    await fill(kw, page, sel.field("Maximum views"), "2");
    await fill(kw, page, sel.field("Password"), "open sesame");
    await save();
    await waitForText(page, "Wi-Fi for guests");
    const s = await until(() => byName("Wi-Fi for guests"));
    assert.deepEqual([s.view.text, s.view.maxAccessCount, s.view.hasPassword], [{ text: "network: kw-guest\npass: Кириллица 🔑", hidden: false }, 2, true]);
    // The deletion default is 7 days.
    assert.ok(Math.abs(Date.parse(s.view.deletionDate) - Date.parse(inDays(7))) < 120_000);

    await openSend("Wi-Fi for guests");
    const link = await shownLink();
    assert.ok(link.startsWith(env.KW_SERVER.replace(/\/$/, "") + "/#/send/"), link);
    await assert.rejects(receive(link), "no password, no Send");
    const got = await receive(link, "open sesame");
    assert.equal(got.text?.text, "network: kw-guest\npass: Кириллица 🔑");
    assert.equal(got.name, "Wi-Fi for guests");
  });

  test("editing keeps the link; the password can be removed", async () => {
    const link = await shownLink();
    await fill(kw, page, sel.field("Name"), "Wi-Fi (renamed)");
    await save();
    await until(() => byName("Wi-Fi (renamed)"));
    await openSend("Wi-Fi (renamed)");
    assert.equal(await shownLink(), link);
    assert.equal((await byName("Wi-Fi (renamed)"))!.view.hasPassword, true, "an empty password field keeps the password");
    await clickText(kw, page, "Remove password", "button");
    await clickText(kw, page, "Remove", ".dialog button");
    await waitForText(page, "Password removed");
    await until(async () => (await byName("Wi-Fi (renamed)"))?.view.hasPassword === false);
    assert.equal((await receive(link)).text?.text.split("\n")[0], "network: kw-guest");
    await click(kw, page, '.topbar button[aria-label="Back"]');
    await page.waitForSelector(".send-list", { timeout: 8000 });
  });

  test("a file Send uploads encrypted and opens for a recipient", async () => {
    const file = "tests/.artifacts/send-file.txt";
    const body = "Keyward file Send ✓ " + Date.now() + "\n" + "x".repeat(50_000);
    writeFileSync(file, body);
    await click(kw, page, "button.fab");
    await clickText(kw, page, "File", '[role="menuitem"]');
    const input = await page.waitForSelector('input[type="file"]');
    if (target === "chromium") await input!.uploadFile(file);
    else {
      // BiDi can't set files on an extension page's input; the page's own DataTransfer can.
      await input!.evaluate((el, text) => {
        const dt = new DataTransfer();
        dt.items.add(new File([text], "send-file.txt", { type: "text/plain" }));
        (el as HTMLInputElement).files = dt.files;
        el.dispatchEvent(new Event("change", { bubbles: true }));
      }, body);
    }
    await waitForText(page, "send-file.txt");
    await save();
    const s = await until(() => byName("send-file.txt"), 20_000);
    assert.equal(s.view.type, SendType.File);
    assert.equal(s.view.file?.fileName, "send-file.txt");
    await openSend("send-file.txt");
    const got = await receive(await shownLink());
    assert.equal(new TextDecoder().decode(got.bytes!), body);
    await click(kw, page, '.topbar button[aria-label="Back"]');
    await page.waitForSelector(".send-list", { timeout: 8000 });
  });

  test("a Send made elsewhere shows up after a sync, and can be deleted", async () => {
    const { body } = await encryptSend(
      { type: SendType.Text, name: "Made elsewhere", notes: null, text: { text: "hidden text", hidden: true }, maxAccessCount: null, expirationDate: inDays(1), deletionDate: inDays(3), disabled: false, hideEmail: false },
      api.ring.user,
    );
    const made = (await api.api.post("/sends", body)) as RawSend;
    await clickText(kw, page, "Vault", "nav button");
    await click(kw, page, 'button[aria-label="Account and vault menu"]');
    await clickText(kw, page, "Sync now", '[role="menuitem"]');
    await clickText(kw, page, "Send", "nav button");
    await waitForText(page, "Made elsewhere");
    const row = await page.waitForFunction(() => [...document.querySelectorAll(".send-list .item")].find((r) => r.textContent?.includes("Made elsewhere"))?.textContent ?? null);
    const text = String(await row.jsonValue());
    assert.match(text, /Hidden text/);
    assert.match(text, /Expires in 2\d hours/);

    await openSend("Made elsewhere");
    await click(kw, page, '.send-edit .topbar button[aria-label="More"]');
    await clickText(kw, page, "Delete", '[role="menuitem"]');
    await clickText(kw, page, "Delete", ".dialog button");
    await waitForText(page, "Send deleted");
    await until(async () => !(await serverSends()).some((s) => s.raw.id === made.id));
    await page.waitForSelector(".send-list", { timeout: 8000 });
    await page.waitForFunction(() => ![...document.querySelectorAll(".send-list .item")].some((r) => r.textContent?.includes("Made elsewhere")), { timeout: 8000 });
  });
});
