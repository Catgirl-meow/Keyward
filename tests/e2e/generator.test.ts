// P6: the generator. Passwords, passphrases and usernames follow their options; forwarded
// aliases come from a self-hosted SimpleLogin and addy.io, played by a server in this process.
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, test as nodeTest } from "node:test";
import type { Page } from "puppeteer-core";
import { click, clickText, fill, login, sel, settle, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { randomPassword, register, uniqueEmail } from "../lib/vw.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
let kw: Keyward;
let page: Page;
let mock: Server;
let mockUrl = "";
const email = uniqueEmail("gen");
const password = randomPassword();
const seen: { path: string; headers: Record<string, string | string[] | undefined>; body: any }[] = [];

function test(name: string, fn: () => Promise<void>) {
  nodeTest(name, async () => {
    try {
      await fn();
    } catch (e) {
      await kw.screenshot(page, `tests/.artifacts/generator-${target}-FAIL-${name.replace(/\W+/g, "-").slice(0, 40)}.png`).catch(() => {});
      console.log(`--- page text (${name}):\n${String(await page.evaluate("document.body.innerText").catch(() => "")).slice(0, 800)}`);
      throw e;
    }
  });
}

/** Self-hosted SimpleLogin and addy.io, as far as alias creation goes. */
function startMock(): Promise<void> {
  mock = createServer(async (req, res) => {
    let raw = "";
    for await (const c of req) raw += c;
    const body = raw ? JSON.parse(raw) : null;
    seen.push({ path: req.url ?? "", headers: req.headers, body });
    const send = (status: number, o: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(o));
    if (req.method === "POST" && req.url?.startsWith("/api/alias/random/new")) {
      return req.headers.authentication === "sl-test-key" ? send(201, { alias: "random.alias@sl.test" }) : send(401, { error: "Wrong api key" });
    }
    if (req.method === "POST" && req.url === "/api/v1/aliases") {
      return req.headers.authorization === "Bearer addy-test-key" ? send(201, { data: { email: `x7k2@${body?.domain}` } }) : send(401, { message: "Unauthenticated." });
    }
    send(404, {});
  });
  return new Promise((r) => mock.listen(0, "127.0.0.1", () => ((mockUrl = `http://127.0.0.1:${(mock.address() as AddressInfo).port}`), r())));
}

const value = () => page.$eval(".gen-value", (e) => e.textContent ?? "");
/** Waits for the output to change from `old` (the generator updates asynchronously). */
async function nextValue(old: string): Promise<string> {
  await page.waitForFunction((o) => (document.querySelector(".gen-value")?.textContent ?? "") !== o, { timeout: 8000 }, old);
  return value();
}
async function chip(label: string) {
  await clickText(kw, page, label, ".generator .chip");
  await settle(page);
}
async function forwarderSettings(name: string, fields: Record<string, string>) {
  await click(kw, page, `button[aria-label="${name} settings"]`);
  await page.waitForSelector(".sheet", { timeout: 8000 });
  for (const [label, v] of Object.entries(fields)) await fill(kw, page, sel.field(label), v);
  await clickText(kw, page, "Save", ".sheet button");
}

describe(`generator (${target})`, () => {
  before(async () => {
    await startMock();
    await register(email, password);
    kw = await launch(target);
    page = await kw.openPopup();
    page.on("pageerror", (e) => console.log("PAGEERROR", (e as Error).message));
    await login(kw, page, env.KW_SERVER, email, password);
    await waitForText(page, "Your vault is empty", 30_000);
    await clickText(kw, page, "Generator", "nav button");
    await page.waitForSelector(".generator .gen-value", { timeout: 8000 });
  });
  after(async () => {
    await kw?.close();
    mock?.close();
  });

  test("passwords follow the length and character options, and land in the history", async () => {
    let v = await value();
    assert.equal(v.length, 20);
    await fill(kw, page, 'input[aria-label="Length"]', "32");
    v = await nextValue(v);
    assert.equal(v.length, 32);
    await click(kw, page, 'button[role="switch"][aria-label="!@#$%^&*"]');
    v = await nextValue(v);
    assert.match(v, /^[A-Za-z0-9]{32}$/);
    await click(kw, page, '.gen-output button[aria-label="Copy"]');
    await click(kw, page, '.topbar button[aria-label="History"]');
    await waitForText(page, v);
    await page.keyboard.press("Escape").catch(() => {});
    await page.evaluate(() => (document.querySelector(".scrim") as HTMLElement | null)?.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true })));
    await page.waitForFunction(() => !document.querySelector(".sheet"), { timeout: 5000 });
  });

  test("passphrases and plus-addressed usernames", async () => {
    await chip("Passphrase");
    const p = await nextValue("");
    assert.equal(p.split("-").length, 5, p);
    assert.match(p, /\d/, "includes a number by default");
    await chip("Username");
    await chip("Plus-addressed email");
    // No email yet: an empty output, not an error.
    assert.equal(await value(), "—");
    assert.ok(!(await page.evaluate(() => document.querySelector(".toasts")?.textContent ?? "")).includes("email"));
    await fill(kw, page, sel.field("Your email"), "kay@example.test");
    await page.waitForFunction(() => /^kay\+\w+@example\.test$/.test(document.querySelector(".gen-value")?.textContent ?? ""), { timeout: 8000 });
  });

  test("forwarded aliases from a self-hosted SimpleLogin and addy.io", async () => {
    await chip("Forwarded alias");
    // The key goes to the server URL, so plain http to another machine is refused.
    await forwarderSettings("SimpleLogin", { "API key": "sl-test-key", "Server URL": "http://sl.example.org" });
    await waitForText(page, "must start with https://");
    await fill(kw, page, sel.field("Server URL"), mockUrl);
    await clickText(kw, page, "Save", ".sheet button");
    await page.waitForFunction(() => !document.querySelector(".sheet"), { timeout: 5000 });
    await waitForText(page, `API key saved · ${new URL(mockUrl).host}`);
    // A toast from earlier may still be up over this button: clicks go through toasts.
    await clickText(kw, page, "Create alias with SimpleLogin", "button");
    await page.waitForFunction(() => document.querySelector(".gen-value")?.textContent === "random.alias@sl.test", { timeout: 10_000 });
    const sl = seen.find((r) => r.path.startsWith("/api/alias/random/new"))!;
    assert.equal(sl.headers.authentication, "sl-test-key");
    assert.match(sl.body.note, /^Generated by Keyward/);

    await clickText(kw, page, "addy.io", ".generator .item");
    await forwarderSettings("addy.io", { "API key": "addy-test-key", "Alias domain": "kay.anonaddy.me", "Server URL": mockUrl + "/" });
    await page.waitForFunction(() => !document.querySelector(".sheet"), { timeout: 5000 });
    await clickText(kw, page, "Create alias with addy.io", "button");
    await page.waitForFunction(() => document.querySelector(".gen-value")?.textContent === "x7k2@kay.anonaddy.me", { timeout: 10_000 });
    assert.deepEqual(seen.find((r) => r.path === "/api/v1/aliases")?.body, { domain: "kay.anonaddy.me", description: "Generated by Keyward" });

    // The keys are stored encrypted with the user key, never as text.
    const stored = await page.evaluate(async () => Object.entries(await chrome.storage.local.get(null)).filter(([k]) => k.startsWith("forwarders:")).map(([, v]) => String(v)));
    assert.equal(stored.length, 1);
    assert.match(stored[0], /^2\./);
    assert.ok(!stored[0].includes("sl-test-key") && !stored[0].includes("addy-test-key"));
  });
});
