// P6: Watchtower on a vault seeded with one problem of each kind. HIBP and 2fa.directory are
// answered by request interception, so the test never contacts them.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test as nodeTest } from "node:test";
import type { HTTPRequest, Page } from "puppeteer-core";
import { click, clickText, login, settle, waitForItems, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { importItems, login as apiLogin, randomPassword, register, uniqueEmail, type Session } from "../lib/vw.ts";
import { decryptCipher, emptyView, encryptCipher } from "../../src/core/vault/cipher.ts";
import { CipherType, type CipherView } from "../../src/core/vault/types.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
let kw: Keyward;
let page: Page;
let api: Session;
let networkChecked = false;
const email = uniqueEmail("watch");
const password = randomPassword();

function test(name: string, fn: () => Promise<void>) {
  nodeTest(name, async () => {
    try {
      await fn();
    } catch (e) {
      await kw.screenshot(page, `tests/.artifacts/watchtower-${target}-FAIL-${name.replace(/\W+/g, "-").slice(0, 40)}.png`).catch(() => {});
      console.log(`--- page text (${name}):\n${String(await page.evaluate("document.body.innerText").catch(() => "")).slice(0, 800)}`);
      throw e;
    }
  });
}

function loginItem(name: string, pw: string | null, uris: string[], more: Partial<CipherView["login"] & object> = {}): CipherView {
  return emptyView(CipherType.Login, {
    name,
    login: { username: "kay", password: pw, passwordRevisionDate: null, totp: null, uris: uris.map((uri) => ({ uri, match: null })), autofillOnPageLoad: null, fido2Credentials: [], ...more },
  });
}

/** A real 1024-bit RSA key, the kind Watchtower should flag. */
function oldRsaKey(): { privateKey: string; publicKey: string; keyFingerprint: string } {
  const dir = mkdtempSync(join(tmpdir(), "kw-ssh-"));
  const f = join(dir, "id_rsa");
  execFileSync("ssh-keygen", ["-q", "-t", "rsa", "-b", "1024", "-N", "", "-C", "old", "-f", f]);
  const keyFingerprint = execFileSync("ssh-keygen", ["-l", "-E", "sha256", "-f", f + ".pub"], { encoding: "utf8" }).split(" ")[1];
  return { privateKey: readFileSync(f, "utf8"), publicKey: readFileSync(f + ".pub", "utf8").trim(), keyFingerprint };
}

const shared = "Shared-Pa55-Phrase!";
const dup = "Dup-Pa55-Word-9!";
const key = oldRsaKey();
const SEED: CipherView[] = [
  loginItem("Weak", "password1", ["https://weak.example"]),
  loginItem("Reused A", shared, ["https://a.example"]),
  loginItem("Reused B", shared, ["https://b.example"]),
  loginItem("Plain http", randomPassword(), ["http://plain.example/login"]),
  loginItem("Router", randomPassword(), ["http://192.168.2.1/"]),
  loginItem("Dup", dup, ["https://dup.example"]),
  loginItem("Dup", dup, ["https://dup.example"]),
  loginItem("No password", null, ["https://nopw.example"]),
  loginItem("Github", randomPassword(), ["https://github.com/login"]),
  loginItem("GitLab", randomPassword(), ["https://gitlab.com"], { totp: "JBSWY3DPEHPK3PXP" }),
  loginItem("Fine", randomPassword(), ["https://fine.example"]),
  loginItem("Trashed", randomPassword(), ["https://trashed.example"]),
  emptyView(CipherType.SecureNote, { name: "Empty note" }),
  emptyView(CipherType.Card, { name: "Old card", card: { cardholderName: "Kay", brand: "Visa", number: "4111111111111111", expMonth: "1", expYear: "2020", code: "123" } }),
  emptyView(CipherType.SshKey, { name: "Old key", sshKey: key }),
  loginItem("Two sites", randomPassword(), ["https://shop.example", "https://www.shop.example/login"]),
  // Strong, distinct passwords for zxcvbn to chew on: scoring them used to freeze the page.
  ...Array.from({ length: 120 }, (_, i) => loginItem(`Filler ${i}`, randomPassword(), [`https://filler-${i}.example`])),
];

// ---------------------------------------------------------------- stand-ins for the two services
const sha1 = (s: string) => createHash("sha1").update(s).digest("hex").toUpperCase();
const pwned = sha1("password1");
const TWOFA = JSON.stringify([
  ["GitHub", { domain: "github.com", tfa: ["totp"] }],
  ["GitLab", { domain: "gitlab.com", tfa: ["totp"] }],
]);
/** The stand-in answer for a URL, or null. Self-contained: it also runs inside the page. */
function standIn(url: string, pwned: string, twofa: string): { type: string; body: string } | null {
  const range = url.match(/^https:\/\/api\.pwnedpasswords\.com\/range\/([0-9A-F]{5})$/i);
  if (range) return { type: "text/plain", body: [`${"0".repeat(35)}:0`, ...(range[1].toUpperCase() === pwned.slice(0, 5) ? [`${pwned.slice(5)}:2413945`] : [])].join("\r\n") };
  if (url.startsWith("https://api.2fa.directory/")) return { type: "application/json", body: twofa };
  return null;
}
/** URLs answered by a stand-in, in order. */
const sent: string[] = [];
function answer(req: HTTPRequest) {
  const url = req.url();
  const a = standIn(url, pwned, TWOFA);
  if (a) {
    sent.push(url);
    return void req.respond({ status: 200, contentType: a.type, headers: { "access-control-allow-origin": "*" }, body: a.body });
  }
  if (/^https?:\/\/(?!localhost|127\.0\.0\.1)/.test(url) && !url.startsWith(env.KW_SERVER)) return void req.abort("blockedbyclient");
  void req.continue();
}
/** Where requests can't be intercepted (BiDi and extension pages): the page's fetch answers. */
async function stubFetch() {
  await page.evaluate(`(() => {
    const standIn = ${standIn};
    const real = window.fetch.bind(window);
    window.__sent = [];
    window.fetch = (input, init) => {
      const url = typeof input === "string" ? input : input instanceof Request ? input.url : String(input);
      const a = standIn(url, ${JSON.stringify(pwned)}, ${JSON.stringify(TWOFA)});
      if (!a) return real(input, init);
      window.__sent.push(url);
      return Promise.resolve(new Response(a.body, { status: 200, headers: { "content-type": a.type } }));
    };
  })()`);
}

/** The cards' counts: check id → number shown ("" for a network check not run yet). */
const counts = () => page.$$eval(".wt-card", (cs) => Object.fromEntries(cs.map((c) => [(c as HTMLElement).dataset.check!, (c as HTMLElement).dataset.count!])));
async function waitForCount(check: string, n: string, timeout = 15_000) {
  await page.waitForFunction((c, v) => (document.querySelector(`.wt-card[data-check="${c}"]`) as HTMLElement | null)?.dataset.count === v, { timeout }, check, n);
}
async function openCard(check: string) {
  await click(kw, page, `.wt-card[data-check="${check}"]`);
  await page.waitForSelector(".watch-list .item", { timeout: 8000 });
  await settle(page);
}
const listed = () => page.$$eval(".watch-list .item", (rows) => rows.map((r) => [r.querySelector(".title")?.textContent ?? "", r.querySelector(".sub")?.textContent ?? ""]));
async function back() {
  await click(kw, page, '.topbar button[aria-label="Back"]');
  await settle(page);
}

describe(`watchtower (${target})`, () => {
  before(async () => {
    await register(email, password);
    api = await apiLogin(email, password);
    await importItems(api, SEED);
    const data = await api.api.get("/sync?excludeDomains=true");
    for (const raw of data.ciphers) if ((await decryptCipher(raw, api.ring)).name === "Trashed") await api.api.put(`/ciphers/${raw.id}/delete`);
    kw = await launch(target);
    page = await kw.openPopup();
    page.on("pageerror", (e) => console.log("PAGEERROR", (e as Error).message));
    page.on("console", (m) => m.type() === "error" && console.log("CONSOLE", m.text()));
    await login(kw, page, env.KW_SERVER, email, password);
    await waitForItems(page, 5, 30_000);
  });
  after(async () => kw?.close());

  test("each check finds its seeded item, and the page never stalls while they run", async () => {
    // The longest gap between ticks of a 20 ms timer: how long the page was unresponsive.
    await page.evaluate(() => {
      const w = window as any;
      let last = performance.now();
      w.__gap = 0;
      w.__beat = setInterval(() => {
        const now = performance.now();
        w.__gap = Math.max(w.__gap, now - last);
        last = now;
      }, 20);
    });
    await clickText(kw, page, "Watchtower", "nav button");
    await page.waitForSelector(".wt-grid .wt-card", { timeout: 15_000 });
    await waitForCount("weak", "1", 30_000);
    const gap = await page.evaluate(() => (clearInterval((window as any).__beat), (window as any).__gap as number));
    assert.ok(gap < 250, `the page stalled for ${Math.round(gap)} ms`);
    assert.deepEqual(await counts(), {
      exposed: "",
      reused: "4", // the two "Reused" items and the two copies of "Dup"
      weak: "1",
      insecure: "1", // the router's local address is left alone
      inactive2fa: "",
      weakKeys: "1",
      expiring: "1",
      duplicates: "2",
      duplicateUris: "1",
      incomplete: "1",
      empty: "1",
      trash: "1",
    });
    await waitForText(page, "8 items need attention");
  });

  test("a card lists its items and opens them", async () => {
    await openCard("weak");
    assert.deepEqual(await listed(), [["Weak", "Very weak"]]);
    await clickText(kw, page, "Weak", ".watch-list .item");
    await page.waitForSelector(".item-view .topbar", { timeout: 8000 });
    await waitForText(page, "weak.example");
    await back();
    await back();
    await openCard("weakKeys");
    assert.deepEqual(await listed(), [["Old key", "RSA 1024-bit (use at least 2048)"]]);
    await back();
    await openCard("reused");
    assert.deepEqual((await listed()).map(([n, d]) => `${n}: ${d}`).sort(), ["Dup: Used in 2 items", "Dup: Used in 2 items", "Reused A: Used in 2 items", "Reused B: Used in 2 items"]);
    await back();
    await openCard("duplicateUris");
    assert.deepEqual(await listed(), [["Two sites", "shop.example and www.shop.example/login fill on the same pages"]]);
    await back();
    await page.waitForSelector(".wt-grid", { timeout: 8000 });
  });

  test("the network checks run only when asked, and send no passwords", async () => {
    // Real request interception in Helium; WebDriver BiDi can't intercept an extension page's
    // requests, so in LibreWolf the page's fetch is replaced instead.
    const intercepted = await page.setRequestInterception(true).then(() => true, () => false);
    if (intercepted) page.on("request", answer);
    else await stubFetch();
    try {
      await click(kw, page, '.wt-card[data-check="exposed"]');
      await waitForCount("exposed", "1");
      await click(kw, page, '.wt-card[data-check="inactive2fa"]');
      await waitForCount("inactive2fa", "1");
      networkChecked = true;
    } finally {
      if (intercepted) {
        page.off("request", answer);
        await page.setRequestInterception(false);
      }
    }
    const urls = intercepted ? sent : await page.evaluate<[], () => string[]>(() => (window as any).__sent);
    // k-anonymity: one 5-digit hash prefix per distinct password, nothing else about it.
    const passwords = [...new Set(SEED.filter((v) => v.name !== "Trashed" && v.login?.password).map((v) => v.login!.password!))];
    const ranges = urls.filter((u) => u.includes("pwnedpasswords"));
    assert.deepEqual(ranges.map((u) => u.slice(-5)).sort(), passwords.map((p) => sha1(p).slice(0, 5)).sort());
    assert.ok(ranges.every((u) => /^https:\/\/api\.pwnedpasswords\.com\/range\/[0-9A-F]{5}$/.test(u)));
    assert.equal(urls.filter((u) => u.includes("2fa.directory")).length, 1);
    assert.equal(urls.length, ranges.length + 1);
    await waitForText(page, "9 items need attention");
    await openCard("exposed");
    assert.deepEqual(await listed(), [["Weak", "Seen 2,413,945 times in data breaches"]]);
    await back();
    await openCard("inactive2fa");
    assert.deepEqual(await listed(), [["Github", "github.com offers two-step login"]]);
    await back();
  });

  test("a fix made elsewhere shows up after a sync", async () => {
    const data = await api.api.get("/sync?excludeDomains=true");
    for (const raw of data.ciphers) {
      const v = await decryptCipher(raw, api.ring);
      if (v.name !== "Plain http") continue;
      const fixed = { ...v, login: { ...v.login!, uris: [{ uri: "https://plain.example/login", match: null }] } };
      await api.api.put(`/ciphers/${raw.id}`, (await encryptCipher(fixed, api.ring, { base: raw, encryptedFor: api.login.userId })).body);
    }
    await clickText(kw, page, "Vault", "nav button");
    await click(kw, page, 'button[aria-label="Account and vault menu"]');
    await clickText(kw, page, "Sync now", '[role="menuitem"]');
    await new Promise((r) => setTimeout(r, 1500));
    await clickText(kw, page, "Watchtower", "nav button");
    await waitForCount("insecure", "0");
    const c = await counts();
    // The network checks keep what they found.
    if (networkChecked) assert.deepEqual([c.exposed, c.inactive2fa], ["1", "1"]);
    await waitForText(page, `${networkChecked ? 8 : 7} items need attention`);
  });
});
