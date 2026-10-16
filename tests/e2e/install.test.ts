// P7: the release .xpi installed the way a user installs it, under LibreWolf's privacy defaults.
// LibreWolf is built without Firefox's signing requirement, so with xpinstall.signatures.required
// off the unsigned package loads as a permanent add-on (not a temporary one, as the other tests'
// installs are). LibreWolf clears cookies and site data at shutdown by default; that must not
// log Keyward out or drop its offline vault.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, describe, test } from "node:test";
import type { Page } from "puppeteer-core";
import { FX, startFixtures } from "../fixtures/server.ts";
import { login, waitForText } from "./flows.ts";
import { FIREFOX_ID, launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { importItems, login as apiLogin, randomPassword, register, uniqueEmail } from "../lib/vw.ts";
import { emptyView } from "../../src/core/vault/cipher.ts";
import { CipherType } from "../../src/core/vault/types.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
const root = new URL("../..", import.meta.url).pathname;
const email = uniqueEmail("install");
const password = randomPassword();
// LibreWolf's own defaults (librewolf.cfg) put back over the test profile's.
// (HTTPS-only mode stays off: the test server is plain http on 127.0.0.1.)
const prefs = {
  "xpinstall.signatures.required": false,
  "privacy.sanitize.sanitizeOnShutdown": true,
  "privacy.clearOnShutdown_v2.cookiesAndStorage": true,
  "privacy.resistFingerprinting": true,
};

describe(`installed package (${target})`, { skip: target !== "firefox" && "LibreWolf only: Helium loads the unpacked folder the tests already use" }, () => {
  let kw: Keyward;
  let page: Page;
  let fixtures: Server;
  const profile = mkdtempSync(join(tmpdir(), "kw-install-"));
  const start = async () => {
    kw = await launch("firefox", { profile, sideloaded: true, prefs });
    page = await kw.openPopup();
  };

  before(async () => {
    await register(email, password);
    await importItems(await apiLogin(email, password), [emptyView(CipherType.SecureNote, { name: "Survives restarts", notes: "x" })]);
    fixtures = await startFixtures();
    // What "Install Add-on From File" leaves behind: the package in the profile, named by its id.
    const dist = join(process.env.KW_DIST ? resolve(process.env.KW_DIST) : join(root, "dist"), "firefox");
    mkdirSync(join(profile, "extensions"));
    execFileSync("zip", ["-q", "-r", "-X", join(profile, "extensions", `${FIREFOX_ID}.xpi`), "."], { cwd: dist });
    await start();
  });
  after(async () => {
    await kw?.close();
    fixtures?.close();
  });

  test("the unsigned package installs as a permanent add-on", async () => {
    const self = await page.evaluate(() => (globalThis as any).browser.management.getSelf());
    // "sideload": put in the profile by hand ("Install Add-on From File" says "normal"); either
    // way permanent, unlike the other tests' temporary "development" installs.
    assert.equal(self.installType, "sideload");
    assert.equal(self.id, FIREFOX_ID);
    await login(kw, page, env.KW_SERVER, email, password);
    await waitForText(page, "Survives restarts", 30_000);
  });

  test("LibreWolf's clear-on-shutdown leaves the account and offline vault", async () => {
    // A site's storage, to see that the shutdown cleanup really ran.
    const site = await kw.browser.newPage();
    await site.goto(FX.url("login"));
    await site.evaluate(() => localStorage.setItem("kw-probe", "1"));
    await kw.close();
    await start();
    await waitForText(page, "Vault is locked", 20_000);
    assert.ok((await page.evaluate(() => document.body.innerText)).includes(email));
    const after = await kw.browser.newPage();
    await after.goto(FX.url("login"));
    assert.equal(await after.evaluate(() => localStorage.getItem("kw-probe")), null, "the site's storage was cleared, so the cleanup ran");
    await after.close();
    await page.bringToFront().catch(() => {});
    await page.$eval('input[aria-label="Master password"]', (el, v) => {
      const i = el as HTMLInputElement;
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(i, v);
      i.dispatchEvent(new Event("input", { bubbles: true }));
    }, password);
    await page.$$eval("button", (bs) => bs.find((b) => b.textContent?.trim() === "Unlock")?.click());
    await waitForText(page, "Survives restarts", 20_000);
  });
});
