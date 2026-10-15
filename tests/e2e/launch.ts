// Launch Helium (Chromium 154) or LibreWolf with the built extension in a throwaway profile.
//   const kw = await launch("chromium" | "firefox", { headless })
//   const page = await kw.openPopup()
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import puppeteer, { type Browser, type Page } from "puppeteer-core";

export type Target = "chromium" | "firefox";
const root = new URL("../..", import.meta.url).pathname;
export const CHROMIUM_ID = readFileSync(join(root, "manifest/chromium-id.txt"), "utf8").trim();
export const FIREFOX_ID = "keyward@catg1rl.com";
export const FIREFOX_UUID = "6b8f0a3e-2a51-4c4b-9a7e-6b4e2b6f1d10";

export interface Keyward {
  target: Target;
  browser: Browser;
  base: string; // chrome-extension://<id>/ or moz-extension://<uuid>/
  profile: string;
  /** Opens popup.html in a 400×600 tab (the real popup can't be scripted reliably headless). */
  openPopup(): Promise<Page>;
  /** Tries the real toolbar popup via action.openPopup(); returns its page or null. */
  openToolbarPopup(): Promise<Page | null>;
  openVault(): Promise<Page>;
  /** Evaluate in the background context (service worker / event page). */
  bg<T>(fn: string): Promise<T>;
  goto(page: Page, url: string): Promise<void>;
  /** page.screenshot, or (Firefox, privileged pages) tabs.captureVisibleTab from the page itself. */
  screenshot(page: Page, path: string): Promise<void>;
  close(): Promise<void>;
}

export async function launch(target: Target, opts: { headless?: boolean; slowMo?: number; profile?: string } = {}): Promise<Keyward> {
  const headless = opts.headless ?? process.env.KW_HEADFUL !== "1";
  // Reusing a profile simulates a browser restart (storage.local survives, storage.session doesn't).
  const profile = opts.profile ?? mkdtempSync(join(tmpdir(), `kw-${target}-`));
  const ext = join(root, "dist", target);
  let browser: Browser;
  let base: string;

  if (target === "chromium") {
    browser = await puppeteer.launch({
      executablePath: "/opt/helium/helium",
      userDataDir: profile,
      headless,
      pipe: true,
      enableExtensions: true,
      slowMo: opts.slowMo,
      defaultViewport: null,
      env: { ...process.env, LD_LIBRARY_PATH: "/opt/helium" },
      // Only Keyward: Helium's bundled uBlock Origin reloads the first page of a fresh profile
      // a few seconds in, which lands in the middle of whatever a test is doing.
      args: ["--no-first-run", "--no-default-browser-check", "--window-size=1280,860", `--disable-extensions-except=${ext}`],
    });
    // Loading at launch (enableExtensions: [path]) races Helium's startup and kills the pipe;
    // CDP Extensions.loadUnpacked right after launch is reliable.
    const id = await browser.installExtension(ext);
    if (id !== CHROMIUM_ID) throw new Error(`unexpected extension id ${id}`);
    base = `chrome-extension://${CHROMIUM_ID}/`;
  } else {
    browser = await puppeteer.launch({
      browser: "firefox",
      executablePath: "/opt/librewolf/librewolf",
      dumpio: !!process.env.KW_CONSOLE,
      userDataDir: profile,
      headless,
      slowMo: opts.slowMo,
      defaultViewport: null,
      // Lets WebDriver BiDi script moz-extension:// pages.
      args: ["-remote-allow-system-access"],
      extraPrefsFirefox: {
        "extensions.webextensions.uuids": JSON.stringify({ [FIREFOX_ID]: FIREFOX_UUID }),
        "privacy.resistFingerprinting": false,
        "dom.security.https_only_mode": false,
        "dom.security.https_only_mode.upgrade_local": false,
        "privacy.sanitize.sanitizeOnShutdown": false,
        "webgl.disabled": false,
        "browser.shell.checkDefaultBrowser": false,
        "extensions.autoDisableScopes": 0,
        // BiDi installs are temporary: keep their data and UUID across the simulated restart.
        "extensions.webextensions.keepStorageOnUninstall": true,
        "extensions.webextensions.keepUuidOnUninstall": true,
        "ui.systemUsesDarkTheme": 1,
        // KW_CONSOLE=1: every console message (pages, extension frames, background) to stdout.
        ...(process.env.KW_CONSOLE ? { "devtools.console.stdout.content": true, "devtools.console.stdout.chrome": true, "browser.dom.window.dump.enabled": true } : {}),
        // Autofill fixtures live on *.localhost names (tests/fixtures/server.ts).
        "network.dns.localDomains": "login.localhost,mailfence.localhost,other.localhost,shop.localhost",
      },
    });
    await browser.installExtension(ext);
    base = `moz-extension://${FIREFOX_UUID}/`;
  }

  /** Firefox BiDi never reports load events for moz-extension pages: navigate, then poll. */
  async function goto(page: Page, url: string) {
    if (target === "chromium") return void (await page.goto(url));
    void page.goto(url, { timeout: 60_000 }).catch(() => {});
    const end = Date.now() + 15_000;
    while (Date.now() < end) {
      const href = await page.evaluate("location.href + '|' + document.readyState").catch(() => "");
      if (href === `${url}|complete`) return;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error(`timed out loading ${url}`);
  }

  const kw: Keyward = {
    target,
    browser,
    base,
    profile,
    async openPopup() {
      const page = await browser.newPage();
      await page.setViewport({ width: 400, height: 600 });
      await goto(page, base + "popup.html");
      return page;
    },
    async openToolbarPopup() {
      if (target !== "chromium") return null;
      const sw = await browser.waitForTarget((t) => t.type() === "service_worker" && t.url().startsWith(base), { timeout: 10_000 });
      const worker = await sw.worker();
      const popupTarget = browser.waitForTarget((t) => t.url() === base + "popup.html", { timeout: 5_000 }).catch(() => null);
      await worker!.evaluate("chrome.action.openPopup()").catch(() => {});
      const t = await popupTarget;
      return t ? ((await t.asPage()) as Page) : null;
    },
    async openVault() {
      const page = await browser.newPage();
      await goto(page, base + "vault.html");
      return page;
    },
    async bg<T>(fn: string): Promise<T> {
      if (target === "chromium") {
        const sw = await browser.waitForTarget((t) => t.type() === "service_worker" && t.url().startsWith(base), { timeout: 10_000 });
        return (await (await sw.worker())!.evaluate(fn)) as T;
      }
      // Firefox: evaluate through an extension page (same privileges; the event page has no BiDi realm by URL).
      const page = await browser.newPage();
      await goto(page, base + "popup.html");
      try {
        return (await page.evaluate(fn)) as T;
      } finally {
        await page.close();
      }
    },
    goto,
    async screenshot(page, path) {
      if (target === "chromium") return void (await page.screenshot({ path }));
      const dataUrl = await page.evaluate(`(async () => {
        const t = await browser.tabs.getCurrent();
        await browser.tabs.update(t.id, { active: true });
        await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
        return browser.tabs.captureVisibleTab(t.windowId, { format: "png" });
      })()`);
      writeFileSync(path, Buffer.from(String(dataUrl).split(",")[1], "base64"));
    },
    async close() {
      await browser.close().catch(() => {});
    },
  };
  return kw;
}

/** Reads tests/.env.test (written by scripts/seed.ts). */
export function testEnv(): Record<string, string> {
  const txt = readFileSync(join(root, "tests/.env.test"), "utf8");
  return Object.fromEntries(txt.split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
}
