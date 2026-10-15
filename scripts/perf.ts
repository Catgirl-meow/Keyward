// Performance budgets (plan: "Performance budgets"). Needs a build, the dev server and the seed.
//   node scripts/perf.ts            → table, exit 1 if a budget is exceeded
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import type { Page } from "puppeteer-core";
import { fill, login } from "../tests/e2e/flows.ts";
import { launch, testEnv } from "../tests/e2e/launch.ts";

const root = new URL("..", import.meta.url).pathname;
const dist = join(root, "dist/chromium");
const KB = 1024;
const rows: { what: string; value: number; unit: string; budget: number }[] = [];
const add = (what: string, value: number, unit: string, budget: number) => rows.push({ what, value, unit, budget });
const gz = (f: string) => gzipSync(readFileSync(f)).length;

// ---------------------------------------------------------------- static budgets
function walk(d: string): string[] {
  return readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));
}
const total = walk(dist).reduce((n, f) => n + statSync(f).size, 0);
add("unpacked extension", total / KB, "KB", 2048);
add("content bootstrap (gz)", gz(join(dist, "cs/boot.js")) / KB, "KB", 3);
add("service worker bundle (gz)", gz(join(dist, "bg.js")) / KB, "KB", 120);
// Popup initial JS: popup.js plus its static-import closure, from the esbuild metafile.
const meta = JSON.parse(readFileSync(join(root, ".cache/meta-chromium.json"), "utf8")).pages;
const seen = new Set<string>();
const visit = (out: string) => {
  if (seen.has(out)) return;
  seen.add(out);
  for (const i of meta.outputs[out]?.imports ?? []) if (i.kind === "import-statement" && i.path.endsWith(".js")) visit(i.path);
};
visit("dist/chromium/ui/popup.js");
add("popup initial JS (gz)", [...seen].reduce((n, f) => n + gz(join(root, f)), 0) / KB, "KB", 60);
const bgSrc = readFileSync(join(dist, "bg.js"), "utf8");
add("setInterval calls in background", (bgSrc.match(/setInterval\(/g) ?? []).length, "", 0);

// ---------------------------------------------------------------- runtime (Helium, 2,000 items)
const env = testEnv();
const kw = await launch("chromium");
async function firstRows(page: Page): Promise<number> {
  // Time from navigation start until the first list rows are in the DOM.
  return page.evaluate(
    () =>
      new Promise<number>((res) => {
        const done = () => document.querySelector(".vault-list .list-section .item") && (res(performance.now()), true);
        if (done()) return;
        new MutationObserver((_, o) => done() && o.disconnect()).observe(document.body, { childList: true, subtree: true });
      }),
  );
}
try {
  let page = await kw.openPopup();
  await login(kw, page, env.KW_SERVER, env.KW_PERF_EMAIL, env.KW_PERF_PASSWORD);
  await page.waitForFunction(() => Number(document.querySelector(".vlist")?.getAttribute("data-count")) >= 2000, { timeout: 60_000 });
  // Keep the key across the restart below so "cold" measures loading, not typing a password.
  await page.evaluate(`chrome.storage.local.get("settings").then(({ settings }) => chrome.storage.local.set({ settings: { ...settings, lockTimeout: -2 } }))`);
  await page.close();

  const warm: number[] = [];
  for (let i = 0; i < 9; i++) {
    page = await kw.openPopup();
    warm.push(await firstRows(page));
    if (i < 8) await page.close();
  }
  warm.sort((a, b) => a - b);
  console.log("warm runs:", warm.map((x) => x.toFixed(0)).join(" "));
  console.log("warm marks:", await page.evaluate(() => performance.getEntriesByType("mark").map((m) => `${m.name.slice(3)} ${m.startTime.toFixed(0)}`).join(", ")));
  console.log("resources:", await page.evaluate(() => (performance.getEntriesByType("resource") as PerformanceResourceTiming[]).map((r) => `${r.name.split("/").pop()} ${r.startTime.toFixed(0)}-${r.responseEnd.toFixed(0)}`).join(", ")));
  add("popup → first rows, 2k items, warm (median)", warm[4], "ms", 150);
  await page.waitForFunction(() => Number(document.querySelector(".vlist")?.getAttribute("data-count")) >= 2000, { timeout: 10_000 });
  const cdp = await page.createCDPSession();
  await cdp.send("HeapProfiler.collectGarbage");
  const { usedSize } = await cdp.send("Runtime.getHeapUsage");
  add("popup JS heap, 2k items", usedSize / KB / KB, "MB", 8);
  const t0 = Date.now();
  await fill(kw, page, 'input[aria-label="Search vault"]', "zephyr");
  await page.waitForFunction(() => Number(document.querySelector(".vlist")?.getAttribute("data-count")) < 1000, { timeout: 5000, polling: "mutation" });
  add("search 2k items (type → filtered list)", Date.now() - t0, "ms", 100);

  // Cold: new browser process, worker not running, key restored from "never lock".
  const profile = kw.profile;
  await kw.close();
  const kw2 = await launch("chromium", { profile });
  const cold = await kw2.openPopup();
  add("popup → first rows, 2k items, cold start", await firstRows(cold), "ms", 300);
  await cold.evaluate(`chrome.storage.local.get("settings").then(({ settings }) => chrome.storage.local.set({ settings: { ...settings, lockTimeout: -1 } }))`);
  const alarms = await kw2.bg<{ name: string; periodInMinutes?: number }[]>("chrome.alarms.getAll()");
  add("repeating alarms faster than 5 min", alarms.filter((a) => a.periodInMinutes != null && a.periodInMinutes < 5).length, "", 0);
  await kw2.close();
} catch (e) {
  await kw.close();
  throw e;
}

// ---------------------------------------------------------------- report
let failed = 0;
console.log("\n  " + "metric".padEnd(46) + "value".padStart(10) + "budget".padStart(10));
for (const r of rows) {
  const ok = r.value <= r.budget;
  if (!ok) failed++;
  const v = r.unit === "" ? String(r.value) : `${r.value.toFixed(r.value < 10 ? 2 : 1)} ${r.unit}`;
  console.log(`${ok ? "✔" : "✖"} ${r.what.padEnd(46)}${v.padStart(10)}${`≤ ${r.budget}${r.unit ? " " + r.unit : ""}`.padStart(12)}`);
}
process.exit(failed ? 1 : 0);
