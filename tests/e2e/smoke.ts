// P0 exit test: the extension loads in both browsers and the popup renders.
//   node tests/e2e/smoke.ts [chromium|firefox]
import { mkdirSync } from "node:fs";
import { launch, type Target } from "./launch.ts";

const targets = (process.argv[2] ? [process.argv[2]] : ["chromium", "firefox"]) as Target[];
const out = new URL("../.artifacts/", import.meta.url).pathname;
mkdirSync(out, { recursive: true });
let failed = 0;
for (const t of targets) {
  const t0 = Date.now();
  const kw = await launch(t);
  try {
    const errors: string[] = [];
    const page = await kw.openPopup();
    page.on("pageerror", (e) => errors.push(String(e)));
    page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
    await page.waitForSelector(".auth-head h1", { timeout: 10_000 });
    const title = await page.$eval(".auth-head h1", (e) => e.textContent);
    await page.waitForFunction("document.getAnimations().every((a) => a.playState !== 'running')", { timeout: 3000 }).catch(() => {});
    await kw.screenshot(page, `${out}smoke-${t}-popup.png`);
    const toolbar = await kw.openToolbarPopup();
    const ok = title === "Log in" && errors.length === 0;
    console.log(`${ok ? "PASS" : "FAIL"} ${t}: popup shows "${title}" in ${Date.now() - t0} ms; toolbar popup: ${toolbar ? "opened" : "n/a"}${errors.length ? `; errors: ${errors.join(" | ")}` : ""}`);
    if (!ok) failed++;
  } catch (e) {
    failed++;
    console.log(`FAIL ${t}: ${(e as Error).message}`);
  } finally {
    await kw.close();
  }
}
process.exit(failed ? 1 : 0);
