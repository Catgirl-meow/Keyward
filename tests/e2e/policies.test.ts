// Organization policies, as an owner on the local Vaultwarden (which supports the generator,
// PIN, Send and ownership policies; owners follow only the generator and PIN ones).
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { Page } from "puppeteer-core";
import { clickText, login, settle, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { createOrg, login as apiLogin, randomPassword, register, uniqueEmail } from "../lib/vw.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();
let kw: Keyward;
let page: Page;
const email = uniqueEmail("policy");
const password = randomPassword();

describe(`organization policies (${target})`, () => {
  before(async () => {
    await register(email, password);
    const s = await apiLogin(email, password);
    const { orgId } = await createOrg(s, "Policy org");
    const set = (type: number, data: unknown = null) => s.api.put(`/organizations/${orgId}/policies/${type}`, { policy: { enabled: true, data } });
    await set(2, { minLength: 40, minNumbers: 3, useSpecial: true });
    await set(14);
    await set(6); // Send off: owners are exempt
    kw = await launch(target);
    page = await kw.openPopup();
    await login(kw, page, env.KW_SERVER, email, password);
    await page.waitForFunction(() => chrome.storage.local.get("policies").then((r: any) => Object.keys(r.policies ?? {}).length > 0), { timeout: 30_000, polling: 200 });
  });
  after(async () => kw?.close());

  test("the sync stores what applies to this account", async () => {
    const p: any = Object.values(await page.evaluate(() => chrome.storage.local.get("policies").then((r: any) => r.policies)))[0];
    assert.equal(p.generator.minLength, 40);
    assert.equal(p.generator.minDigits, 3);
    assert.equal(p.removePin, true);
    assert.equal(p.disableSend, undefined, "owners may still send");
  });

  test("the generator keeps the organization's minimums", async () => {
    await clickText(kw, page, "Generator", ".navbar button");
    await waitForText(page, "Minimums set by Policy org's policy");
    await settle(page);
    const v = await page.$eval(".gen-value", (e) => e.textContent ?? "");
    assert.ok(v.length >= 40, `generated ${v.length} characters`);
    assert.ok((v.match(/\d/g) ?? []).length >= 3, "at least 3 digits");
  });

  test("PIN unlock is off and says why", async () => {
    await clickText(kw, page, "Settings", ".navbar button");
    await clickText(kw, page, "Security");
    await waitForText(page, "PIN unlock is turned off by Policy org's policy");
    assert.equal(await page.evaluate(() => document.body.innerText.includes("Unlock with PIN")), false);
  });
});
