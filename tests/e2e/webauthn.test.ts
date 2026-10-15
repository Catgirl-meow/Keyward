// WebAuthn (FIDO2) two-step login through the server-origin tab, with Chromium's CDP virtual
// authenticator standing in for a security key. Helium only: LibreWolf has no virtual authenticator over BiDi.
import assert from "node:assert/strict";
import { after, describe, test } from "node:test";
import type { CDPSession, Page, Target as PTarget } from "puppeteer-core";
import { clickText, login, waitForText } from "./flows.ts";
import { launch, testEnv, type Keyward, type Target } from "./launch.ts";
import { enableWebauthn, login as apiLogin, randomPassword, register, uniqueEmail } from "../lib/vw.ts";

const target = (process.env.KW_TARGET ?? "chromium") as Target;
const env = testEnv();

async function virtualKey(cdp: CDPSession) {
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "usb", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  return authenticatorId;
}

/** Runs navigator.credentials.create on the server origin with Vaultwarden's options. */
async function createInPage(page: Page, options: any) {
  return page.evaluate(async (raw) => {
    const o = raw.publicKey ?? raw;
    const b = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
    const enc = (x: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(x))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const cred = (await navigator.credentials.create({
      publicKey: {
        ...o,
        challenge: b(o.challenge),
        user: { ...o.user, id: b(o.user.id) },
        excludeCredentials: (o.excludeCredentials ?? []).map((c: any) => ({ ...c, id: b(c.id) })),
      },
    })) as PublicKeyCredential;
    const r = cred.response as AuthenticatorAttestationResponse;
    return {
      id: cred.id,
      rawId: enc(cred.rawId),
      type: cred.type,
      extensions: {},
      response: { AttestationObject: enc(r.attestationObject), clientDataJson: enc(r.clientDataJSON) },
    };
  }, options);
}

describe(`webauthn 2fa (${target})`, { skip: target !== "chromium" && "virtual authenticator is CDP-only" }, () => {
  let kw: Keyward;
  after(async () => kw?.close());

  test("login with a security key in the server tab", async () => {
    kw = await launch(target);
    const email = uniqueEmail("fido");
    const pw = randomPassword();
    await register(email, pw);
    const s = await apiLogin(email, pw);

    // 1. Register a key on the account from a page on the server origin.
    const reg = await kw.browser.newPage();
    await reg.goto(env.KW_SERVER + "/404.html");
    const regCdp = await reg.createCDPSession();
    const authId = await virtualKey(regCdp);
    await enableWebauthn(s, pw, (o) => createInPage(reg, o));
    const { credentials } = await regCdp.send("WebAuthn.getCredentials", { authenticatorId: authId });
    assert.equal(credentials.length, 1);
    await reg.close();
    if (process.env.KW_DEBUG) {
      const { api } = await import("../lib/vw.ts");
      const { startLogin, submitLogin } = await import("../../src/core/auth/login.ts");
      const a = api();
      const out = await submitLogin(a, await startLogin(a, email, pw));
      console.log("LOGIN OPTIONS:", JSON.stringify(out.kind === "twoFactor" ? (out as any).providers[7] : out.kind));
    }

    // 2. Every new server tab the extension opens gets a virtual key holding that credential.
    const used: string[] = [];
    kw.browser.on("targetcreated", async (t: PTarget) => {
      if (t.type() !== "page" || !t.url().startsWith(env.KW_SERVER)) return;
      const cdp = await t.createCDPSession();
      // Headless tabs never get focus, and WebAuthn refuses unfocused documents.
      await cdp.send("Emulation.setFocusEmulationEnabled", { enabled: true });
      const id = await virtualKey(cdp);
      await cdp.send("WebAuthn.addCredential", { authenticatorId: id, credential: credentials[0] });
      used.push(t.url());
    });

    const page = await kw.openPopup();
    await login(kw, page, env.KW_SERVER, email, pw);
    await waitForText(page, "Two-step login", 20_000);
    await clickText(kw, page, "Use passkey / security key");
    try {
      await waitForText(page, "Your vault is empty", 30_000);
    } catch (e) {
      console.log("popup text:", await page.evaluate("document.body.innerText"));
      console.log("pages:", (await kw.browser.pages()).map((p) => p.url()));
      console.log("server tabs seen:", used);
      throw e;
    }
    assert.equal(used.length, 1, "server tab not opened");
    assert.match(used[0], /404\.html#keyward-webauthn$/);
    const left = (await kw.browser.pages()).filter((p) => p.url().startsWith(env.KW_SERVER));
    assert.equal(left.length, 0, "server tab left open");
  });
});
