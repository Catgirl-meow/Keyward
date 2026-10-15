// WebAuthn (FIDO2 / passkey) two-step login. Vaultwarden only accepts assertions whose origin is
// its own DOMAIN, so the assertion runs in a short-lived tab on the server's origin (a static
// page of the web vault) and the background finishes the login — the popup has closed by then.
import { serverUrls } from "../core/api/client.ts";
import { TwoFactorProvider } from "../core/auth/login.ts";
import { finishLogin, loadPending, submitTwoFactor } from "../platform/login.ts";

function waitComplete(tabId: number, timeoutMs = 20000): Promise<void> {
  return new Promise((res, rej) => {
    const t = setTimeout(() => {
      chrome.tabs.onUpdated.removeListener(on);
      rej(new Error("Timed out opening the server page"));
    }, timeoutMs);
    const on = (id: number, ch: chrome.tabs.OnUpdatedInfo) => {
      if (id === tabId && ch.status === "complete") {
        clearTimeout(t);
        chrome.tabs.onUpdated.removeListener(on);
        res();
      }
    };
    chrome.tabs.onUpdated.addListener(on);
    // The page may have finished loading before the listener was attached.
    chrome.tabs.get(tabId).then((t) => t.status === "complete" && on(tabId, { status: "complete" }), () => {});
  });
}

/** Injected into the server page (MAIN world). Must be self-contained. */
async function assertInPage(raw: any): Promise<any> {
  const o = raw?.publicKey ?? raw;
  const b64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
  const enc = (b: ArrayBuffer) => {
    let s = "";
    for (const x of new Uint8Array(b)) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  document.title = "Confirm with your security key — Keyward";
  document.body.innerHTML =
    '<div style="font:16px system-ui;padding:48px;text-align:center">Keyward is asking your passkey or security key to confirm the login…</div>';
  let cred: PublicKeyCredential;
  try {
    cred = (await navigator.credentials.get({
      publicKey: {
        challenge: b64u(o.challenge),
        timeout: o.timeout ?? 60000,
        rpId: o.rpId,
        userVerification: o.userVerification ?? "discouraged",
        allowCredentials: (o.allowCredentials ?? []).map((c: any) => ({ type: c.type ?? "public-key", id: b64u(c.id), transports: c.transports })),
        // The legacy U2F `appid` extension must be an https URL; browsers reject the whole
        // request otherwise (e.g. a Vaultwarden on http://localhost). It only matters for keys
        // registered through old U2F, which an http server can't have anyway.
        extensions: o.extensions ? Object.fromEntries(Object.entries(o.extensions).filter(([k, v]) => k !== "appid" || String(v).startsWith("https:"))) : undefined,
      },
    })) as PublicKeyCredential;
  } catch (e) {
    // A rejected promise would reach the background as an empty result; pass the reason instead.
    return { error: `${(e as Error).name}: ${(e as Error).message}` };
  }
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: enc(cred.rawId),
    type: cred.type,
    extensions: cred.getClientExtensionResults(),
    response: {
      authenticatorData: enc(r.authenticatorData),
      clientDataJson: enc(r.clientDataJSON),
      signature: enc(r.signature),
      userHandle: r.userHandle ? enc(r.userHandle) : null,
    },
  };
}

export async function webauthnTwoFactor(remember: boolean, afterLogin: (accountId: string, userKey: string) => Promise<unknown>): Promise<{ ok: boolean; error?: string }> {
  const p = await loadPending();
  if (!p) return { ok: false, error: "The login expired — start again" };
  const options = p.providers[TwoFactorProvider.WebAuthn];
  if (!options) return { ok: false, error: "Security keys are not enabled for this account" };
  const [prev] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  const tab = await chrome.tabs.create({ url: serverUrls(p.server).base + "/404.html#keyward-webauthn", active: true });
  try {
    await waitComplete(tab.id!);
    const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id! }, world: "MAIN", func: assertInPage, args: [options] });
    const assertion = res?.result;
    if (!assertion) throw new Error((res as any)?.error?.message ?? "No response from the security key");
    if (assertion.error) {
      throw new Error(/NotAllowedError/.test(assertion.error) ? "The security key prompt was cancelled or timed out" : assertion.error);
    }
    const out = await submitTwoFactor(p, { provider: TwoFactorProvider.WebAuthn, token: JSON.stringify(assertion), remember });
    if (out.kind !== "success") throw new Error("The server rejected the security key");
    const { accountId, userKey } = await finishLogin(p.server, out);
    await afterLogin(accountId, userKey);
    return { ok: true };
  } catch (e) {
    const msg = (e as Error)?.message ?? String(e);
    return { ok: false, error: /NotAllowedError|timed out|cancel/i.test(msg) ? "Cancelled or timed out" : msg };
  } finally {
    await chrome.tabs.remove(tab.id!).catch(() => {});
    if (prev?.id) await chrome.tabs.update(prev.id, { active: true }).catch(() => {});
    await chrome.action.openPopup?.().catch(() => {});
  }
}
