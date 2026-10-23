// Passkey provider, background half. The relay content script brings a page's create()/get()
// (JSON options); the origin used is the sender's, never the page's word. Requests Keyward can't
// or shouldn't answer go back as `fallback` (the browser's own WebAuthn: security keys, phones);
// the rest wait in session storage for the user's choice in the passkey dialog, and the answer
// goes back to the requesting frame. A conditional get() (passkeys in the sign-in field's
// autofill) shows no dialog: it waits, one per frame, for a pick in the inline menu.
import { sha256 } from "../core/crypto/primitives.ts";
import { assert, attest, createPasskey, credentialIdBytes } from "../core/passkey/authenticator.ts";
import { authenticationJSON, clientDataJSON, excluded, parseCreate, parseGet, registrationJSON, usable, type CreateRequest, type GetRequest, type Refusal } from "../core/passkey/client.ts";
import { emptyView } from "../core/vault/cipher.ts";
import { CipherType, type CipherView, type Fido2View } from "../core/vault/types.ts";
import { fromB64, toB64 } from "../core/util/bytes.ts";
import { loadAccounts } from "../platform/accounts.ts";
import type { Handlers, PasskeyOffer } from "../platform/messages.ts";
import { isUnlocked } from "../platform/session.ts";
import { loadSettings } from "../platform/settings.ts";
import { local, session } from "../platform/storage.ts";
import { ApiError } from "../core/api/client.ts";
import { LockedError, unlockedCtx, type UnlockedCtx } from "./ctx.ts";
import { vaultHandlers } from "./vault.ts";
import { twoFactorTabs } from "./webauthn2fa.ts";

const TTL = 10 * 60_000;
/** A sign-in page may sit open a long while before the user focuses its field. */
const CONDITIONAL_TTL = 60 * 60_000;

interface Pending {
  tabId: number;
  frameId: number;
  kind: "create" | "get";
  origin: string;
  rpId: string;
  at: number;
  /** a conditional get(): answered from the inline menu */
  conditional?: boolean;
  /** conditional, a protected pick in the dialog: the full offer to go back to */
  narrowed?: { itemId: string; credentialId: string }[];
  /** CreateRequest / GetRequest with byte fields as base64 */
  req: Record<string, unknown>;
  /** get: the passkeys the dialog may offer */
  candidates?: { itemId: string; credentialId: string }[];
  /** create: excludeCredentials names a passkey already in the vault */
  exists?: boolean;
}

export type PasskeyResult = { ok: unknown } | Refusal;

const newToken = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
const listed = (l: string[], host: string) => l.some((x) => host === x || host.endsWith("." + x));
const originOf = (s: chrome.runtime.MessageSender) => (s as any).origin ?? (s.url ? new URL(s.url).origin : "");

function pack(r: CreateRequest | GetRequest): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(r).map(([k, v]) => [k, v instanceof Uint8Array ? { b: toB64(v) } : Array.isArray(v) ? v.map((x) => (x instanceof Uint8Array ? { b: toB64(x) } : x)) : v]),
  );
}
function unpack<T>(o: Record<string, unknown>): T {
  const un = (v: any) => (v && typeof v === "object" && "b" in v ? fromB64(v.b) : v);
  return Object.fromEntries(Object.entries(o).map(([k, v]) => [k, Array.isArray(v) ? v.map(un) : un(v)])) as T;
}

/** Login items holding a passkey for `rpId`. */
async function passkeysFor(c: UnlockedCtx, rpId: string): Promise<{ view: CipherView; f: Fido2View }[]> {
  const { vaultIndex, loadView } = await import("./autofill.ts");
  const v = await vaultIndex(c.account.id);
  const out: { view: CipherView; f: Fido2View }[] = [];
  for (const s of v.items.values()) {
    if (s.del || !s.pk.includes(rpId)) continue;
    const view = await loadView(c, s.id).catch(() => null);
    for (const f of view?.login?.fido2Credentials ?? []) if (f.rpId === rpId) out.push({ view: view!, f });
  }
  return out;
}

async function begin(m: { kind: string; options: any }, sender: chrome.runtime.MessageSender): Promise<Refusal | { pending: string }> {
  const tabId = sender.tab!.id!;
  const frameId = sender.frameId ?? 0;
  const origin = originOf(sender);
  const top = sender.tab?.url ? new URL(sender.tab.url).origin : origin;
  // Cross-origin frames need the page's permission policy, which only the browser can check.
  if (frameId !== 0 && origin !== top) return { fallback: "cross-origin frame" };
  if (twoFactorTabs.has(tabId)) return { fallback: "Keyward's own two-step login" };
  const settings = await loadSettings();
  if (!settings.passkeys.enabled || listed(settings.passkeys.excluded, new URL(origin).hostname)) return { fallback: "passkeys off for this site" };
  let c: UnlockedCtx;
  try {
    c = await unlockedCtx();
  } catch (e) {
    return { fallback: e instanceof LockedError ? "vault locked" : "no account" };
  }
  let p: Pending;
  if (m.kind === "create") {
    const r = parseCreate(m.options, origin);
    if (!("rpId" in r)) return r;
    const have = await passkeysFor(c, r.rpId);
    p = { tabId, frameId, kind: "create", origin, rpId: r.rpId, at: Date.now(), req: pack(r), exists: have.some((x) => excluded(x.f, r)) };
  } else if (m.kind === "get") {
    const r = parseGet(m.options, origin);
    if (!("rpId" in r)) return r;
    const cands = (await passkeysFor(c, r.rpId)).filter((x) => usable(x.f, r));
    if (!cands.length) return { fallback: "no passkey for this site in Keyward" };
    p = { tabId, frameId, kind: "get", origin, rpId: r.rpId, at: Date.now(), req: pack(r), candidates: cands.map((x) => ({ itemId: x.view.id, credentialId: x.f.credentialId })) };
    if (m.options?.mediation === "conditional") p.conditional = true;
  } else return { fallback: "unknown request" };
  const token = newToken();
  if (p.conditional) {
    // One waiting autofill request per frame: a newer one replaces it.
    const key = `pkc:${tabId}:${frameId}`;
    const old = await session.get<string>(key);
    const prev = old ? await pendingFor(old) : null;
    if (prev) await finish(old!, prev, { error: "NotAllowedError", message: "A newer request replaced this one." });
    await session.setMany({ [`pk:${token}`]: p, [key]: token });
    // A field already focused gets its menu now.
    await chrome.tabs.sendMessage(tabId, { kw: "af", t: "refocus" }, { frameId }).catch(() => {});
    return { pending: token };
  }
  await session.set(`pk:${token}`, p);
  await chrome.tabs.sendMessage(tabId, { kw: "pkd", t: "show", token }, { frameId: 0 }).catch(() => {});
  return { pending: token };
}

async function pendingFor(token: unknown): Promise<Pending | null> {
  if (typeof token !== "string" || !/^[0-9a-f]{32}$/.test(token)) return null;
  const p = await session.get<Pending>(`pk:${token}`);
  if (!p) return null;
  if (Date.now() - p.at > (p.conditional ? CONDITIONAL_TTL : TTL)) {
    await drop(token, p);
    return null;
  }
  return p;
}

async function drop(token: string, p: Pending) {
  const key = `pkc:${p.tabId}:${p.frameId}`;
  const keys = [`pk:${token}`];
  if (p.conditional && (await session.get<string>(key)) === token) keys.push(key);
  await session.remove(keys);
}

async function finish(token: string, p: Pending, result: PasskeyResult) {
  await drop(token, p);
  if (p.frameId !== 0) await chrome.tabs.sendMessage(p.tabId, { kw: "pkd", t: "hide", token }, { frameId: 0 }).catch(() => {});
  await chrome.tabs.sendMessage(p.tabId, { kw: "pkr", token, result }, { frameId: p.frameId }).catch(() => {});
}

/** Signs with one of the request's offered passkeys and sends the answer to the page. */
async function answerGet(token: string, p: Pending, itemId: string | undefined, credentialId: string | undefined, sender: chrome.runtime.MessageSender) {
  if (!itemId || !p.candidates?.some((k) => k.itemId === itemId && k.credentialId === credentialId)) throw new Error("not one of the offered passkeys");
  const c = await unlockedCtx();
  const { loadView } = await import("./autofill.ts");
  const r = unpack<GetRequest>(p.req);
  const view = await loadView(c, itemId);
  const f = view.login?.fido2Credentials.find((x) => x.credentialId === credentialId && x.rpId === p.rpId);
  if (!f) throw new Error("passkey not found");
  const cd = clientDataJSON("webauthn.get", r.challenge, p.origin);
  // A counting passkey must count up even when the last save to the server failed: the
  // highest counter used on this device is kept locally too.
  const used = `pkn:${c.account.id}:${f.credentialId}`;
  const a = await assert({ ...f, counter: Math.max(f.counter, (await local.get<number>(used)) ?? 0) }, await sha256(cd), true);
  if (a.counter > f.counter) await local.set(used, a.counter);
  await finish(token, p, { ok: authenticationJSON(credentialIdBytes(f.credentialId)!, a, cd) });
  // The site has its answer; a slow or unreachable server no longer holds up the sign-in.
  if (a.counter > f.counter) void saveCounter(c.account.id, itemId, f.credentialId, a.counter, sender).catch((e) => console.warn("passkey counter not saved:", e));
}

/** Stores a passkey's new counter in its item. Changed elsewhere meanwhile: the counter goes
 * into the server's version (never a conflict copy, which would duplicate the key). */
async function saveCounter(accountId: string, itemId: string, credentialId: string, counter: number, sender: chrome.runtime.MessageSender) {
  const { loadView } = await import("./autofill.ts");
  for (let tries = 0; ; tries++) {
    const view = await loadView(await unlockedCtx(accountId), itemId);
    const f = view.login?.fido2Credentials.find((x) => x.credentialId === credentialId);
    if (!f || f.counter >= counter) return;
    f.counter = counter;
    try {
      await vaultHandlers["vault.save"]!({ accountId, view, keepServer: true }, sender);
      return;
    } catch (e) {
      if (tries > 0 || !(e instanceof ApiError && /out of date/i.test(e.message))) throw e;
    }
  }
}

async function offered(c: UnlockedCtx, p: Pending): Promise<PasskeyOffer[]> {
  const views = await passkeysFor(c, p.rpId);
  return (p.candidates ?? []).flatMap((k) => {
    const hit = views.find((x) => x.view.id === k.itemId && x.f.credentialId === k.credentialId);
    return hit ? [{ itemId: k.itemId, credentialId: k.credentialId, itemName: hit.view.name, userName: hit.f.userName, displayName: hit.f.userDisplayName, reprompt: hit.view.reprompt === 1 }] : [];
  });
}

async function conditionalFor(tabId: number, frameId: number): Promise<{ token: string; p: Pending } | null> {
  const token = await session.get<string>(`pkc:${tabId}:${frameId}`);
  const p = token ? await pendingFor(token) : null;
  return p?.conditional && p.tabId === tabId && p.frameId === frameId ? { token: token!, p } : null;
}

/** The passkeys a frame's waiting autofill request offers (for the inline menu). */
export async function conditionalPasskeys(tabId: number, frameId: number): Promise<PasskeyOffer[]> {
  const w = await conditionalFor(tabId, frameId);
  if (!w) return [];
  try {
    return await offered(await unlockedCtx(), w.p);
  } catch {
    return [];
  }
}

/** The inline menu's pick. A protected item opens the passkey dialog, which asks for the master
 * password, with just that passkey. */
export async function useConditional(tabId: number, frameId: number, itemId: string, credentialId: string, sender: chrome.runtime.MessageSender): Promise<{ done: boolean; dialog?: boolean }> {
  const w = await conditionalFor(tabId, frameId);
  if (!w) return { done: false };
  const one = w.p.candidates?.find((k) => k.itemId === itemId && k.credentialId === credentialId);
  if (!one) throw new Error("not one of the offered passkeys");
  const view = await (await import("./autofill.ts")).loadView(await unlockedCtx(), itemId);
  if (view.reprompt === 1) {
    await session.set(`pk:${w.token}`, { ...w.p, candidates: [one], narrowed: w.p.narrowed ?? w.p.candidates });
    await chrome.tabs.sendMessage(tabId, { kw: "pkd", t: "show", token: w.token }, { frameId: 0 }).catch(() => {});
    return { done: false, dialog: true };
  }
  await answerGet(w.token, w.p, itemId, credentialId, sender);
  return { done: true };
}

/** A closed tab's waiting requests. */
export async function dropPasskeyTab(tabId: number): Promise<void> {
  const all = await session.all();
  const keys = Object.keys(all).filter((k) => (k.startsWith("pk:") && all[k]?.tabId === tabId) || k.startsWith(`pkc:${tabId}:`));
  if (keys.length) await session.remove(keys);
}

export function passkeyMessage(msg: any, sender: chrome.runtime.MessageSender, respond: (r: unknown) => void): boolean | void {
  if (msg?.kw !== "pk" || sender.tab?.id == null) return false;
  if (/^(chrome|moz)-extension:/.test(sender.url ?? "")) return false;
  if (msg.t === "begin") {
    begin(msg, sender).then(respond, (e) => respond({ fallback: String(e?.message ?? e) }));
    return true;
  }
  if (msg.t === "cancel") {
    void pendingFor(msg.token).then(async (p) => {
      if (!p || p.tabId !== sender.tab!.id) return;
      await drop(msg.token, p);
      await chrome.tabs.sendMessage(p.tabId, { kw: "pkd", t: "hide", token: msg.token }, { frameId: 0 }).catch(() => {});
    });
  }
  return false;
}

export const passkeyHandlers: Handlers = {
  "pk.ctx": async ({ token }) => {
    const p = await pendingFor(token);
    if (!p) return null;
    const host = new URL(p.origin).host;
    const c = await unlockedCtx();
    if (p.kind === "get") return { kind: "get" as const, host, rpId: p.rpId, passkeys: await offered(c, p), picked: !!p.narrowed };
    const r = unpack<CreateRequest>(p.req);
    const { matchesFor, loadView } = await import("./autofill.ts");
    const logins = (await matchesFor(p.origin)).filter((x) => x.type === CipherType.Login);
    const targets = [];
    for (const x of logins.slice(0, 20)) {
      const v = await loadView(c, x.id).catch(() => null);
      if (v) targets.push({ itemId: v.id, name: v.name, userName: v.login?.username ?? null, hasPasskey: (v.login?.fido2Credentials.length ?? 0) > 0, reprompt: v.reprompt === 1 });
    }
    return { kind: "create" as const, host, rpId: p.rpId, rpName: r.rpName, userName: r.userName, displayName: r.userDisplayName, exists: !!p.exists, targets };
  },

  "pk.decide": async ({ token, action, itemId, credentialId }, sender) => {
    const p = await pendingFor(token);
    if (!p) return { done: false };
    if (action === "fallback") {
      await finish(token, p, { fallback: "the user chose the browser" });
      return { done: true };
    }
    if (action === "cancel" && p.conditional) {
      // Closing the dialog of an autofill pick leaves the page's request waiting, as it was.
      await session.set(`pk:${token}`, { ...p, candidates: p.narrowed ?? p.candidates, narrowed: undefined });
      await chrome.tabs.sendMessage(p.tabId, { kw: "pkd", t: "hide", token }, { frameId: 0 }).catch(() => {});
      return { done: true };
    }
    if (action === "cancel" || (p.kind === "create" && p.exists)) {
      const err: Refusal = p.exists && action !== "cancel"
        ? { error: "InvalidStateError", message: "A passkey for this account is already saved." }
        : { error: "NotAllowedError", message: "The operation either timed out or was not allowed." };
      await finish(token, p, err);
      return { done: true };
    }
    if (p.kind === "get") {
      if (action !== "use") throw new Error("unknown action");
      await answerGet(token, p, itemId, credentialId, sender);
      return { done: true };
    }
    if (action !== "save") throw new Error("unknown action");
    const c = await unlockedCtx();
    const { loadView } = await import("./autofill.ts");
    const r = unpack<CreateRequest>(p.req);
    const k = await createPasskey(r);
    const att = await attest(k, true);
    let view: CipherView;
    if (itemId) {
      view = await loadView(c, itemId);
      if (view.type !== CipherType.Login || !view.login) throw new Error("not a login");
      // One passkey per login, as in Bitwarden: a new one replaces the old.
      view.login.fido2Credentials = [k.fido2];
      if (!view.login.username && r.userName) view.login.username = r.userName;
    } else {
      view = emptyView(CipherType.Login, { name: r.rpName || r.rpId });
      view.login!.username = r.userName;
      view.login!.uris = [{ uri: p.origin, match: null }];
      view.login!.fido2Credentials = [k.fido2];
    }
    await vaultHandlers["vault.save"]!({ view }, sender);
    await finish(token, p, { ok: registrationJSON(k, att, clientDataJSON("webauthn.create", r.challenge, p.origin), r) });
    return { done: true };
  },
};

// ------------------------------------------------------------------ page scripts
const SCRIPTS = ["kw-pk-main", "kw-pk-relay"];
const MATCHES = ["https://*/*", "http://localhost/*", "http://*.localhost/*"];
let syncing: Promise<void> = Promise.resolve();

/** The shim goes into pages only while passkeys are on and the active account is unlocked. */
export function syncPasskeyScripts(): Promise<void> {
  syncing = syncing.then(async () => {
    const [s, a] = await Promise.all([loadSettings(), loadAccounts()]);
    const on = s.passkeys.enabled && !!a.active && (await isUnlocked(a.active));
    const have = (await chrome.scripting.getRegisteredContentScripts({ ids: SCRIPTS })).map((x) => x.id);
    if (on && have.length === SCRIPTS.length) return;
    if (have.length) await chrome.scripting.unregisterContentScripts({ ids: have });
    if (!on) return;
    const base = { matches: MATCHES, allFrames: true, runAt: "document_start" as const, persistAcrossSessions: false };
    await chrome.scripting.registerContentScripts([
      { ...base, id: "kw-pk-main", js: ["cs/passkey-main.js"], world: "MAIN" as any },
      { ...base, id: "kw-pk-relay", js: ["cs/passkey-relay.js"] },
    ]);
  }).catch(() => {});
  return syncing;
}
