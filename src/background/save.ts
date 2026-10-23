// Save / update prompts. A content script reports a submitted login form; the prompt shows only
// after the page has moved on (navigation committed, or the password field gone for 0.8 s in a
// single-page app) and only when the vault doesn't already hold exactly that login. A login page
// that comes back with a password field (failed login) gets no prompt.
import { parseUrl, baseDomain } from "../core/url/match.ts";
import { emptyView } from "../core/vault/cipher.ts";
import { CipherType, type CipherView } from "../core/vault/types.ts";
import type { SubmitData } from "../content/autofill/protocol.ts";
import { broadcast, type Handlers } from "../platform/messages.ts";
import { loadSettings, saveSettings } from "../platform/settings.ts";
import { session } from "../platform/storage.ts";
import { LockedError, unlockedCtx } from "./ctx.ts";
import { vaultHandlers } from "./vault.ts";

export type SaveKind = "save" | "update" | "locked" | "none";

interface Pending {
  data: SubmitData;
  frameId: number;
  at: number;
  navigated: boolean;
  shown: boolean;
  kind?: SaveKind;
  itemId?: string;
  itemName?: string;
  token?: string;
}

const KEEP_MS = 60_000;
/** What a one-time code looks like (4 to 8 digits, spaces allowed). */
const CODE = /^\s*(\d\s?){4,8}$/;
const hostOf = (u: string) => parseUrl(u)?.hostname ?? "";
const same = (a?: string | null, b?: string | null) => (a ?? "").trim().toLowerCase() === (b ?? "").trim().toLowerCase();

async function lazyAutofill() {
  return import("./autofill.ts");
}

export async function onSaveSubmit(data: SubmitData, sender: chrome.runtime.MessageSender): Promise<void> {
  const tabId = sender.tab?.id;
  if (tabId == null || !/^https?:/.test(data.url)) return;
  const s = await loadSettings();
  const host = hostOf(data.url);
  const listed = (l: string[]) => l.some((x) => host === x || host.endsWith("." + x));
  if ((!s.autofill.savePrompt && !s.autofill.updatePrompt) || listed(s.autofill.excluded) || listed(s.autofill.neverSave)) return;
  const site = baseDomain(host) ?? host;
  // A username-only step: remember the name for the password page that follows.
  if (!data.password && !data.newPassword) {
    if (data.username) await session.set(`user:${tabId}`, { site, username: data.username, at: Date.now() });
    return;
  }
  if (!data.username) {
    const u = await session.get<{ site: string; username: string; at: number }>(`user:${tabId}`);
    if (u && u.site === site && Date.now() - u.at < 10 * 60_000) data.username = u.username;
  }
  const { getFlow, filledPasswordHash } = await lazyAutofill();
  const flow = await getFlow(tabId);
  if (flow && flow.site === site && !data.newPassword && flow.pw && flow.pw === (await filledPasswordHash(data.password))) {
    if (!data.username || same(data.username, flow.user)) return; // exactly what we filled
  }
  if (!data.username && flow?.site === site) data.username = flow.user ?? "";
  await session.set(`save:${tabId}`, { data, frameId: sender.frameId ?? 0, at: Date.now(), navigated: false, shown: false } satisfies Pending);
}

export async function onSaveSubmitDone(tabId: number): Promise<void> {
  const p = await session.get<Pending>(`save:${tabId}`);
  if (p && !p.shown && Date.now() - p.at < KEEP_MS) await evaluateAndShow(tabId, p);
}

export async function onSaveTab(tabId: number, change: chrome.tabs.OnUpdatedInfo, tab: chrome.tabs.Tab): Promise<void> {
  if (change.status !== "loading" && change.status !== "complete") return;
  const p = await session.get<Pending>(`save:${tabId}`);
  if (!p || p.shown) return;
  if (Date.now() - p.at > KEEP_MS) return session.remove(`save:${tabId}`);
  if (change.status === "loading") {
    p.navigated = true;
    return session.set(`save:${tabId}`, p);
  }
  if (!p.navigated) return;
  if (p.data.type === "login" && (await stillOnLoginForm(tabId, tab.url ?? "", p.data.url))) {
    await session.remove(`save:${tabId}`); // the site showed the login form again: probably a wrong password
    return;
  }
  await evaluateAndShow(tabId, p);
}

async function stillOnLoginForm(tabId: number, url: string, submittedUrl: string): Promise<boolean> {
  if (hostOf(url) !== hostOf(submittedUrl)) return false;
  try {
    const [r] = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: () =>
        Array.from(document.querySelectorAll("input[type=password]")).some((e) => {
          const r = e.getBoundingClientRect();
          return r.width > 1 && r.height > 1 && getComputedStyle(e).visibility !== "hidden";
        }),
    });
    return !!r?.result;
  } catch {
    return false;
  }
}

async function decide(p: Pending): Promise<Pick<Pending, "kind" | "itemId" | "itemName">> {
  let c;
  try {
    c = await unlockedCtx();
  } catch (e) {
    if (e instanceof LockedError) return { kind: "locked" };
    return { kind: "none" };
  }
  const s = await loadSettings();
  const { matchesFor, loadView } = await lazyAutofill();
  const matches = (await matchesFor(p.data.url)).filter((m) => m.type === CipherType.Login);
  const views: CipherView[] = [];
  for (const m of matches.slice(0, 20)) views.push(await loadView(c, m.id).catch(() => null as any));
  const ok = views.filter(Boolean);
  const { username, password, newPassword, type } = p.data;
  const sameUser = ok.filter((v) => same(v.login?.username, username));
  const update = (v: CipherView | undefined) => (v && s.autofill.updatePrompt ? { kind: "update" as const, itemId: v.id, itemName: v.name } : { kind: "none" as const });

  if (type === "change") {
    if (ok.some((v) => v.login?.password === newPassword)) return { kind: "none" };
    const target = ok.find((v) => v.login?.password === password && (!username || same(v.login?.username, username))) ?? sameUser[0];
    if (target) return update(target);
  } else {
    const pw = type === "signup" ? newPassword : password;
    // A one-time code typed into a box drawn as a password field (some banks' second step):
    // never offer it as a new login, or as the new password of a login whose password isn't a
    // number itself.
    if (type === "login" && CODE.test(pw)) {
      if (!username) return { kind: "none" };
      if (sameUser.some((v) => v.login?.password && !CODE.test(v.login.password))) return { kind: "none" };
    }
    if (sameUser.some((v) => v.login?.password === pw)) return { kind: "none" };
    if (!username && ok.some((v) => v.login?.password === pw)) return { kind: "none" };
    if (sameUser.length) return update(sameUser[0]);
    if (!username && ok.length === 1) return update(ok[0]);
  }
  return s.autofill.savePrompt ? { kind: "save" } : { kind: "none" };
}

async function evaluateAndShow(tabId: number, p: Pending) {
  Object.assign(p, await decide(p));
  if (p.kind === "none") return session.remove(`save:${tabId}`);
  p.shown = true;
  p.token = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
  await session.setMany({ [`save:${tabId}`]: p, [`saveTok:${p.token}`]: tabId });
  const { inject, toFrame } = await lazyAutofill();
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (!tab?.url) return;
  const t = { frameId: 0, url: tab.url };
  try {
    await inject(tabId, t);
    await toFrame(tabId, t, { kw: "af", t: "savebar", token: p.token });
  } catch {}
}

async function pendingFor(token: string | undefined): Promise<{ tabId: number; p: Pending } | null> {
  if (!token || typeof token !== "string") return null;
  const tabId = await session.get<number>(`saveTok:${token}`);
  if (tabId == null) return null;
  const p = await session.get<Pending>(`save:${tabId}`);
  return p?.token === token ? { tabId, p } : null;
}

async function closeBar(tabId: number) {
  const p = await session.get<Pending>(`save:${tabId}`);
  await session.remove([`save:${tabId}`, ...(p?.token ? [`saveTok:${p.token}`] : [])]);
  await chrome.tabs.sendMessage(tabId, { kw: "af", t: "savebarClose" }, { frameId: 0 }).catch(() => {});
}

export const saveHandlers: Handlers = {
  "save.ctx": async ({ token }) => {
    const hit = await pendingFor(token);
    if (!hit) return { kind: "none" as SaveKind, host: "", username: "" };
    const { tabId, p } = hit;
    if (p.kind === "locked") {
      // Unlocked since the prompt appeared: decide now.
      Object.assign(p, await decide(p));
      await session.set(`save:${tabId}`, p);
    }
    let folders: { id: string; name: string }[] = [];
    try {
      const c = await unlockedCtx();
      const { loadSnapshot } = await import("../core/store/summaries.ts");
      folders = (await loadSnapshot(c.db, c.cacheKey)).aux.folders;
    } catch {}
    return { kind: p.kind ?? "none", tabId, host: hostOf(p.data.url), username: p.data.username, itemName: p.itemName, folders, type: p.data.type };
  },
  "save.decide": async ({ token, action, folderId }, sender) => {
    const hit = await pendingFor(token);
    if (!hit) return;
    const { tabId, p } = hit;
    const host = hostOf(p.data.url);
    if (action === "never") {
      const s = await loadSettings();
      await saveSettings({ autofill: { ...s.autofill, neverSave: [...new Set([...s.autofill.neverSave, host])] } });
      broadcast({ kind: "settings" });
    } else if (action === "save" && p.kind === "save") {
      const origin = new URL(p.data.url).origin;
      const v = emptyView(CipherType.Login, { name: baseDomain(host) ?? host, folderId: folderId ?? null });
      v.login!.username = p.data.username || null;
      v.login!.password = p.data.newPassword || p.data.password;
      v.login!.uris = [{ uri: origin, match: null }];
      await vaultHandlers["vault.save"]!({ view: v }, sender);
    } else if (action === "update" && p.kind === "update" && p.itemId) {
      const c = await unlockedCtx();
      const { loadView } = await lazyAutofill();
      const v = await loadView(c, p.itemId);
      const next = p.data.newPassword || p.data.password;
      if (v.login && v.login.password !== next) {
        if (v.login.password) v.passwordHistory = [{ password: v.login.password, lastUsedDate: new Date().toISOString() }, ...v.passwordHistory].slice(0, 5);
        v.login.password = next;
        v.login.passwordRevisionDate = new Date().toISOString();
        if (!v.login.username && p.data.username) v.login.username = p.data.username;
        await vaultHandlers["vault.save"]!({ view: v }, sender);
      }
    }
    await closeBar(tabId);
  },
};
