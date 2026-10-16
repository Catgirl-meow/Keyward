// Autofill orchestration: injection on demand, frame choice, fill, multi-step login flows, the
// inline menu's data, shortcuts and the context menu. Page matching uses an in-memory domain
// index over the sealed summary buckets, rebuilt only when the vault changes.
import { sha256 } from "../core/crypto/primitives.ts";
import { generatePassword } from "../core/generator/password.ts";
import { loadSnapshot } from "../core/store/summaries.ts";
import { otpCode, parseOtp } from "../core/totp/totp.ts";
import { MatchIndex, baseDomain, parseUrl } from "../core/url/match.ts";
import { decryptCipher } from "../core/vault/cipher.ts";
import { CipherType, FieldType, type CipherView, type Summary } from "../core/vault/types.ts";
import { toB64 } from "../core/util/bytes.ts";
import type { FillPlan } from "../content/autofill/fill.ts";
import type { AfFillResult, AfMessage, CsMessage, FieldReply, FillPurpose, FillVia, ScanResult, ScopeInfo } from "../content/autofill/protocol.ts";
import type { Purpose } from "../content/autofill/classify.ts";
import { listen, type Handlers, type PageMatch } from "../platform/messages.ts";
import { loadAccounts } from "../platform/accounts.ts";
import { isUnlocked } from "../platform/session.ts";
import { loadSettings, type Settings } from "../platform/settings.ts";
import { session } from "../platform/storage.ts";
import { loadGeneratorPrefs, rememberGenerated } from "../platform/generator.ts";
import { copy } from "./clipboard.ts";
import { LockedError, unlockedCtx, type UnlockedCtx } from "./ctx.ts";
import { lock } from "./lock.ts";
import { onSaveSubmit, onSaveSubmitDone, onSaveTab } from "./save.ts";
import { conditionalPasskeys, useConditional } from "./passkey.ts";

interface VaultIndex {
  accountId: string;
  items: Map<string, Summary>;
  index: MatchIndex;
}

let cached: Promise<VaultIndex> | null = null;

listen((m) => {
  if (m.kind === "vault" || m.kind === "lock" || m.kind === "accounts" || m.kind === "settings") {
    cached = null;
    scheduleBadge();
  }
});

async function build(c: UnlockedCtx): Promise<VaultIndex> {
  const [snap, groups, settings] = await Promise.all([loadSnapshot(c.db, c.cacheKey), c.db.meta<string[][]>("domains"), loadSettings()]);
  return { accountId: c.account.id, items: snap.items, index: new MatchIndex(snap.items.values(), settings.defaultUriMatch, groups ?? []) };
}

export async function vaultIndex(accountId?: string): Promise<VaultIndex> {
  const c = await unlockedCtx(accountId);
  if (cached) {
    const v = await cached.catch(() => null);
    if (v && v.accountId === c.account.id) return v;
  }
  cached = build(c);
  cached.catch(() => (cached = null));
  return cached;
}

function toMatch(s: Summary, uri: string | null): PageMatch {
  return { id: s.id, name: s.name, sub: s.sub, uri, type: s.type, totp: s.totp, fav: s.fav, rp: s.rp };
}

const byFavName = (a: PageMatch, b: PageMatch) => Number(b.fav) - Number(a.fav) || a.name.localeCompare(b.name);

export async function matchesFor(url: string, accountId?: string): Promise<PageMatch[]> {
  const page = parseUrl(url);
  if (!page || !/^https?:$/.test(page.protocol)) return [];
  const v = await vaultIndex(accountId);
  return v.index
    .lookup(url, v.items)
    .map((h) => toMatch(v.items.get(h.id)!, h.uri))
    .sort(byFavName);
}

async function itemsOfType(type: CipherType): Promise<PageMatch[]> {
  const v = await vaultIndex();
  const out: PageMatch[] = [];
  for (const s of v.items.values()) if (s.type === type && !s.del && !s.arch) out.push(toMatch(s, null));
  return out.sort(byFavName);
}

async function activeTab(): Promise<chrome.tabs.Tab | undefined> {
  const [t] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return t;
}

const isWeb = (url?: string) => !!url && /^https?:/i.test(url);
const hostOf = (url?: string) => parseUrl(url)?.hostname ?? "";
const siteOf = (url?: string) => baseDomain(hostOf(url)) ?? "";

function excluded(s: Settings, ...urls: (string | undefined)[]) {
  const hosts = urls.map(hostOf).filter(Boolean);
  return s.autofill.excluded.some((x) => hosts.some((h) => h === x || h.endsWith("." + x)));
}

/** URL of the frame a content-script message came from (about:blank/srcdoc inherit the origin). */
function senderUrl(sender: chrome.runtime.MessageSender): string {
  const u = sender.url ?? "";
  if (/^(about|data|blob):/.test(u) && (sender as any).origin) return (sender as any).origin + "/";
  return u;
}

// ---------------------------------------------------------------- frames
interface Target {
  frameId: number;
  documentId?: string;
  url: string;
}

const targetOf = (sender: chrome.runtime.MessageSender): Target => ({ frameId: sender.frameId ?? 0, documentId: (sender as any).documentId, url: senderUrl(sender) });

function injectionTarget(tabId: number, t: Target): chrome.scripting.InjectionTarget {
  return __CHROMIUM__ && t.documentId ? { tabId, documentIds: [t.documentId] } : { tabId, frameIds: [t.frameId] };
}

async function inject(tabId: number, t: Target): Promise<void> {
  await chrome.scripting.executeScript({ target: injectionTarget(tabId, t), files: ["cs/autofill.js"] });
}

function toFrame<T>(tabId: number, t: Target, msg: AfMessage): Promise<T> {
  return chrome.tabs.sendMessage(tabId, msg, __CHROMIUM__ && t.documentId ? { documentId: t.documentId } : { frameId: t.frameId }) as Promise<T>;
}

interface Probe {
  url: string;
  focus: boolean;
  pw: number;
  text: number;
  cc: number;
}

/** Runs in every frame (isolated world) for explicit fills. Must be self-contained. */
function probe(): Probe {
  const vis = (el: Element) => {
    const r = el.getBoundingClientRect();
    return r.width > 1 && r.height > 1 && getComputedStyle(el).visibility !== "hidden";
  };
  const n = (s: string) => Array.from(document.querySelectorAll(s)).filter(vis).length;
  const a = document.activeElement;
  const tag = a?.tagName ?? "";
  return {
    url: location.href,
    focus: document.hasFocus() && (tag === "INPUT" || tag === "SELECT" || tag.includes("-")),
    pw: n("input[type=password]"),
    text: n("input:not([type]),input[type=text],input[type=email],input[type=tel],input[type=number]"),
    cc: n('input[autocomplete^="cc-"],select[autocomplete^="cc-"],input[name*="card" i],input[id*="card" i],input[name*="cc-" i],input[name*="cvc" i],input[name*="cvv" i]'),
  };
}

async function probeFrames(tabId: number): Promise<(Probe & Target)[]> {
  try {
    const rs = await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, func: probe });
    return rs.filter((r) => r.result).map((r) => ({ ...(r.result as Probe), frameId: r.frameId, documentId: (r as any).documentId }));
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------- items
async function loadView(c: UnlockedCtx, id: string): Promise<CipherView> {
  const raw = await c.db.getCipher(id);
  if (!raw) throw new Error("Item not found");
  return decryptCipher(raw, c.ring);
}

async function totpFor(v: CipherView): Promise<string | null> {
  const spec = parseOtp(v.login?.totp);
  if (!spec || spec.kind === "hotp") return null;
  return (await otpCode(spec)).code;
}

function customFields(v: CipherView) {
  return v.fields.filter((f) => (f.type === FieldType.Text || f.type === FieldType.Hidden) && f.name && f.value).map((f) => ({ name: f.name!, value: f.value! }));
}

const purposeOfType = (t: CipherType): FillPurpose | null => (t === CipherType.Login ? "login" : t === CipherType.Card ? "card" : t === CipherType.Identity ? "identity" : null);

async function planFor(v: CipherView, purpose: FillPurpose): Promise<FillPlan> {
  if (purpose === "card") return { card: v.card };
  if (purpose === "identity") return { identity: v.identity };
  const totp = await totpFor(v);
  if (purpose === "totp") return { totp };
  return { username: v.login?.username, password: v.login?.password, totp, fields: customFields(v) };
}

async function itemMatchesUrl(id: string, url: string): Promise<boolean> {
  return (await matchesFor(url)).some((m) => m.id === id);
}

/** May this login item fill into this frame of this tab? */
async function frameAllowed(id: string, frameUrl: string, tabUrl: string): Promise<boolean> {
  if (!isWeb(frameUrl)) return false;
  if (await itemMatchesUrl(id, frameUrl)) return true;
  return siteOf(frameUrl) === siteOf(tabUrl) && (await itemMatchesUrl(id, tabUrl));
}

// ---------------------------------------------------------------- flows (multi-step logins)
interface Flow {
  itemId: string;
  accountId: string;
  site: string;
  at: number;
  pw: string | null; // sha256 of the filled password, so filling it doesn't prompt "save"
  user: string | null;
  steps: string[];
}
const FLOW_MS = 5 * 60_000;

export async function getFlow(tabId: number): Promise<Flow | null> {
  const f = await session.get<Flow>(`flow:${tabId}`);
  if (!f) return null;
  if (Date.now() - f.at > FLOW_MS) {
    await session.remove(`flow:${tabId}`);
    return null;
  }
  return f;
}

export async function filledPasswordHash(password: string): Promise<string> {
  return toB64(await sha256(password));
}

async function startFlow(tabId: number, c: UnlockedCtx, v: CipherView, url: string, filled: string[]) {
  await session.set(`flow:${tabId}`, {
    itemId: v.id,
    accountId: c.account.id,
    site: siteOf(url),
    at: Date.now(),
    pw: v.login?.password ? await filledPasswordHash(v.login.password) : null,
    user: v.login?.username ?? null,
    steps: [`${url}|${filled.join(",")}`],
  } satisfies Flow);
}

/** Fill the next step of a login this tab started (password page, code page). */
async function continueFlow(tabId: number, t: Target, info: ScopeInfo): Promise<boolean> {
  const flow = await getFlow(tabId);
  if (!flow || !isWeb(t.url) || siteOf(t.url) !== flow.site) return false;
  const wantPw = info.hasPw && info.emptyPw;
  const wantOtp = info.hasOtp && info.emptyOtp;
  if (!wantPw && !wantOtp) return false;
  const settings = await loadSettings();
  if (!settings.autofill.continueSteps) return false;
  // Each step at most once per URL: a failed login that shows the form again isn't refilled.
  const key = `${t.url.split("#")[0]}|${wantPw ? "pw" : ""}${wantOtp ? "otp" : ""}`;
  if (flow.steps.includes(key)) return false;
  flow.steps.push(key);
  await session.set(`flow:${tabId}`, flow);
  let c: UnlockedCtx;
  try {
    c = await unlockedCtx(flow.accountId);
  } catch {
    return false;
  }
  const v = await loadView(c, flow.itemId);
  const plan: FillPlan = { onlyEmpty: true };
  if (wantPw) {
    plan.password = v.login?.password;
    if (info.hasUser) plan.username = v.login?.username;
  }
  if (wantOtp) plan.totp = await totpFor(v);
  if (!plan.password && !plan.totp) return false;
  await inject(tabId, t).catch(() => {});
  const r = await toFrame<AfFillResult>(tabId, t, { kw: "af", t: "fill", plan, via: "flow", purpose: wantPw ? "login" : "totp" }).catch(() => null);
  if (r?.filled.includes("password") && !r.otpField && plan.password) await maybeCopyTotp(v, settings);
  return !!r?.filled.length;
}

async function maybeCopyTotp(v: CipherView, settings?: Settings): Promise<boolean> {
  const s = settings ?? (await loadSettings());
  if (!s.autofill.copyTotp) return false;
  const code = await totpFor(v);
  if (!code) return false;
  await copy(code).catch(() => {});
  return true;
}

// ---------------------------------------------------------------- fill
export interface FillOpts {
  via: FillVia;
  target?: Target;
  purpose?: FillPurpose;
  force?: boolean;
  /** The caller asked for the master password (items with re-prompt fill only then). */
  verified?: boolean;
}

export interface FillOutcome {
  filled: boolean;
  totpCopied?: boolean;
  error?: string;
  confirm?: string;
  reprompt?: boolean;
}

export async function fillItem(tabId: number, itemId: string, opts: FillOpts): Promise<FillOutcome> {
  const r = await fillOnce(tabId, itemId, opts);
  // The page swapped documents between the probe and the fill (redirect, slow commit): once more.
  if (r.stale && !opts.target) return fillOnce(tabId, itemId, opts);
  return r;
}

async function fillOnce(tabId: number, itemId: string, opts: FillOpts): Promise<FillOutcome & { stale?: boolean }> {
  const c = await unlockedCtx();
  const v = await loadView(c, itemId);
  if (v.deletedDate) return { filled: false, error: "This item is in the trash" };
  if (v.reprompt === 1 && !opts.verified) return { filled: false, reprompt: true };
  const purpose = opts.purpose ?? purposeOfType(v.type);
  if (!purpose) return { filled: false, error: "This kind of item can't be filled" };
  const tab = await chrome.tabs.get(tabId);
  const tabUrl = tab.url ?? "";
  const settings = await loadSettings();
  if (excluded(settings, tabUrl) && opts.via !== "popup") return { filled: false, error: "Autofill is turned off for this site" };

  // Which frames?
  let targets: Target[];
  if (opts.target) {
    targets = [opts.target];
    if (purpose === "card") {
      // Payment forms split one card over several frames: fill them all.
      for (const p of await probeFrames(tabId)) if (p.cc && p.frameId !== opts.target.frameId && isWeb(p.url)) targets.push(p);
    }
  } else {
    const frames = (await probeFrames(tabId)).filter((p) => isWeb(p.url));
    if (!frames.length) return { filled: false, error: isWeb(tabUrl) ? "Can't reach this page. Reload it and try again." : "Nothing to fill on this page" };
    const top = frames.find((f) => f.frameId === 0);
    if (purpose === "card") {
      targets = frames.filter((f) => f.cc || f.focus);
      if (!targets.length && top) targets = [top];
    } else if (purpose === "identity") {
      targets = [frames.find((f) => f.focus && f.text) ?? top ?? frames[0]];
    } else {
      const score = (f: Probe & Target) => (f.focus && (f.pw || f.text) ? 100 : 0) + (f.pw ? 50 : 0) + (f.text ? 10 : 0) + (f.frameId === 0 ? 5 : 0);
      const ranked = [...frames].sort((a, b) => score(b) - score(a));
      const allowed: Target[] = [];
      let blocked: string | null = null;
      // Frames with fields; the top frame alone when none has any in its light DOM (shadow DOM forms).
      const withFields = ranked.filter((f) => f.pw || f.text || f.focus);
      for (const f of withFields.length ? withFields : ranked.filter((f) => f.frameId === 0)) {
        if (opts.force || (await frameAllowed(v.id, f.url, tabUrl))) {
          allowed.push(f);
          break;
        }
        if (f.pw || f.text) blocked ??= hostOf(f.url);
      }
      if (!allowed.length) {
        const uri = v.login?.uris.find((u) => parseUrl(u.uri))?.uri;
        const where = blocked ?? hostOf(tabUrl);
        return {
          filled: false,
          confirm: uri ? `“${v.name}” is saved for ${hostOf(uri)}, but this form is on ${where}. Fill it anyway?` : `“${v.name}” has no website. Fill it into ${where}?`,
        };
      }
      targets = allowed;
    }
  }

  // An https item on an http page of the same host: ask first.
  if (purpose === "login" && !opts.force && opts.via !== "flow") {
    const t = targets[0];
    const pu = parseUrl(t.url);
    if (pu?.protocol === "http:" && v.login?.uris.some((u) => parseUrl(u.uri)?.protocol === "https:" && parseUrl(u.uri)?.hostname === pu.hostname)) {
      return { filled: false, confirm: `${pu.hostname} isn't using a secure connection (http). Fill “${v.name}” anyway?` };
    }
  }

  const plan = await planFor(v, purpose);
  // Nobody asked for this fill: leave whatever is already typed.
  if (opts.via === "pageload") plan.onlyEmpty = true;
  let filled: string[] = [];
  let otpField = false;
  let error: string | undefined;
  let stale = false;
  for (const t of targets) {
    try {
      await inject(tabId, t);
      const r = await toFrame<AfFillResult>(tabId, t, { kw: "af", t: "fill", plan, via: opts.via, purpose });
      if (r?.filled.length) {
        filled = filled.concat(r.filled);
        otpField ||= r.otpField;
        if (purpose === "login") {
          await startFlow(tabId, c, v, t.url, r.filled);
          // A username-only step of a single-page login: watch for the next field.
          if (!r.filled.includes("password")) await toFrame(tabId, t, { kw: "af", t: "watch", ms: 120_000 }).catch(() => {});
        }
      } else error ??= r?.error;
    } catch (e) {
      const msg = (e as Error).message;
      if (/No (document|frame)|Receiving end does not exist|Frame with ID/i.test(msg)) stale = true;
      else error ??= msg;
    }
  }
  if (!filled.length) return { filled: false, stale, error: error ?? (stale ? "The page changed while filling. Try again." : "No matching fields on this page") };
  let totpCopied = false;
  if (purpose === "login" && !otpField && v.login?.totp && filled.includes("password")) totpCopied = await maybeCopyTotp(v, settings);
  return { filled: true, totpCopied };
}

async function fillGenerated(tabId: number, t: Target | undefined, value: string, via: FillVia): Promise<FillOutcome> {
  const targets = t ? [t] : (await probeFrames(tabId)).filter((p) => isWeb(p.url) && (p.focus || p.pw)).sort((a, b) => Number(b.focus) - Number(a.focus)).slice(0, 1);
  for (const x of targets) {
    await inject(tabId, x).catch(() => {});
    const r = await toFrame<AfFillResult>(tabId, x, { kw: "af", t: "fill", plan: { newPassword: value }, via, purpose: "generate" }).catch(() => null);
    if (r?.filled.length) return { filled: true };
  }
  return { filled: false, error: "No new-password field on this page" };
}

async function rememberValue(value: string) {
  try {
    const c = await unlockedCtx();
    await rememberGenerated(c.account.id, c.ring.user, value);
  } catch {}
}

async function generate(): Promise<string> {
  const p = await loadGeneratorPrefs();
  return generatePassword(p.password);
}

// ---------------------------------------------------------------- content-script messages
// One open menu per tab. The content script makes a random token, gives it to us and (by
// postMessage) to its menu frame; the frame proves which menu it is with that token.
interface MenuSession {
  tabId: number;
  target: Target;
  purpose: Purpose;
  token: string;
  at: number;
  /** the field takes passkeys (autocomplete "webauthn") */
  webauthn?: boolean;
}
const menus = new Map<number, MenuSession>();

async function menuSession(token: string | undefined): Promise<MenuSession | null> {
  if (!token || typeof token !== "string") return null;
  for (const s of menus.values()) if (s.token === token) return s;
  const tabId = await session.get<number>(`menuTok:${token}`);
  if (tabId == null) return null;
  const s = await session.get<MenuSession>(`menu:${tabId}`);
  return s?.token === token ? s : null;
}

async function onField(m: Extract<CsMessage, { t: "field" }>, sender: chrome.runtime.MessageSender): Promise<FieldReply> {
  const no = { icon: false, open: false };
  const tabId = sender.tab?.id;
  if (tabId == null) return no;
  const t = targetOf(sender);
  const settings = await loadSettings();
  if (!isWeb(t.url) || excluded(settings, t.url, sender.tab?.url)) return no;
  const accounts = await loadAccounts();
  if (!accounts.active) return no;
  if (!(await isUnlocked(accounts.active))) {
    // A locked vault can still restore a "never lock" key.
    try {
      await unlockedCtx();
    } catch (e) {
      if (e instanceof LockedError) return { icon: settings.autofill.inlineMenu && m.purpose !== null, open: false };
      return no;
    }
  }
  // The next step of a login started in this tab fills itself.
  if ((m.purpose === "login" || m.purpose === "otp") && (await continueFlow(tabId, t, m))) return { icon: settings.autofill.inlineMenu, open: false };
  if (!settings.autofill.inlineMenu) return no;
  switch (m.purpose) {
    case "login": {
      const ms = (await matchesFor(t.url)).filter((x) => x.type === CipherType.Login);
      // A page waiting for a passkey from this field's autofill: offer Keyward's.
      const pks = m.webauthn ? await conditionalPasskeys(tabId, t.frameId) : [];
      return { icon: true, open: settings.autofill.menuOnFocus && m.empty && ms.length + pks.length > 0 };
    }
    case "newPassword":
      return { icon: true, open: false };
    case "otp": {
      // A code field on a site with a TOTP login: offer the code right away (the page usually
      // focuses the field itself; split one-digit boxes are too narrow for the field icon).
      const has = (await matchesFor(t.url)).some((x) => x.totp);
      return { icon: has, open: has && settings.autofill.menuOnFocus && m.empty };
    }
    case "card":
      return { icon: (await itemsOfType(CipherType.Card)).length > 0, open: false };
    case "identity":
      return { icon: (await itemsOfType(CipherType.Identity)).length > 0, open: false };
  }
  return no;
}

async function onBootstrapFocus(sender: chrome.runtime.MessageSender) {
  const tabId = sender.tab?.id;
  const t = targetOf(sender);
  if (tabId == null || !isWeb(t.url)) return;
  const [settings, accounts] = await Promise.all([loadSettings(), loadAccounts()]);
  if (!accounts.active || excluded(settings, t.url, sender.tab?.url)) return;
  await inject(tabId, t).catch(() => {});
}

export function contentMessage(msg: any, sender: chrome.runtime.MessageSender, respond: (r: any) => void): boolean | void {
  if (msg?.kw !== "cs" || sender.tab?.id == null) return false;
  if (/^(chrome|moz)-extension:/.test(sender.url ?? "")) return false;
  const m = msg as CsMessage;
  const tabId = sender.tab.id;
  switch (m.t) {
    case "focus":
      void onBootstrapFocus(sender);
      return false;
    case "pageload":
      void fillOnPageLoad(tabId, targetOf(sender));
      return false;
    case "field":
      onField(m, sender).then(respond, () => respond(null));
      return true;
    case "menu": {
      if (typeof m.token !== "string" || m.token.length < 16) return false;
      const prev = menus.get(tabId);
      const s: MenuSession = { tabId, target: targetOf(sender), purpose: m.purpose, token: m.token, at: Date.now(), webauthn: m.webauthn === true };
      menus.set(tabId, s);
      void (async () => {
        if (prev) await session.remove(`menuTok:${prev.token}`);
        await session.setMany({ [`menu:${tabId}`]: s, [`menuTok:${m.token}`]: tabId });
      })().then(() => respond(true), () => respond(true));
      return true;
    }
    case "step":
      void continueFlow(tabId, targetOf(sender), m);
      return false;
    case "submit":
      void onSaveSubmit(m.data, sender);
      return false;
    case "submitDone":
      void onSaveSubmitDone(tabId);
      return false;
  }
  return false;
}

// ---------------------------------------------------------------- RPC (extension pages)
export interface MenuItem extends PageMatch {
  host: string | null;
}

async function cycleIndex(key: string, n: number): Promise<number> {
  const prev = await session.get<{ i: number; at: number }>(key);
  const i = prev && Date.now() - prev.at < 60_000 ? (prev.i + 1) % n : 0;
  await session.set(key, { i, at: Date.now() });
  return i;
}

export const autofillHandlers: Handlers = {
  "autofill.pageMatches": async ({ tabId, url }) => {
    const tab = tabId != null ? await chrome.tabs.get(tabId).catch(() => undefined) : await activeTab();
    const pageUrl = url ?? tab?.url ?? "";
    const parsed = parseUrl(pageUrl);
    const host = parsed && /^https?:$/.test(parsed.protocol) ? parsed.hostname : "";
    return { url: pageUrl, host, tabId: tab?.id, matches: host ? await matchesFor(pageUrl) : [] };
  },
  "autofill.fill": ({ tabId, itemId, force, verified }) => fillItem(tabId, itemId, { via: "popup", force, verified }),
  "menu.ctx": async ({ token }) => {
    const s = await menuSession(token);
    if (!s) throw new Error("No menu for this tab");
    const base = { tabId: s.tabId, frameId: s.target.frameId, purpose: s.purpose, host: hostOf(s.target.url) };
    try {
      await unlockedCtx();
    } catch (e) {
      if (e instanceof LockedError) return { ...base, locked: true, items: [], passkeys: [] };
      throw e;
    }
    const v = await vaultIndex();
    const withHost = (m: PageMatch): MenuItem => {
      const s = v.items.get(m.id);
      const u = s?.uris.map((x) => parseUrl(x)).find((p) => p && /^https?:$/.test(p.protocol));
      return { ...m, host: u?.hostname ?? null };
    };
    let items: PageMatch[] = [];
    if (s.purpose === "login" || s.purpose === "newPassword") items = (await matchesFor(s.target.url)).filter((m) => m.type === CipherType.Login);
    else if (s.purpose === "otp") items = (await matchesFor(s.target.url)).filter((m) => m.totp);
    else if (s.purpose === "card") items = await itemsOfType(CipherType.Card);
    else if (s.purpose === "identity") items = await itemsOfType(CipherType.Identity);
    const passkeys = s.purpose === "login" && s.webauthn ? await conditionalPasskeys(s.tabId, s.target.frameId) : [];
    return { ...base, locked: false, items: items.slice(0, 50).map(withHost), passkeys };
  },
  "menu.passkey": async ({ token, itemId, credentialId }, sender) => {
    const s = await menuSession(token);
    if (!s || s.purpose !== "login" || !s.webauthn) throw new Error("No menu for this tab");
    // As for a fill from the menu: nothing happens through a menu the page has hidden or covered.
    if (!(await toFrame<boolean>(s.tabId, s.target, { kw: "af", t: "menuTrusted" }).catch(() => false))) return { done: false, error: "The menu was hidden or covered; nothing was signed." };
    const r = await useConditional(s.tabId, s.target.frameId, String(itemId), String(credentialId), sender);
    if (!r.done && !r.dialog) return { done: false, error: "The page stopped waiting for a passkey" };
    await toFrame(s.tabId, s.target, { kw: "af", t: "menuClose" }).catch(() => {});
    return r;
  },
  "menu.pick": async ({ token, itemId, generated, force }) => {
    const s = await menuSession(token);
    if (!s) throw new Error("No menu for this tab");
    if (generated != null) {
      if (typeof generated !== "string" || !generated || generated.length > 256) throw new Error("Bad value");
      const r = await fillGenerated(s.tabId, s.target, generated, "menu");
      if (r.filled) await rememberValue(generated);
      return r;
    }
    const c = await unlockedCtx();
    const sum = (await vaultIndex()).items.get(itemId!);
    if (!sum) throw new Error("Item not found");
    if (sum.rp) return { filled: false, reprompt: true };
    if (sum.type === CipherType.Login && !(await frameAllowed(sum.id, s.target.url, (await chrome.tabs.get(s.tabId)).url ?? ""))) {
      return { filled: false, error: "This item doesn't match this site" };
    }
    void c;
    // force: the user accepted the menu's warning (an https item on an http page).
    return fillItem(s.tabId, sum.id, { via: "menu", target: s.target, purpose: s.purpose === "otp" ? "totp" : undefined, force: force === true });
  },
  // Pages framed in a website see the site's color scheme, not the system's: LibreWolf's
  // fingerprinting protection tells sites "light". Firefox's background is a real page and knows;
  // Chromium's service worker has no matchMedia, and there the frames already see the system's.
  "ui.dark": async () => (typeof matchMedia === "function" ? matchMedia("(prefers-color-scheme: dark)").matches : null),
  "ui.openPopup": async () => {
    await chrome.action.openPopup().catch(() => {});
  },
};

// ---------------------------------------------------------------- fill on page load
// Opt-in (Settings → Autofill). A frame with an empty password field asks once it loads; it gets
// a login only when exactly one matches, the item allows it, the frame is one the item may fill
// without asking (fillOnce's own rule for explicit fills), and only into empty fields.
const pageLoadDone = new Map<number, string>();
export const forgetPageLoad = (tabId: number) => pageLoadDone.delete(tabId);

async function fillOnPageLoad(tabId: number, t: Target): Promise<void> {
  const s = await loadSettings();
  if (!s.autofill.onPageLoad || !isWeb(t.url) || excluded(s, t.url)) return;
  let c: UnlockedCtx;
  try {
    c = await unlockedCtx();
  } catch {
    return;
  }
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (!tab?.url || excluded(s, tab.url)) return;
  const list = (await matchesFor(t.url)).filter((m) => m.type === CipherType.Login && !m.rp);
  if (list.length !== 1) return;
  const v = await loadView(c, list[0].id);
  if (v.login?.autofillOnPageLoad === false || !(await frameAllowed(v.id, t.url, tab.url))) return;
  // Once per frame and address: a page that redraws its form isn't filled over and over.
  const key = `${t.frameId}|${t.url}`;
  if (pageLoadDone.get(tabId) === key) return;
  pageLoadDone.set(tabId, key);
  await fillItem(tabId, v.id, { via: "pageload", target: t, purpose: "login" }).catch(() => {});
}

// ---------------------------------------------------------------- shortcuts and context menu
async function openPopupOrVault() {
  try {
    await chrome.action.openPopup();
  } catch {
    await chrome.tabs.create({ url: chrome.runtime.getURL("vault.html") });
  }
}

async function unlockedOrPopup(): Promise<boolean> {
  try {
    await unlockedCtx();
    return true;
  } catch {
    await openPopupOrVault();
    return false;
  }
}

async function cycleFill(tab: chrome.tabs.Tab, type: CipherType, via: FillVia, frame?: Target) {
  if (tab.id == null || !(await unlockedOrPopup())) return;
  const list = (type === CipherType.Login ? await matchesFor(frame?.url ?? tab.url ?? "") : await itemsOfType(type)).filter((m) => m.type === type && !m.rp);
  if (!list.length) {
    if (type === CipherType.Login) await openPopupOrVault();
    return;
  }
  const i = await cycleIndex(`cycle:${tab.id}:${type}`, list.length);
  const r = await fillItem(tab.id, list[i].id, { via, target: frame }).catch((e) => ({ filled: false, error: (e as Error).message }) as FillOutcome);
  // A shortcut has nowhere to ask (fill a frame of another site? master password?) or to say
  // what went wrong: the popup has this site's logins and asks itself.
  if (!r.filled) await openPopupOrVault();
}

export async function onAutofillCommand(cmd: string, tab?: chrome.tabs.Tab): Promise<void> {
  tab ??= await activeTab();
  if (!tab?.id) return;
  switch (cmd) {
    case "autofill_login":
      return cycleFill(tab, CipherType.Login, "hotkey");
    case "autofill_card":
      return cycleFill(tab, CipherType.Card, "hotkey");
    case "autofill_identity":
      return cycleFill(tab, CipherType.Identity, "hotkey");
    case "generate_password": {
      if (!(await unlockedOrPopup())) return;
      const value = await generate();
      await copy(value).catch(() => {});
      await fillGenerated(tab.id, undefined, value, "hotkey");
      await rememberValue(value);
      return;
    }
    case "lock_vault":
      return lock(undefined, true);
  }
}

export async function installContextMenus(): Promise<void> {
  await chrome.contextMenus.removeAll();
  const contexts: chrome.contextMenus.CreateProperties["contexts"] = ["editable", "page", "frame"];
  const add = (p: chrome.contextMenus.CreateProperties) => chrome.contextMenus.create(p, () => void chrome.runtime.lastError);
  add({ id: "kw", title: "Keyward", contexts });
  add({ id: "kw-fill", parentId: "kw", title: "Autofill login", contexts });
  add({ id: "kw-user", parentId: "kw", title: "Copy username", contexts });
  add({ id: "kw-pass", parentId: "kw", title: "Copy password", contexts });
  add({ id: "kw-totp", parentId: "kw", title: "Copy verification code", contexts });
  add({ id: "kw-sep1", parentId: "kw", type: "separator", contexts });
  add({ id: "kw-card", parentId: "kw", title: "Autofill card", contexts });
  add({ id: "kw-identity", parentId: "kw", title: "Autofill identity", contexts });
  add({ id: "kw-gen", parentId: "kw", title: "Generate password", contexts: ["editable"] });
}

export async function onContextMenu(info: chrome.contextMenus.OnClickData, tab?: chrome.tabs.Tab): Promise<void> {
  if (!tab?.id) return;
  const frame: Target | undefined = info.frameId != null && info.frameUrl ? { frameId: info.frameId, url: info.frameUrl } : info.frameId === 0 ? { frameId: 0, url: tab.url ?? "" } : undefined;
  const url = info.frameUrl ?? info.pageUrl ?? tab.url ?? "";
  switch (info.menuItemId) {
    case "kw-fill":
      return cycleFill(tab, CipherType.Login, "context", frame);
    case "kw-card":
      return cycleFill(tab, CipherType.Card, "context", frame);
    case "kw-identity":
      return cycleFill(tab, CipherType.Identity, "context", frame);
    case "kw-gen": {
      if (!(await unlockedOrPopup())) return;
      const value = await generate();
      await copy(value).catch(() => {});
      await fillGenerated(tab.id, frame, value, "context");
      await rememberValue(value);
      return;
    }
    case "kw-user":
    case "kw-pass":
    case "kw-totp": {
      if (!(await unlockedOrPopup())) return;
      const m = (await matchesFor(url)).filter((x) => x.type === CipherType.Login && !x.rp);
      if (!m.length) return openPopupOrVault();
      const c = await unlockedCtx();
      const v = await loadView(c, m[0].id);
      const text = info.menuItemId === "kw-user" ? v.login?.username : info.menuItemId === "kw-pass" ? v.login?.password : await totpFor(v);
      if (text) await copy(text, info.menuItemId !== "kw-user");
      return;
    }
  }
}

// ---------------------------------------------------------------- tabs: badge, flows, save prompts
let badgeTimer: ReturnType<typeof setTimeout> | null = null;
function scheduleBadge(tabId?: number) {
  if (badgeTimer) clearTimeout(badgeTimer);
  badgeTimer = setTimeout(() => void updateBadge(tabId), 150);
}

async function updateBadge(tabId?: number) {
  const tab = tabId != null ? await chrome.tabs.get(tabId).catch(() => undefined) : await activeTab();
  if (!tab?.id) return;
  let text = "";
  try {
    const [settings, accounts] = await Promise.all([loadSettings(), loadAccounts()]);
    if (settings.badgeCount && accounts.active && tab.url && (await isUnlocked(accounts.active))) {
      const n = (await matchesFor(tab.url)).length;
      text = n ? String(n > 9 ? "9+" : n) : "";
    }
  } catch {}
  await chrome.action.setBadgeText({ tabId: tab.id, text }).catch(() => {});
  if (text) await chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: "#5c6bc0" }).catch(() => {});
}

/** A page finished loading in a tab with a login in progress: fill its next step. */
async function flowOnLoad(tabId: number, url: string) {
  const flow = await getFlow(tabId);
  if (!flow || siteOf(url) !== flow.site) return;
  const t: Target = { frameId: 0, url };
  try {
    await inject(tabId, t);
    const scan = await toFrame<ScanResult>(tabId, t, { kw: "af", t: "scan" });
    const next = scan.scopes.find((s) => (s.hasPw && s.emptyPw) || (s.hasOtp && s.emptyOtp));
    if (next) await continueFlow(tabId, t, next);
    // Code fields drawn after load (single-page apps): watch for a minute.
    else await toFrame(tabId, t, { kw: "af", t: "watch", ms: 60_000 });
  } catch {}
}

export function onTabUpdated(tabId: number, change: chrome.tabs.OnUpdatedInfo, tab: chrome.tabs.Tab): void {
  if (change.status === "complete" || change.url) scheduleBadge(tabId);
  if (change.status === "complete" && isWeb(tab.url)) void flowOnLoad(tabId, tab.url!);
  void onSaveTab(tabId, change, tab);
}

export function onTabEvent(tabId: number, removed = false): void {
  if (!removed) return scheduleBadge(tabId);
  const tok = menus.get(tabId)?.token;
  menus.delete(tabId);
  void session.remove([...(tok ? [`menuTok:${tok}`] : []), `flow:${tabId}`, `menu:${tabId}`, `save:${tabId}`, `user:${tabId}`, `cycle:${tabId}:1`, `cycle:${tabId}:3`, `cycle:${tabId}:4`]);
}

export { loadView, siteOf, hostOf, inject, toFrame, type Target };
