// Watchtower state for this page. The local checks run on the vault decrypted here and never
// leave it; the network checks run once the user asks for them. Results live in signals so the
// list of affected items and the way back keep them, and are dropped on lock or account switch.
//
// They are also kept in the vault's database, sealed with the vault key (app.ts, saveSealed), so
// a reopened popup shows them at once instead of checking the whole vault again. What is kept
// names no password: zxcvbn's scores and HIBP's counts are filed under an HMAC of the password
// with a key derived from the vault key, and only for passwords still in the vault.
import { effect, signal } from "@preact/signals";
import { hkdf, hmac, importHmacKey, sha256 } from "../../core/crypto/primitives.ts";
import { toB64, toHex, utf8 } from "../../core/util/bytes.ts";
import type { CipherView, Summary } from "../../core/vault/types.ts";
import { pwnedCount } from "../../core/watchtower/hibp.ts";
import { analyze, exposed, inactive2fa, parseTwoFaDirectory, type CheckId, type Finding, type Findings, type MatchRules, type TwoFaSite } from "../../core/watchtower/report.ts";
import type { ScoreReply, ScoreRequest } from "../../workers/zxcvbn.ts";
import { currentRing, equivalentDomains, items, loadSealed, openItem, saveSealed, settings, vaultOwner } from "./app.ts";

export type NetCheck = "exposed" | "inactive2fa";
export type NetState = { state: "idle" } | { state: "running"; done: number; total: number } | { state: "done" } | { state: "error"; message: string };

export interface Report {
  findings: Findings;
  /** What the local checks depended on (basisOf): a different one means the vault changed. */
  basis: string;
  total: number;
  at: number;
}

const IDLE: Record<NetCheck, NetState> = { exposed: { state: "idle" }, inactive2fa: { state: "idle" } };
export const report = signal<Report | null>(null);
export const reportError = signal<string | null>(null);
export const checking = signal(false);
/** Passwords zxcvbn is scoring for the report on screen; the weak-password card waits for them. */
export const scoring = signal<{ done: number; total: number } | null>(null);
export const net = signal<Record<NetCheck, NetState>>(IDLE);

export const TWOFA_DIRECTORY = "https://api.2fa.directory/v3/totp.json";
/** A breach count or the 2fa.directory list older than this is fetched again. */
const NET_TTL = 7 * 24 * 3600_000;
/** Bump when a change to the checks makes kept reports wrong. */
const REPORT_VERSION = 1;
const SAVED = "watchtower";
const SAVED_2FA = "watchtower-2fa";

interface Saved {
  v: number;
  report: Report;
  /** zxcvbn's scores by tag(password, inputs). */
  scores: Record<string, number>;
  /** HIBP's counts and when they were looked up, by tag(password); there once the user asked. */
  pwned?: Record<string, [count: number, at: number]>;
}
interface Saved2fa {
  at: number;
  sites: [string, TwoFaSite][];
}

let owner: string | null = null;
let generation = 0;
/** For the current owner: the kept report was read (or there was none). */
let restored: Promise<void> | null = null;
let scores = new Map<string, number>();
let pwned: Map<string, [number, number]> | null = null;
let twofa: { at: number; sites: Map<string, TwoFaSite> } | null = null;
let tagKey: Promise<CryptoKey> | null = null;

effect(() => {
  const id = vaultOwner.value;
  if (id === owner) return;
  owner = id;
  generation++;
  report.value = null;
  reportError.value = null;
  scoring.value = null;
  net.value = IDLE;
  restored = null;
  scores = new Map();
  pwned = null;
  twofa = null;
  tagKey = null;
});

/** An HMAC of `parts` under a key only this vault's key gives: names a password without holding it. */
async function tag(parts: unknown[]): Promise<string> {
  const ring = currentRing();
  if (!ring) throw new Error("The vault is locked");
  tagKey ??= hkdf(ring.user.raw, "keyward", "keyward-watchtower-v1", 32).then((k) => importHmacKey(k));
  return toB64((await hmac(await tagKey, utf8(JSON.stringify(parts)))).subarray(0, 16));
}

/** Everything the local checks depend on, hashed: the items' revisions, the match rules, the day. */
async function basisOf(sums: Map<string, Summary>, rules: MatchRules): Promise<string> {
  const rows = [...sums.values()].map((s) => [s.id, s.rev, s.pwRev, s.del, s.arch, s.err]).sort((a, b) => (a[0]! < b[0]! ? -1 : 1));
  // "Expiring cards" counts from today.
  const day = new Date().toDateString();
  return toHex(await sha256(JSON.stringify([REPORT_VERSION, day, rules.defaultMatch ?? null, rules.groups ?? [], rows])));
}

async function matchRules(): Promise<MatchRules> {
  return { defaultMatch: settings.value.defaultUriMatch, groups: await equivalentDomains() };
}

/** Puts back the report kept for this vault, once per page and vault. */
function restore(): Promise<void> {
  const gen = generation;
  return (restored ??= (async () => {
    const [s, t] = await Promise.all([loadSealed<Saved>(SAVED), loadSealed<Saved2fa>(SAVED_2FA)]);
    if (gen !== generation) return;
    if (t) twofa = { at: t.at, sites: new Map(t.sites) };
    if (s?.v !== REPORT_VERSION) return;
    scores = new Map(Object.entries(s.scores));
    pwned = s.pwned ? new Map(Object.entries(s.pwned)) : null;
    if (report.value) return;
    report.value = s.report;
    const f = s.report.findings;
    net.value = { exposed: f.exposed ? { state: "done" } : { state: "idle" }, inactive2fa: f.inactive2fa ? { state: "done" } : { state: "idle" } };
  })());
}

/** Keeps the report, the scores and the breach counts for the next time the popup opens. */
let saving = Promise.resolve();
function save(gen: number) {
  const id = owner;
  if (gen !== generation || !id || !report.value) return;
  const s: Saved = { v: REPORT_VERSION, report: report.value, scores: Object.fromEntries(scores), pwned: pwned ? Object.fromEntries(pwned) : undefined };
  saving = saving.then(() => saveSealed(id, SAVED, s)).catch(() => {});
}

/**
 * Shows the kept report, and checks the vault again if it changed since. Called while a
 * Watchtower screen is shown, whenever the item list changes.
 */
export async function ensureReport(): Promise<void> {
  const gen = generation;
  const basis = items.value;
  await restore();
  if (gen !== generation || checking.value) return;
  const r = report.value;
  if (r && r.basis === (await basisOf(basis, await matchRules()))) return;
  if (gen === generation && items.value === basis) await runReport();
}

const POOL = Math.max(1, Math.min(4, (navigator.hardwareConcurrency || 2) - 1));
const CHUNK = 50;
let pool: Worker[] = [];
let poolIdle: ReturnType<typeof setTimeout> | undefined;
let nextRequest = 0;

function stopPool() {
  for (const w of pool) w.terminate();
  pool = [];
}

function ask(w: Worker, pairs: [string, string[]][]): Promise<number[]> {
  const id = ++nextRequest;
  return new Promise<number[]>((resolve, reject) => {
    const done = () => {
      w.removeEventListener("message", onMessage);
      w.removeEventListener("error", onError);
    };
    const onMessage = (e: MessageEvent<ScoreReply>) => {
      if (e.data.id !== id) return;
      done();
      if ("error" in e.data) reject(new Error(e.data.error));
      else resolve(e.data.scores);
    };
    const onError = (e: ErrorEvent) => {
      done();
      reject(new Error(e.message || "The password checker stopped"));
    };
    w.addEventListener("message", onMessage);
    w.addEventListener("error", onError);
    w.postMessage({ id, pairs } satisfies ScoreRequest);
  });
}

/**
 * zxcvbn scores, worked out in Web Workers (src/workers/zxcvbn.ts): one takes up to 40 ms a
 * password, which on this page's thread froze the whole popup, so a big vault is split across a
 * few of them. Each holds zxcvbn's dictionaries while it works; they are stopped once idle for
 * half a minute so those don't stay in memory.
 */
async function scoreInWorkers(pairs: [string, string[]][], progress: (done: number) => void, stop: () => boolean): Promise<number[]> {
  if (!pairs.length) return [];
  clearTimeout(poolIdle);
  const n = Math.min(POOL, Math.ceil(pairs.length / CHUNK));
  while (pool.length < n) pool.push(new Worker(chrome.runtime.getURL("workers/zxcvbn.js")));
  const out = new Array<number>(pairs.length);
  let next = 0;
  let done = 0;
  try {
    await Promise.all(pool.slice(0, n).map(async (w) => {
      while (next < pairs.length && !stop()) {
        const at = next;
        next += CHUNK;
        const got = await ask(w, pairs.slice(at, at + CHUNK));
        got.forEach((s, i) => (out[at + i] = s));
        progress((done += got.length));
      }
    }));
  } catch (e) {
    next = pairs.length;
    stopPool();
    throw e;
  } finally {
    poolIdle = setTimeout(stopPool, 30_000);
  }
  if (stop()) throw new Error("stale");
  return out;
}

/** Every item decrypted, trash included; an item that fails to decrypt is left out. */
async function openAll(basis: Map<string, Summary>): Promise<CipherView[]> {
  const opened = await Promise.all([...basis.keys()].map((id) => openItem(id).catch(() => null)));
  return opened.flatMap((r) => (r ? [r.view] : []));
}

/**
 * Runs the local checks; what the network checks found is kept for items still in the vault,
 * and worked out again for changed passwords once the user has run them. The report goes on
 * screen before zxcvbn has scored the passwords it hasn't seen, and is completed after.
 * `force` ("Check again"): the network checks look everything up again too.
 */
export async function runReport(force = false): Promise<void> {
  if (checking.value) return;
  const gen = generation;
  const sums = items.value;
  checking.value = true;
  reportError.value = null;
  let views: CipherView[] = [];
  try {
    await restore();
    const rules = await matchRules();
    const [opened, basis] = await Promise.all([openAll(sums), basisOf(sums, rules)]);
    views = opened;
    if (gen !== generation) return;
    // analyze() wants a score at once: a first pass collects what it asks about.
    const asked = new Map<string, [string, string[]]>();
    analyze(views, (pw, inputs) => (asked.set(JSON.stringify([pw, inputs]), [pw, inputs]), 4), undefined, rules);
    const tags = new Map<string, string>();
    await Promise.all([...asked].map(async ([k, pair]) => tags.set(k, await tag(pair))));
    if (gen !== generation) return;
    const score = (pw: string, inputs: string[]) => scores.get(tags.get(JSON.stringify([pw, inputs]))!) ?? 4;
    const live = new Set(views.filter((v) => !v.deletedDate).map((v) => v.id));
    const publish = () => {
      const findings = analyze(views, score, undefined, rules);
      const prev = report.value?.findings ?? {};
      for (const c of ["exposed", "inactive2fa"] as const) if (prev[c]) findings[c] = prev[c]!.filter((f) => live.has(f.id));
      report.value = { findings, basis, total: live.size, at: Date.now() };
    };
    const unscored = [...asked].filter(([k]) => !scores.has(tags.get(k)!));
    if (unscored.length) {
      publish();
      scoring.value = { done: 0, total: unscored.length };
      const got = await scoreInWorkers(unscored.map(([, p]) => p), (done) => gen === generation && (scoring.value = { done, total: unscored.length }), () => gen !== generation);
      unscored.forEach(([k], i) => scores.set(tags.get(k)!, got[i]));
    }
    // Only scores of passwords still in the vault are kept.
    const used = new Set(tags.values());
    for (const t of scores.keys()) if (!used.has(t)) scores.delete(t);
    publish();
    save(gen);
  } catch (e) {
    if (gen === generation) reportError.value = (e as Error).message;
  } finally {
    if (gen === generation) {
      checking.value = false;
      scoring.value = null;
    }
  }
  if (gen !== generation || reportError.value) return;
  // The vault changed while we were checking it.
  if (items.value !== sums) return void ensureReport();
  // The network checks the user already ran follow the vault, from what was looked up before.
  if (pwned) void checkExposed(force, views);
  if (twofa) void checkInactive2fa(force, views);
}

/** Network checks under way: a second run of one waits for nothing and does nothing. */
const busy = new Set<string>();
async function once(c: NetCheck, run: (gen: number) => Promise<void>): Promise<void> {
  const gen = generation;
  const key = `${gen}:${c}`;
  if (busy.has(key)) return;
  busy.add(key);
  try {
    await run(gen);
  } finally {
    busy.delete(key);
  }
}

function setNet(c: NetCheck, s: NetState, gen: number) {
  if (gen === generation) net.value = { ...net.value, [c]: s };
}
function setFindings(c: CheckId, f: Finding[], gen: number) {
  if (gen === generation && report.value) report.value = { ...report.value, findings: { ...report.value.findings, [c]: f } };
}

/**
 * Breached passwords (HIBP): only the first 5 hex digits of each password's SHA-1 leave. A count
 * looked up in the last week is reused unless `force` ("Check again").
 */
export function checkExposed(force = false, opened?: CipherView[]): Promise<void> {
  return once("exposed", async (gen) => {
    try {
      await restore();
      const views = opened ?? (await openAll(items.value));
      if (gen !== generation) return;
      const known = pwned ?? new Map<string, [number, number]>();
      const now = Date.now();
      const passwords = [...new Set(views.filter((v) => !v.deletedDate && v.login?.password && v.viewPassword).map((v) => v.login!.password!))];
      const tags = new Map(await Promise.all(passwords.map(async (pw) => [pw, await tag(["hibp", pw])] as const)));
      const fresh = (pw: string) => {
        const k = known.get(tags.get(pw)!);
        return !force && !!k && now - k[1] < NET_TTL;
      };
      const total = passwords.filter((pw) => !fresh(pw)).length;
      let done = 0;
      if (total) setNet("exposed", { state: "running", done, total }, gen);
      const f = await exposed(views, async (pw) => {
        if (fresh(pw)) return known.get(tags.get(pw)!)![0];
        const n = await pwnedCount(pw);
        known.set(tags.get(pw)!, [n, Date.now()]);
        setNet("exposed", { state: "running", done: ++done, total }, gen);
        return n;
      });
      if (gen !== generation) return;
      const used = new Set(tags.values());
      for (const t of known.keys()) if (!used.has(t)) known.delete(t);
      pwned = known;
      setFindings("exposed", f, gen);
      setNet("exposed", { state: "done" }, gen);
      save(gen);
    } catch (e) {
      setNet("exposed", { state: "error", message: `Couldn't reach Have I Been Pwned: ${(e as Error).message}` }, gen);
    }
  });
}

/** Sites that offer one-time codes, from 2fa.directory's public list (downloaded whole, kept a week). */
export function checkInactive2fa(force = false, opened?: CipherView[]): Promise<void> {
  return once("inactive2fa", async (gen) => {
    try {
      await restore();
      let sites = twofa && !force && Date.now() - twofa.at < NET_TTL ? twofa.sites : null;
      if (!sites) {
        setNet("inactive2fa", { state: "running", done: 0, total: 1 }, gen);
        const r = await fetch(TWOFA_DIRECTORY, { credentials: "omit", cache: "no-cache" });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        sites = parseTwoFaDirectory(await r.json());
        if (gen !== generation) return;
        twofa = { at: Date.now(), sites };
        const id = owner;
        if (id) void saveSealed(id, SAVED_2FA, { at: twofa.at, sites: [...sites] } satisfies Saved2fa).catch(() => {});
      }
      setFindings("inactive2fa", inactive2fa(opened ?? (await openAll(items.value)), sites), gen);
      setNet("inactive2fa", { state: "done" }, gen);
      save(gen);
    } catch (e) {
      setNet("inactive2fa", { state: "error", message: `Couldn't load 2fa.directory: ${(e as Error).message}` }, gen);
    }
  });
}
