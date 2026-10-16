// Watchtower state for this page. The local checks run on the vault decrypted here and never
// leave it; the two network checks run only when the user asks. Results live in signals so the
// list of affected items and the way back keep them, and are dropped on lock or account switch.
import { effect, signal } from "@preact/signals";
import type { CipherView, Summary } from "../../core/vault/types.ts";
import { pwnedCount } from "../../core/watchtower/hibp.ts";
import { analyze, exposed, inactive2fa, parseTwoFaDirectory, type CheckId, type Finding, type Findings, type ScoreFn } from "../../core/watchtower/report.ts";
import { unFrontCode } from "../../core/watchtower/frontcode.ts";
import { items, openItem, vaultOwner } from "./app.ts";

export type NetCheck = "exposed" | "inactive2fa";
export type NetState = { state: "idle" } | { state: "running"; done: number; total: number } | { state: "done" } | { state: "error"; message: string };

export interface Report {
  findings: Findings;
  /** The item map the report was made from: a different one means the vault changed. */
  basis: Map<string, Summary>;
  total: number;
  at: number;
}

const IDLE: Record<NetCheck, NetState> = { exposed: { state: "idle" }, inactive2fa: { state: "idle" } };
export const report = signal<Report | null>(null);
export const reportError = signal<string | null>(null);
export const checking = signal(false);
export const net = signal<Record<NetCheck, NetState>>(IDLE);

export const TWOFA_DIRECTORY = "https://api.2fa.directory/v3/totp.json";

let owner: string | null = null;
let generation = 0;
effect(() => {
  const id = vaultOwner.value;
  if (id === owner) return;
  owner = id;
  generation++;
  report.value = null;
  reportError.value = null;
  net.value = IDLE;
});

let scorer: Promise<ScoreFn> | null = null;
/**
 * zxcvbn with common passwords, keyboard patterns and English words and first names, loaded
 * only here. The build gzips the dictionaries (scripts/build.ts, writeZxcvbnData) to keep the
 * extension under 2 MB; surnames and Wikipedia words are left out for the same reason.
 */
function zxcvbnScore(): Promise<ScoreFn> {
  return (scorer ??= Promise.all([import("@zxcvbn-ts/core"), zxcvbnData()]).then(([{ ZxcvbnFactory }, { graphs, dictionary }]) => {
    const z = new ZxcvbnFactory({ graphs, dictionary });
    return (pw: string, inputs: string[]) => z.check(pw, inputs).score;
  })).catch((e) => {
    scorer = null;
    throw e;
  });
}

async function zxcvbnData(): Promise<{ graphs: any; dictionary: Record<string, string[]> }> {
  const res = await fetch("/data/zxcvbn.json.gz");
  if (!res.ok || !res.body) throw new Error("Password dictionaries are missing");
  const data = await new Response(res.body.pipeThrough(new DecompressionStream("gzip"))).json();
  return { graphs: data.graphs, dictionary: Object.fromEntries(Object.entries(data.lists as Record<string, string>).map(([k, v]) => [k, unFrontCode(v)])) };
}

/** Every item decrypted, trash included; an item that fails to decrypt is left out. */
async function openAll(basis: Map<string, Summary>): Promise<CipherView[]> {
  const opened = await Promise.all([...basis.keys()].map((id) => openItem(id).catch(() => null)));
  return opened.flatMap((r) => (r ? [r.view] : []));
}

/** Runs the local checks; what the network checks found is kept for items still in the vault. */
export async function runReport(): Promise<void> {
  if (checking.value) return;
  const gen = generation;
  const basis = items.value;
  checking.value = true;
  reportError.value = null;
  try {
    const [score, views] = await Promise.all([zxcvbnScore(), openAll(basis)]);
    if (gen !== generation) return;
    const findings = analyze(views, score);
    const live = new Set(views.filter((v) => !v.deletedDate).map((v) => v.id));
    const prev = report.value?.findings ?? {};
    for (const c of ["exposed", "inactive2fa"] as const) if (prev[c]) findings[c] = prev[c]!.filter((f) => live.has(f.id));
    report.value = { findings, basis, total: live.size, at: Date.now() };
  } catch (e) {
    if (gen === generation) reportError.value = (e as Error).message;
  } finally {
    checking.value = false;
  }
  // The vault changed while we were checking it.
  if (gen === generation && items.value !== basis) void runReport();
}

function setNet(c: NetCheck, s: NetState, gen: number) {
  if (gen === generation) net.value = { ...net.value, [c]: s };
}
function setFindings(c: CheckId, f: Finding[], gen: number) {
  if (gen === generation && report.value) report.value = { ...report.value, findings: { ...report.value.findings, [c]: f } };
}

/** Breached passwords (HIBP): only the first 5 hex digits of each password's SHA-1 leave. */
export async function checkExposed(): Promise<void> {
  const gen = generation;
  const views = await openAll(items.value);
  const total = new Set(views.filter((v) => !v.deletedDate && v.login?.password && v.viewPassword).map((v) => v.login!.password)).size;
  let done = 0;
  setNet("exposed", { state: "running", done, total }, gen);
  try {
    const f = await exposed(views, async (pw) => {
      const n = await pwnedCount(pw);
      setNet("exposed", { state: "running", done: ++done, total }, gen);
      return n;
    });
    setFindings("exposed", f, gen);
    setNet("exposed", { state: "done" }, gen);
  } catch (e) {
    setNet("exposed", { state: "error", message: `Couldn't reach Have I Been Pwned: ${(e as Error).message}` }, gen);
  }
}

/** Sites that offer one-time codes, from 2fa.directory's public list (downloaded whole). */
export async function checkInactive2fa(): Promise<void> {
  const gen = generation;
  setNet("inactive2fa", { state: "running", done: 0, total: 1 }, gen);
  try {
    const r = await fetch(TWOFA_DIRECTORY, { credentials: "omit", cache: "no-cache" });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const sites = parseTwoFaDirectory(await r.json());
    setFindings("inactive2fa", inactive2fa(await openAll(items.value), sites), gen);
    setNet("inactive2fa", { state: "done" }, gen);
  } catch (e) {
    setNet("inactive2fa", { state: "error", message: `Couldn't load 2fa.directory: ${(e as Error).message}` }, gen);
  }
}
