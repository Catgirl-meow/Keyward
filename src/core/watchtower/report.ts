// Watchtower: the vault's health checks. Everything here runs on decrypted items in the page,
// with no network; the two checks that need one (breached passwords via HIBP's k-anonymity
// range API, sites that offer two-step login via 2fa.directory) take their data as arguments.
import { baseDomain, parseUrl } from "../url/match.ts";
import { fromB64 } from "../util/bytes.ts";
import { CipherType, IDENTITY_FIELDS, type CipherView } from "../vault/types.ts";

export type CheckId =
  | "exposed"
  | "reused"
  | "weak"
  | "insecure"
  | "inactive2fa"
  | "duplicates"
  | "incomplete"
  | "expiring"
  | "weakKeys"
  | "empty"
  | "trash";

/** An affected item, with what is wrong with it ("Used in 3 items", "Expired 01/2020"). */
export interface Finding {
  id: string;
  detail: string;
}

export type Findings = Partial<Record<CheckId, Finding[]>>;

/** zxcvbn-style score 0 (very weak) … 4 (strong); `inputs`: words the password shouldn't lean on. */
export type ScoreFn = (password: string, inputs: string[]) => number;

const live = (v: CipherView) => !v.deletedDate;
/** Items whose password the user may see (an org can hide them): only those are judged on it. */
const withPassword = (v: CipherView) => live(v) && v.type === CipherType.Login && !!v.login?.password && v.viewPassword;

const hostOf = (uri: string) => parseUrl(uri)?.hostname ?? null;

/** Addresses where TLS is often impossible (a router, a NAS): not flagged for plain http. */
function localHost(h: string): boolean {
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".lan") || h.endsWith(".home.arpa")) return true;
  const m = h.match(/^(\d+)\.(\d+)\.\d+\.\d+$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
  }
  return h === "[::1]" || /^\[f[cd]/i.test(h) || /^\[fe80:/i.test(h);
}

function groups<K>(views: CipherView[], key: (v: CipherView) => K | null): CipherView[][] {
  const m = new Map<K, CipherView[]>();
  for (const v of views) {
    const k = key(v);
    if (k == null) continue;
    let g = m.get(k);
    if (!g) m.set(k, (g = []));
    g.push(v);
  }
  return [...m.values()].filter((g) => g.length > 1);
}

const plural = (n: number, one: string, many = one + "s") => `${n} ${n === 1 ? one : many}`;

function isEmpty(v: CipherView): boolean {
  if (v.notes?.trim() || v.fields.some((f) => f.value?.trim()) || v.attachments.length) return false;
  switch (v.type) {
    case CipherType.Login: {
      const l = v.login;
      return !l || (!l.username?.trim() && !l.password && !l.totp && !l.uris.some((u) => u.uri.trim()) && !l.fido2Credentials.length);
    }
    case CipherType.Card:
      return !v.card || Object.values(v.card).every((x) => !x?.trim());
    case CipherType.Identity:
      return !v.identity || IDENTITY_FIELDS.every((k) => !v.identity![k]?.trim());
    case CipherType.SshKey:
      return !v.sshKey?.privateKey && !v.sshKey?.publicKey;
    default:
      return true; // a note with no text, no fields, no files
  }
}

function incomplete(v: CipherView): string | null {
  if (isEmpty(v)) return null; // reported as empty instead
  if (v.type === CipherType.Login && v.login) {
    const l = v.login;
    if (!l.password && !l.fido2Credentials.length) return "No password or passkey";
    if (!l.uris.some((u) => u.uri.trim())) return "No website, so it can't be filled";
  }
  if (v.type === CipherType.Card && v.card) {
    if (!v.card.number?.trim()) return "No card number";
    if (!v.card.expMonth || !v.card.expYear) return "No expiry date";
  }
  return null;
}

/** "Expired 01/2020" / "Expires 07/2031" for a card that ends within a month (or has ended). */
function expiry(v: CipherView, now: Date): string | null {
  const c = v.card;
  if (v.type !== CipherType.Card || !c?.expMonth || !c.expYear) return null;
  const month = Number(c.expMonth);
  let year = Number(c.expYear);
  if (!(month >= 1 && month <= 12) || !(year > 0)) return null;
  if (year < 100) year += 2000;
  const end = new Date(year, month, 1); // the first day after the expiry month
  const mm = String(month).padStart(2, "0");
  if (end <= now) return `Expired ${mm}/${year}`;
  const soon = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 31);
  return end <= soon ? `Expires ${mm}/${year}` : null;
}

function rd(b: Uint8Array, at: number): [Uint8Array, number] {
  const n = (b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3];
  return [b.subarray(at + 4, at + 4 + n), at + 4 + n];
}

/** A weak SSH key's description ("RSA 1024-bit", "DSA"), or null. Reads the public key line. */
export function weakSshKey(publicKey: string | null | undefined): string | null {
  const [type, b64] = (publicKey ?? "").trim().split(/\s+/);
  if (type === "ssh-dss") return "DSA keys are no longer considered safe";
  if (type !== "ssh-rsa" || !b64) return null;
  try {
    const blob = fromB64(b64);
    let [, at] = rd(blob, 0); // "ssh-rsa"
    [, at] = rd(blob, at); // e
    const [n] = rd(blob, at);
    let i = 0;
    while (i < n.length && n[i] === 0) i++;
    const bits = (n.length - i) * 8 - (n[i] ? Math.clz32(n[i]) - 24 : 0);
    return bits < 2048 ? `RSA ${bits}-bit (use at least 2048)` : null;
  } catch {
    return null;
  }
}

/** The checks that need no network. `score`: zxcvbn's (or a quick estimate). */
export function analyze(views: CipherView[], score: ScoreFn, now = new Date()): Findings {
  const f: Findings = {};
  const add = (c: CheckId, id: string, detail: string) => (f[c] ??= []).push({ id, detail });
  const items = views.filter(live);

  for (const g of groups(items.filter(withPassword), (v) => v.login!.password!)) for (const v of g) add("reused", v.id, `Used in ${plural(g.length, "item")}`);

  for (const v of items.filter(withPassword)) {
    const l = v.login!;
    const inputs = [l.username ?? "", v.name, ...l.uris.map((u) => baseDomain(hostOf(u.uri) ?? "") ?? "")].filter(Boolean);
    const s = score(l.password!, inputs);
    if (s <= 2) add("weak", v.id, ["Very weak", "Weak", "Could be guessed"][s] ?? "Weak");
  }

  for (const v of items) {
    if (v.type !== CipherType.Login) continue;
    const plain = v.login?.uris.map((u) => u.uri.trim()).find((u) => /^http:\/\//i.test(u) && !localHost(hostOf(u) ?? ""));
    if (plain) add("insecure", v.id, `${hostOf(plain)} without https`);
  }

  // Same kind, name, username, sites and password: one is a stray copy.
  const sig = (v: CipherView) => {
    if (v.type !== CipherType.Login || !v.login) return null;
    const hosts = v.login.uris.map((u) => hostOf(u.uri) ?? u.uri).sort().join(" ");
    return JSON.stringify([v.name.trim().toLowerCase(), v.login.username ?? "", hosts, v.login.password ?? ""]);
  };
  for (const g of groups(items, sig)) for (const v of g) add("duplicates", v.id, `${plural(g.length, "copy", "copies")} of this login`);

  for (const v of items) {
    if (isEmpty(v)) add("empty", v.id, "Nothing saved in it");
    const why = incomplete(v);
    if (why) add("incomplete", v.id, why);
    const exp = expiry(v, now);
    if (exp) add("expiring", v.id, exp);
    if (v.type === CipherType.SshKey) {
      const weak = weakSshKey(v.sshKey?.publicKey);
      if (weak) add("weakKeys", v.id, weak);
    }
  }

  for (const v of views) if (v.deletedDate) add("trash", v.id, `Deleted ${new Date(v.deletedDate).toLocaleDateString()}`);
  return f;
}

/** Breached passwords: `count` looks one up (HIBP); each distinct password is asked once. */
export async function exposed(views: CipherView[], count: (password: string) => Promise<number>): Promise<Finding[]> {
  const byPassword = new Map<string, CipherView[]>();
  for (const v of views.filter(withPassword)) {
    const pw = v.login!.password!;
    byPassword.set(pw, [...(byPassword.get(pw) ?? []), v]);
  }
  const out: Finding[] = [];
  for (const [pw, vs] of byPassword) {
    const n = await count(pw);
    if (n > 0) for (const v of vs) out.push({ id: v.id, detail: `Seen ${n.toLocaleString("en")} times in data breaches` });
  }
  return out;
}

/** One site that offers a one-time-code (TOTP) second step, from 2fa.directory's totp.json. */
export interface TwoFaSite {
  domain: string;
  documentation?: string;
}

/** 2fa.directory's v3 totp.json: [[name, {domain, "additional-domains"?, documentation?}], …]. */
export function parseTwoFaDirectory(json: unknown): Map<string, TwoFaSite> {
  const m = new Map<string, TwoFaSite>();
  if (!Array.isArray(json)) return m;
  for (const e of json) {
    const s = Array.isArray(e) ? e[1] : null;
    if (!s || typeof s.domain !== "string") continue;
    const site = { domain: s.domain, documentation: typeof s.documentation === "string" ? s.documentation : undefined };
    for (const d of [s.domain, ...(Array.isArray(s["additional-domains"]) ? s["additional-domains"] : [])]) if (typeof d === "string") m.set(d.toLowerCase(), site);
  }
  return m;
}

/** Logins without a TOTP secret on sites that offer one (passkeys count as a second factor too). */
export function inactive2fa(views: CipherView[], sites: Map<string, TwoFaSite>): Finding[] {
  const out: Finding[] = [];
  for (const v of views) {
    if (!live(v) || v.type !== CipherType.Login || !v.login || v.login.totp || v.login.fido2Credentials.length) continue;
    for (const u of v.login.uris) {
      const h = hostOf(u.uri);
      const site = h && (sites.get(h) ?? sites.get(baseDomain(h) ?? ""));
      if (site) {
        out.push({ id: v.id, detail: `${site.domain} offers two-step login` });
        break;
      }
    }
  }
  return out;
}
