// Password / passphrase / username generation with rejection sampling (no modulo bias).

export interface PasswordOpts {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
  minDigits: number;
  minSymbols: number;
  avoidAmbiguous: boolean;
}

export interface PassphraseOpts {
  words: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export const DEFAULT_PASSWORD: PasswordOpts = { length: 20, upper: true, lower: true, digits: true, symbols: true, minDigits: 1, minSymbols: 1, avoidAmbiguous: false };
export const DEFAULT_PASSPHRASE: PassphraseOpts = { words: 5, separator: "-", capitalize: true, includeNumber: true };

const SETS = {
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lower: "abcdefghijklmnopqrstuvwxyz",
  digits: "0123456789",
  symbols: "!@#$%^&*",
};
const AMBIGUOUS = /[IlO01]/g;

export function randomInt(max: number): number {
  if (max <= 0) throw new Error("max must be positive");
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % max;
  }
}

function shuffle<T>(a: T[]): T[] {
  for (let i = a.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

export function generatePassword(o: PasswordOpts): string {
  const strip = (s: string) => (o.avoidAmbiguous ? s.replace(AMBIGUOUS, "") : s);
  const sets: string[] = [];
  const req: string[] = [];
  if (o.upper) sets.push(strip(SETS.upper)), req.push(strip(SETS.upper));
  if (o.lower) sets.push(strip(SETS.lower)), req.push(strip(SETS.lower));
  if (o.digits) {
    sets.push(strip(SETS.digits));
    for (let i = 0; i < Math.max(1, o.minDigits); i++) req.push(strip(SETS.digits));
  }
  if (o.symbols) {
    sets.push(SETS.symbols);
    for (let i = 0; i < Math.max(1, o.minSymbols); i++) req.push(SETS.symbols);
  }
  if (!sets.length) sets.push(SETS.lower), req.push(SETS.lower);
  const all = sets.join("");
  const len = Math.max(o.length, req.length, 4);
  const chars = req.map((s) => s[randomInt(s.length)]);
  while (chars.length < len) chars.push(all[randomInt(all.length)]);
  return shuffle(chars).join("");
}

let words: string[] | null = null;
export async function loadWords(): Promise<string[]> {
  if (!words) {
    const text = (await import("./eff-large.txt")).default as string;
    words = text.split("\n").map((w) => w.trim()).filter(Boolean);
  }
  return words;
}

export async function generatePassphrase(o: PassphraseOpts): Promise<string> {
  const list = await loadWords();
  const n = Math.max(3, o.words);
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    let w = list[randomInt(list.length)];
    if (o.capitalize) w = w[0].toUpperCase() + w.slice(1);
    out.push(w);
  }
  if (o.includeNumber) {
    const i = randomInt(n);
    out[i] += String(randomInt(10));
  }
  return out.join(o.separator);
}

/** Entropy estimate in bits for display next to the generator. */
export function passwordEntropy(o: PasswordOpts): number {
  let n = 0;
  if (o.upper) n += o.avoidAmbiguous ? 24 : 26;
  if (o.lower) n += o.avoidAmbiguous ? 25 : 26;
  if (o.digits) n += o.avoidAmbiguous ? 8 : 10;
  if (o.symbols) n += SETS.symbols.length;
  return Math.round(o.length * Math.log2(Math.max(n, 2)));
}

export function passphraseEntropy(o: PassphraseOpts): number {
  return Math.round(o.words * Math.log2(7776) + (o.includeNumber ? Math.log2(10 * o.words) : 0));
}

// ---- usernames ----
export type UsernameKind = "word" | "plus" | "catchall";
export async function generateUsername(kind: UsernameKind, opts: { email?: string; domain?: string; capitalize?: boolean; number?: boolean; site?: string }): Promise<string> {
  const rand = () => Array.from({ length: 8 }, () => "abcdefghijklmnopqrstuvwxyz0123456789"[randomInt(36)]).join("");
  if (kind === "plus") {
    const [user, dom] = (opts.email ?? "").split("@");
    if (!user || !dom) throw new Error("Enter your email address first");
    return `${user}+${opts.site ? opts.site.replace(/[^a-z0-9]/gi, "").toLowerCase() : rand()}@${dom}`;
  }
  if (kind === "catchall") {
    if (!opts.domain) throw new Error("Enter your catch-all domain first");
    return `${opts.site ? opts.site.replace(/[^a-z0-9]/gi, "").toLowerCase() : rand()}@${opts.domain.replace(/^@/, "")}`;
  }
  const list = await loadWords();
  let w = list[randomInt(list.length)];
  if (opts.capitalize) w = w[0].toUpperCase() + w.slice(1);
  return opts.number !== false ? w + String(randomInt(10000)).padStart(4, "0") : w;
}
