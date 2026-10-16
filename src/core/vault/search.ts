// Search, filter and sort over summaries. Plain loops over <=thousands of items stay well
// under a frame; no index library needed.
import { CipherType, GPG_KIND, kindOf, type ItemKind, type Summary } from "./types.ts";

export interface Filter {
  type?: ItemKind | null;
  folder?: string | null; // "none" = no folder
  collection?: string | null;
  org?: string | null; // "personal" = no org
  favorites?: boolean;
  trash?: boolean;
  archive?: boolean;
  totp?: boolean;
  passkeys?: boolean;
  attachments?: boolean;
}

export type SortKey = "name" | "modified" | "created" | "password";

export interface Hit {
  s: Summary;
  score: number;
  /** [start, end) ranges in name / sub to highlight */
  nameHits?: [number, number][];
  subHits?: [number, number][];
  /** where else the query matched, shown as a chip */
  context?: string;
}

const fold = (s: string) => s.normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase();

const QUALIFIERS: Record<string, (s: Summary, v: string) => boolean> = {
  type: (s, v) => ({ login: 1, note: 2, card: 3, identity: 4, ssh: 5, gpg: GPG_KIND } as Record<string, number>)[v] === kindOf(s),
  is: (s, v) => (v === "fav" || v === "favorite" ? s.fav : v === "reprompt" ? s.rp : v === "broken" ? !!s.err : false),
  has: (s, v) => (v === "totp" || v === "otp" ? s.totp : v === "passkey" ? s.pk.length > 0 : v === "attachment" ? s.att : v === "uri" ? s.uris.length > 0 : false),
};

function ranges(hay: string, needles: string[]): [number, number][] {
  const f = fold(hay);
  const out: [number, number][] = [];
  for (const n of needles) {
    let i = f.indexOf(n);
    while (i >= 0 && n) {
      out.push([i, i + n.length]);
      i = f.indexOf(n, i + n.length);
    }
  }
  return out.sort((a, b) => a[0] - b[0]);
}

export function passesFilter(s: Summary, f: Filter): boolean {
  if (f.trash) {
    if (!s.del) return false;
  } else if (s.del) return false;
  if (f.archive) {
    if (!s.arch) return false;
  } else if (s.arch && !f.trash) return false;
  if (f.type != null && kindOf(s) !== f.type) return false;
  if (f.favorites && !s.fav) return false;
  if (f.folder != null && (f.folder === "none" ? s.folder != null : s.folder !== f.folder)) return false;
  if (f.org != null && (f.org === "personal" ? s.org != null : s.org !== f.org)) return false;
  if (f.collection != null && !s.cols.includes(f.collection)) return false;
  if (f.totp && !s.totp) return false;
  if (f.passkeys && !s.pk.length) return false;
  if (f.attachments && !s.att) return false;
  return true;
}

// One collator for all comparisons: localeCompare with options builds a new one per call,
// which made sorting 2,000 names take ~200 ms.
const collator = new Intl.Collator(undefined, { sensitivity: "base", numeric: true });

export function search(items: Iterable<Summary>, query: string, filter: Filter = {}, sort: SortKey = "name", folderNames?: Map<string, string>): Hit[] {
  const raw = query.trim();
  const quals: [string, string][] = [];
  const terms: string[] = [];
  for (const tok of raw.split(/\s+/).filter(Boolean)) {
    const m = /^(type|is|has):(\S+)$/i.exec(tok);
    if (m) quals.push([m[1].toLowerCase(), m[2].toLowerCase()]);
    else terms.push(fold(tok));
  }
  const out: Hit[] = [];
  for (const s of items) {
    if (!passesFilter(s, filter)) continue;
    if (quals.some(([k, v]) => !QUALIFIERS[k](s, v))) continue;
    if (!terms.length) {
      out.push({ s, score: 0 });
      continue;
    }
    const name = fold(s.name);
    const sub = fold(s.sub);
    let score = 0;
    let context: string | undefined;
    let ok = true;
    for (const t of terms) {
      if (name.startsWith(t)) score += 100;
      else if (name.includes(t)) score += 60;
      else if (sub.includes(t)) score += 40;
      else {
        const uri = s.uris.find((u) => fold(u).includes(t));
        if (uri) {
          score += 30;
          context ??= uri.replace(/^https?:\/\//, "").replace(/\/$/, "");
          continue;
        }
        const folder = s.folder && folderNames?.get(s.folder);
        if (folder && fold(folder).includes(t)) {
          score += 15;
          context ??= `Folder: ${folder}`;
          continue;
        }
        if (s.note && fold(s.note).includes(t)) {
          score += 10;
          context ??= "Notes";
          continue;
        }
        if (s.brand && fold(s.brand).includes(t)) {
          score += 20;
          continue;
        }
        ok = false;
        break;
      }
    }
    if (!ok) continue;
    out.push({ s, score: score + (s.fav ? 5 : 0), nameHits: ranges(s.name, terms), subHits: ranges(s.sub, terms), context });
  }
  const byName = (a: Hit, b: Hit) => collator.compare(a.s.name, b.s.name);
  const date = (v: string | null) => (v ? Date.parse(v) || 0 : 0);
  out.sort((a, b) => {
    if (terms.length && b.score !== a.score) return b.score - a.score;
    switch (sort) {
      case "modified":
        return date(b.s.rev) - date(a.s.rev) || byName(a, b);
      case "created":
        return date(b.s.created) - date(a.s.created) || byName(a, b);
      case "password":
        return date(b.s.pwRev) - date(a.s.pwRev) || byName(a, b);
      default:
        return byName(a, b);
    }
  });
  return out;
}
