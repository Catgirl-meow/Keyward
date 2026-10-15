// Bitwarden URI match semantics, with an index so a page lookup is O(1) instead of a scan
// over every item (the official extension's #15899 blow-up).
import { getDomain, parse } from "tldts";
import { UriMatch, type Summary } from "../vault/types.ts";

export interface ParsedUrl {
  href: string;
  protocol: string;
  host: string; // hostname[:port]
  hostname: string;
  domain: string | null; // eTLD+1, or hostname for IPs / localhost / single-label hosts
}

const NON_WEB = /^(chrome|chrome-extension|moz-extension|about|edge|brave|vivaldi|opera|file|data|javascript|view-source|devtools):/i;

export function parseUrl(raw: string | null | undefined): ParsedUrl | null {
  if (!raw) return null;
  let s = raw.trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:/i.test(s)) s = "http://" + s; // Bitwarden prefixes scheme-less URIs
  if (NON_WEB.test(s)) return null;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (!u.hostname) return null;
  const hostname = u.hostname.toLowerCase().replace(/\.$/, "");
  return { href: u.href, protocol: u.protocol, host: u.port ? `${hostname}:${u.port}` : hostname, hostname, domain: baseDomain(hostname) };
}

export function baseDomain(hostname: string): string | null {
  if (!hostname) return null;
  const p = parse(hostname, { allowPrivateDomains: true });
  if (p.isIp || !hostname.includes(".")) return hostname;
  return p.domain ?? getDomain(hostname) ?? hostname;
}

export function sameSite(a: string, b: string): boolean {
  const pa = parseUrl(a), pb = parseUrl(b);
  return !!pa && !!pb && pa.domain === pb.domain;
}

export function equivalentSet(domain: string | null, groups: string[][]): Set<string> {
  const s = new Set<string>();
  if (!domain) return s;
  s.add(domain);
  for (const g of groups) if (g.includes(domain)) for (const d of g) s.add(d);
  return s;
}

/** Does `itemUri` (with its match type) match the page? */
export function uriMatches(itemUri: string, match: number | null, page: ParsedUrl, defaultMatch = 0, equiv?: Set<string>): boolean {
  const m = match ?? defaultMatch;
  switch (m) {
    case UriMatch.Domain: {
      const u = parseUrl(itemUri);
      if (!u || !u.domain || !page.domain) return false;
      if (u.domain === page.domain) return true;
      return !!equiv && equiv.has(u.domain);
    }
    case UriMatch.Host: {
      const u = parseUrl(itemUri);
      return !!u && u.host === page.host;
    }
    case UriMatch.StartsWith:
      return page.href.startsWith(itemUri.trim()) || page.href.startsWith(parseUrl(itemUri)?.href ?? "\0");
    case UriMatch.Exact:
      return page.href === itemUri.trim() || page.href === parseUrl(itemUri)?.href;
    case UriMatch.RegularExpression:
      try {
        return new RegExp(itemUri, "i").test(page.href);
      } catch {
        return false;
      }
    default:
      return false;
  }
}

/**
 * Domain → item ids index over summaries. Domain/Host matches are looked up by key; the few
 * StartsWith/Exact/Regex URIs are kept in a short list and tested directly.
 */
export class MatchIndex {
  byDomain = new Map<string, Set<string>>();
  special: { id: string; uri: string; match: number }[] = [];
  readonly defaultMatch: number;
  readonly groups: string[][];

  constructor(items: Iterable<Summary>, defaultMatch = 0, groups: string[][] = []) {
    this.defaultMatch = defaultMatch;
    this.groups = groups;
    for (const s of items) this.add(s);
  }

  add(s: Summary) {
    if (s.del || s.arch || s.type !== 1) return; // trashed and archived items never autofill
    s.uris.forEach((uri, i) => {
      const m = s.match[i] ?? this.defaultMatch;
      if (m === UriMatch.Never) return;
      if (m === UriMatch.Domain || m === UriMatch.Host) {
        const d = parseUrl(uri)?.domain;
        if (!d) return;
        let set = this.byDomain.get(d);
        if (!set) this.byDomain.set(d, (set = new Set()));
        set.add(s.id);
      } else this.special.push({ id: s.id, uri, match: m });
    });
  }

  /** Returns ids of matching items with the URI that matched. */
  lookup(pageUrl: string, items: Map<string, Summary>): { id: string; uri: string }[] {
    const page = parseUrl(pageUrl);
    if (!page) return [];
    const equiv = equivalentSet(page.domain, this.groups);
    const out = new Map<string, string>();
    for (const d of equiv) {
      for (const id of this.byDomain.get(d) ?? []) {
        const s = items.get(id);
        if (!s) continue;
        const i = s.uris.findIndex((u, k) => uriMatches(u, s.match[k], page, this.defaultMatch, equiv));
        if (i >= 0) out.set(id, s.uris[i]);
      }
    }
    for (const sp of this.special) if (!out.has(sp.id) && uriMatches(sp.uri, sp.match, page, this.defaultMatch, equiv)) out.set(sp.id, sp.uri);
    return [...out].map(([id, uri]) => ({ id, uri }));
  }
}

export function faviconHost(uris: string[]): string | null {
  for (const u of uris) {
    const p = parseUrl(u);
    if (p && /^https?:$/.test(p.protocol)) return p.hostname;
  }
  return null;
}
