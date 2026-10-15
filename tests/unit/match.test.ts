import { describe, expect, it } from "vitest";
import { MatchIndex, parseUrl, uriMatches } from "../../src/core/url/match.ts";
import { search } from "../../src/core/vault/search.ts";
import type { Summary } from "../../src/core/vault/types.ts";

const sum = (id: string, name: string, uris: string[], match: (number | null)[] = [], extra: Partial<Summary> = {}): Summary => ({
  id, type: 1, name, sub: "", fav: false, folder: null, org: null, cols: [], uris, match, totp: false, pk: [], rp: false, att: false,
  del: null, arch: null, rev: null, created: null, pwRev: null, note: null, brand: null, err: null, ...extra,
});

describe("uri matching", () => {
  const page = parseUrl("https://login.accounts.example.co.uk:8443/signin?x=1")!;
  it("domain uses eTLD+1", () => {
    expect(page.domain).toBe("example.co.uk");
    expect(uriMatches("example.co.uk", null, page)).toBe(true);
    expect(uriMatches("https://www.example.co.uk", 0, page)).toBe(true);
    expect(uriMatches("https://evil-example.co.uk", 0, page)).toBe(false);
    expect(uriMatches("https://example.com", 0, page)).toBe(false);
  });
  it("host includes port; startsWith / exact / regex / never", () => {
    expect(uriMatches("https://login.accounts.example.co.uk:8443", 1, page)).toBe(true);
    expect(uriMatches("https://login.accounts.example.co.uk", 1, page)).toBe(false);
    expect(uriMatches("https://login.accounts.example.co.uk:8443/signin", 2, page)).toBe(true);
    expect(uriMatches("https://login.accounts.example.co.uk:8443/signin?x=1", 3, page)).toBe(true);
    expect(uriMatches("^https://login\\.", 4, page)).toBe(true);
    expect(uriMatches("example.co.uk", 5, page)).toBe(false);
  });
  it("ip and localhost compare by host", () => {
    expect(uriMatches("http://192.168.2.2:8006", 0, parseUrl("https://192.168.2.2:8006/#v1")!)).toBe(true);
    expect(uriMatches("http://localhost:3000", 0, parseUrl("http://localhost:8080")!)).toBe(true);
  });
  it("index finds equivalent domains and special matches without scanning", () => {
    const items = new Map([
      ["a", sum("a", "Google", ["https://accounts.google.com"])],
      ["b", sum("b", "YouTube", ["youtube.com"])],
      ["c", sum("c", "Exact", ["https://site.test/login"], [3])],
      ["d", sum("d", "Deleted", ["https://accounts.google.com"], [], { del: "2026-01-01" })],
    ]);
    const idx = new MatchIndex(items.values(), 0, [["google.com", "youtube.com"]]);
    expect(idx.lookup("https://www.youtube.com/watch", items).map((m) => m.id).sort()).toEqual(["a", "b"]);
    expect(idx.lookup("https://site.test/login", items).map((m) => m.id)).toEqual(["c"]);
    expect(idx.lookup("chrome://settings", items)).toEqual([]);
  });
});

describe("search", () => {
  const items = [
    sum("1", "GitHub", ["https://github.com"], [], { sub: "octocat", totp: true }),
    sum("2", "Госуслуги", ["https://www.gosuslugi.ru"], [], { sub: "+7 900" }),
    sum("3", "Bank", [], [], { type: 3, sub: "Visa, *4242", brand: "Visa" }),
    sum("4", "Old", [], [], { del: "2026-01-01" }),
  ];
  it("matches names, subtitles, uris, cyrillic and qualifiers", () => {
    expect(search(items, "git").map((h) => h.s.id)).toEqual(["1"]);
    expect(search(items, "госу").map((h) => h.s.id)).toEqual(["2"]);
    expect(search(items, "gosuslugi").map((h) => h.s.id)).toEqual(["2"]);
    expect(search(items, "has:totp").map((h) => h.s.id)).toEqual(["1"]);
    expect(search(items, "type:card visa").map((h) => h.s.id)).toEqual(["3"]);
    expect(search(items, "", { trash: true }).map((h) => h.s.id)).toEqual(["4"]);
    expect(search(items, "").map((h) => h.s.id)).toEqual(["3", "1", "2"]);
    expect(search(items, "hub")[0].nameHits).toEqual([[3, 6]]);
  });
});
