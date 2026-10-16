// Watchtower's checks on hand-made items (the E2E test runs them on a real vault).
import { describe, expect, test } from "vitest";
import { analyze, exposed, inactive2fa, parseTwoFaDirectory, weakSshKey, type CheckId, type Findings } from "../../src/core/watchtower/report.ts";
import { quickStrength } from "../../src/core/watchtower/strength.ts";
import { emptyView } from "../../src/core/vault/cipher.ts";
import { CipherType, type CipherView } from "../../src/core/vault/types.ts";
import { toB64, utf8 } from "../../src/core/util/bytes.ts";
import { frontCode, unFrontCode } from "../../src/core/watchtower/frontcode.ts";

let n = 0;
function login(name: string, l: { user?: string; pw?: string | null; uris?: string[]; totp?: string }, more: Partial<CipherView> = {}): CipherView {
  return emptyView(CipherType.Login, {
    id: `id-${++n}`,
    name,
    login: { username: l.user ?? null, password: l.pw === undefined ? "Vq7#kT2!pZ9@wL4$" + n : l.pw, passwordRevisionDate: null, totp: l.totp ?? null, uris: (l.uris ?? ["https://site.example"]).map((uri) => ({ uri, match: null })), autofillOnPageLoad: null, fido2Credentials: [] },
    ...more,
  });
}
const card = (name: string, expMonth: string | null, expYear: string | null, number: string | null = "4111111111111111") =>
  emptyView(CipherType.Card, { id: `id-${++n}`, name, card: { cardholderName: "K", brand: "Visa", number, expMonth, expYear, code: "123" } });

const score = (pw: string) => quickStrength(pw);
const ids = (f: Findings, c: CheckId) => (f[c] ?? []).map((x) => x.id).sort();
const names = (f: Findings, c: CheckId, vs: CipherView[]) => ids(f, c).map((id) => vs.find((v) => v.id === id)!.name).sort();

/** An "ssh-rsa" public key line with a modulus of `bits` bits (the value doesn't matter). */
function rsaLine(bits: number): string {
  const str = (b: Uint8Array) => {
    const out = new Uint8Array(4 + b.length);
    new DataView(out.buffer).setUint32(0, b.length);
    out.set(b, 4);
    return out;
  };
  const nBytes = new Uint8Array(bits / 8 + 1).fill(0x5a);
  nBytes[0] = 0; // mpint sign byte
  nBytes[1] = 0xc1; // top bit set
  const blob = [str(utf8("ssh-rsa")), str(new Uint8Array([1, 0, 1])), str(nBytes)];
  const all = new Uint8Array(blob.reduce((s, b) => s + b.length, 0));
  let at = 0;
  for (const b of blob) (all.set(b, at), (at += b.length));
  return `ssh-rsa ${toB64(all)} test`;
}

describe("watchtower", () => {
  test("weak, reused, plain-http and duplicate logins", () => {
    const vs = [
      login("Weak", { pw: "password1" }),
      login("Reused A", { pw: "Shared-Pa55-Phrase!", uris: ["https://a.example"] }),
      login("Reused B", { pw: "Shared-Pa55-Phrase!", uris: ["https://b.example"] }),
      login("Plain", { uris: ["http://plain.example/login"] }),
      login("Router", { uris: ["http://192.168.2.1/"] }),
      login("NAS", { uris: ["http://nas.local:5000"] }),
      login("Dup", { user: "kay", pw: "Dup-Pa55-Word-9!", uris: ["https://dup.example"] }),
      login("dup ", { user: "kay", pw: "Dup-Pa55-Word-9!", uris: ["https://dup.example/other-path"] }),
      login("Hidden", { pw: "password1" }, { viewPassword: false }),
      login("Deleted", { pw: "password1" }, { deletedDate: "2026-10-01T00:00:00Z" }),
    ];
    const f = analyze(vs, score);
    expect(names(f, "weak", vs)).toEqual(["Weak"]);
    expect(names(f, "reused", vs)).toEqual(["Dup", "Reused A", "Reused B", "dup "]);
    expect(f.reused!.find((x) => x.id === vs[1].id)!.detail).toBe("Used in 2 items");
    expect(names(f, "insecure", vs)).toEqual(["Plain"]); // local addresses are left alone
    expect(names(f, "duplicates", vs)).toEqual(["Dup", "dup "]);
    expect(names(f, "trash", vs)).toEqual(["Deleted"]);
  });

  test("the weak check gets the username and site as words to avoid", () => {
    const seen: string[][] = [];
    analyze([login("Shop", { user: "kayward", uris: ["https://shop.example.co.uk/x"] })], (_pw, inputs) => (seen.push(inputs), 4));
    expect(seen[0]).toEqual(["kayward", "Shop", "example.co.uk"]);
  });

  test("incomplete, empty and expiring items", () => {
    const now = new Date(2026, 9, 16);
    const vs = [
      login("No password", { user: "kay", pw: null }),
      login("No site", { user: "kay", uris: [] }),
      login("Blank", { pw: null, uris: [] }),
      emptyView(CipherType.SecureNote, { id: "note-empty", name: "Empty note" }),
      emptyView(CipherType.SecureNote, { id: "note-full", name: "Note", notes: "text" }),
      card("Old card", "1", "2020"),
      card("Ends soon", "10", "26"),
      card("Fine card", "12", "2031"),
      card("No number", "12", "2031", null),
    ];
    const f = analyze(vs, score, now);
    expect(names(f, "incomplete", vs)).toEqual(["No number", "No password", "No site"]);
    expect(names(f, "empty", vs)).toEqual(["Blank", "Empty note"]);
    expect(f.expiring!.map((x) => x.detail).sort()).toEqual(["Expired 01/2020", "Expires 10/2026"]);
  });

  test("weak SSH keys: short RSA and DSA", () => {
    expect(weakSshKey(rsaLine(1024))).toBe("RSA 1024-bit (use at least 2048)");
    expect(weakSshKey(rsaLine(4096))).toBeNull();
    expect(weakSshKey("ssh-dss AAAAB3NzaC1kc3M= x")).toMatch(/DSA/);
    expect(weakSshKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== x")).toBeNull();
    const key = emptyView(CipherType.SshKey, { id: "ssh", name: "Old key", sshKey: { privateKey: "x", publicKey: rsaLine(1024), keyFingerprint: null } });
    expect(ids(analyze([key], score), "weakKeys")).toEqual(["ssh"]);
  });

  test("exposed: each distinct password asked once, every item using it reported", async () => {
    const vs = [login("A", { pw: "password1" }), login("B", { pw: "password1" }), login("C", { pw: "Unique-Pa55-Phrase!" })];
    const asked: string[] = [];
    const f = await exposed(vs, async (pw) => (asked.push(pw), pw === "password1" ? 12345 : 0));
    expect(asked.sort()).toEqual(["Unique-Pa55-Phrase!", "password1"]);
    expect(f.map((x) => x.id).sort()).toEqual([vs[0].id, vs[1].id].sort());
    expect(f[0].detail).toBe("Seen 12,345 times in data breaches");
  });

  test("inactive two-step login from 2fa.directory data", () => {
    const sites = parseTwoFaDirectory([
      ["Example", { domain: "example.com", "additional-domains": ["example.org"], documentation: "https://example.com/2fa" }],
      ["broken"],
    ]);
    const vs = [
      login("Has code", { uris: ["https://example.com"], totp: "JBSWY3DPEHPK3PXP" }),
      login("No code", { uris: ["https://accounts.example.com/login"] }),
      login("Other domain", { uris: ["https://example.org"] }),
      login("Unlisted", { uris: ["https://nothing.test"] }),
    ];
    expect(inactive2fa(vs, sites).map((x) => vs.find((v) => v.id === x.id)!.name).sort()).toEqual(["No code", "Other domain"]);
  });
});

describe("front coding (the build's zxcvbn dictionaries)", () => {
  test("zxcvbn's own lists come back word for word", async () => {
    const common = await import("@zxcvbn-ts/language-common");
    const words = (await import("@zxcvbn-ts/language-en/dist/commonWords.json.mjs" as string)).default as string[];
    for (const list of [common.dictionary["passwords-common"] as string[], words]) {
      expect(unFrontCode(frontCode(list))).toEqual(list);
    }
  });
  test("long shared prefixes and capital letters", () => {
    const list = ["a".repeat(40), "a".repeat(41), "b"];
    expect(unFrontCode(frontCode(list))).toEqual(list);
    expect(() => frontCode(["Abc"])).toThrow();
  });
});
