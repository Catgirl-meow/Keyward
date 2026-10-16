// Send crypto against node's own HKDF and PBKDF2 (the bw interop test checks the real format).
import { hkdfSync, pbkdf2Sync } from "node:crypto";
import { describe, expect, test } from "vitest";
import { SymKey } from "../../src/core/crypto/symkey.ts";
import { decryptSend, decryptSendAccess, encryptSend, inDays, parseSendLink, sendKey, sendLink, sendPasswordHash, sendStatus, SendType, type SendDraft, type RawSend } from "../../src/core/send/send.ts";
import { fromB64Url } from "../../src/core/util/bytes.ts";

const material = new Uint8Array(16).map((_, i) => i * 7 + 1);
const draft = (d: Partial<SendDraft> = {}): SendDraft => ({
  type: SendType.Text, name: "Wi-Fi", notes: "for the guests", text: { text: "hunter2 🔑", hidden: true },
  maxAccessCount: 3, expirationDate: null, deletionDate: inDays(7), disabled: false, hideEmail: true, ...d,
});

describe("send", () => {
  test("the Send key is HKDF-SHA256(material, 'bitwarden-send', 'send'), 64 bytes", async () => {
    const want = Buffer.from(hkdfSync("sha256", material, "bitwarden-send", "send", 64));
    expect(Buffer.from((await sendKey(material)).raw)).toEqual(want);
  });

  test("the password is PBKDF2-SHA256 with the material as salt, 100 000 rounds", async () => {
    expect(await sendPasswordHash("correct horse", material)).toBe(pbkdf2Sync("correct horse", material, 100_000, 32, "sha256").toString("base64"));
  });

  test("encrypt, then decrypt as the owner and as a recipient", async () => {
    const user = SymKey.random();
    const { body, material: m } = await encryptSend(draft(), user, "pw");
    expect(body.password).toBe(await sendPasswordHash("pw", m));
    expect(body.file).toBeNull();
    const raw = { ...body, id: "s1", accessId: "acc", accessCount: 1, password: "server-hash" } as unknown as RawSend;
    const v = await decryptSend(raw, user);
    expect(v).toMatchObject({ name: "Wi-Fi", notes: "for the guests", text: { text: "hunter2 🔑", hidden: true }, hasPassword: true, maxAccessCount: 3, accessCount: 1, hideEmail: true });
    expect(fromB64Url(v.material)).toEqual(m);
    // Editing keeps the material, so the link stays the same; no new password leaves it alone.
    const again = await encryptSend({ ...draft({ name: "Renamed" }), id: v.id, material: v.material }, user);
    expect(again.material).toEqual(m);
    expect(again.body.password).toBeNull();
    // The recipient has only the link.
    const link = sendLink("https://pass.example/", "acc", v.material);
    expect(link).toBe(`https://pass.example/#/send/acc/${v.material}`);
    const p = parseSendLink(link)!;
    expect(p.accessId).toBe("acc");
    const seen = await decryptSendAccess(raw as any, p.material);
    expect(seen.text?.text).toBe("hunter2 🔑");
  });

  test("a file Send carries only its encrypted name", async () => {
    const { body } = await encryptSend(draft({ type: SendType.File, text: null, fileName: "report.pdf" }), SymKey.random());
    expect(body.text).toBeNull();
    expect(String((body.file as any).fileName)).toMatch(/^2\./);
  });

  test("links: a server path is kept, junk is refused", () => {
    expect(parseSendLink("https://host.example/vault/#/send/abc/" + "AQID")?.server).toBe("https://host.example/vault");
    expect(parseSendLink("https://host.example/#/send/abc")).toBeNull();
    expect(parseSendLink("not a link")).toBeNull();
  });

  test("status: disabled, expired, used up, or how long it lasts", async () => {
    const now = Date.parse("2026-10-16T12:00:00Z");
    const base = await decryptSend({ ...(await encryptSend(draft(), SymKey.random())).body, id: "x", accessId: "a" } as any, SymKey.random()).catch(() => null);
    expect(base).toBeNull(); // another user's key can't open it
    const user = SymKey.random();
    const v = await decryptSend({ ...(await encryptSend(draft(), user)).body, id: "x", accessId: "a" } as any, user);
    const at = (p: Partial<typeof v>) => sendStatus({ ...v, ...p }, now);
    expect(at({ deletionDate: "2026-10-19T12:00:00Z" })).toEqual({ open: true, label: "Deletes in 3 days" });
    expect(at({ deletionDate: "2026-10-19T12:00:00Z", expirationDate: "2026-10-16T17:00:00Z" })).toEqual({ open: true, label: "Expires in 5 hours" });
    expect(at({ deletionDate: "2026-10-19T12:00:00Z", expirationDate: "2026-10-16T11:00:00Z" }).label).toBe("Expired");
    expect(at({ deletionDate: "2026-10-19T12:00:00Z", accessCount: 3 }).label).toBe("Maximum views reached");
    expect(at({ deletionDate: "2026-10-19T12:00:00Z", disabled: true }).label).toBe("Disabled");
  });
});

