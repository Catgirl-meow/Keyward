// Interop with the official Bitwarden client (CLI 2026.10, Bitwarden's own crypto): items written
// by Keyward's core (the code the extension runs) must read back in `bw`, and items `bw` writes
// must decrypt in Keyward. Needs: npm install --prefix .cache/bwcli @bitwarden/cli
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { CERT, startTlsProxy } from "../lib/tlsproxy.ts";
import { decryptCipher, emptyView } from "../../src/core/vault/cipher.ts";
import { CipherType, FieldType, type CipherView } from "../../src/core/vault/types.ts";
import { generateEd25519 } from "../../src/core/ssh/keys.ts";
import { SERVER, importItems, login, randomPassword, register, sync, uniqueEmail, type Session } from "../lib/vw.ts";

const root = new URL("../..", import.meta.url).pathname;
const BW = join(root, ".cache/bwcli/node_modules/.bin/bw");
const email = uniqueEmail("interop");
const password = randomPassword();
const appdata = mkdtempSync(join(tmpdir(), "kw-bw-"));
let session = "";
let s: Session;
let proxy: Awaited<ReturnType<typeof startTlsProxy>> | null = null;
const bwEnv = () => ({ ...process.env, BITWARDENCLI_APPDATA_DIR: appdata, BW_NOINTERACTION: "true", NODE_EXTRA_CA_CERTS: CERT });

// Async on purpose: the TLS proxy lives in this process, a sync exec would deadlock it.
const run = promisify(execFile);
async function bw(args: string[], input?: string): Promise<string> {
  const p = run(BW, [...args, ...(session ? ["--session", session] : [])], { env: bwEnv(), encoding: "utf8", maxBuffer: 32 << 20 });
  if (input != null) p.child.stdin!.end(input);
  return (await p).stdout.trim();
}
const bwJson = async (args: string[], input?: string) => JSON.parse(await bw(args, input));
const encode = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64");

describe("interop with the official Bitwarden CLI", { skip: !existsSync(BW) && "bw CLI not installed" }, () => {
  let ssh: Awaited<ReturnType<typeof generateEd25519>>;

  before(async () => {
    await register(email, password);
    s = await login(email, password);
    ssh = await generateEd25519("interop");
    const items: CipherView[] = [
      emptyView(CipherType.Login, {
        name: "KW login",
        notes: "multi\nline",
        favorite: true,
        login: {
          username: "kw-user", password: "kw-Pass-1!", passwordRevisionDate: null, totp: "JBSWY3DPEHPK3PXP",
          uris: [{ uri: "https://kw.example.test/login", match: 1 as any }, { uri: "https://alt.example.test", match: null }],
          autofillOnPageLoad: null, fido2Credentials: [],
        },
        fields: [
          { type: FieldType.Text, name: "text", value: "plain", linkedId: null },
          { type: FieldType.Hidden, name: "hidden", value: "secret", linkedId: null },
          { type: FieldType.Boolean, name: "bool", value: "true", linkedId: null },
        ],
        passwordHistory: [{ password: "old-1", lastUsedDate: "2025-01-01T00:00:00.000Z" }],
      }),
      emptyView(CipherType.Card, { name: "KW card", card: { cardholderName: "Kay Ward", brand: "Visa", number: "4111111111111111", expMonth: "7", expYear: "2031", code: "123" } }),
      emptyView(CipherType.SecureNote, { name: "KW note", notes: "Кириллица и emoji 🔑" }),
      emptyView(CipherType.SshKey, { name: "KW ssh", sshKey: { privateKey: ssh.privateKey, publicKey: ssh.publicKey, keyFingerprint: ssh.fingerprint } }),
    ];
    const id = emptyView(CipherType.Identity, { name: "KW identity" });
    Object.assign(id.identity!, { firstName: "Kay", lastName: "Ward", email: "kay@example.test", country: "US" });
    items.push(id);
    await importItems(s, items);

    // bw only talks https: front the local server with a TLS proxy.
    proxy = await startTlsProxy(SERVER);
    await bw(["config", "server", proxy.url]);
    session = await bw(["login", email, password, "--raw"]);
    assert.ok(session.length > 20, "bw login failed");
    await bw(["sync"]);
  });

  after(() => proxy?.server.close());

  test("bw reads items written by Keyward", async () => {
    const list = await bwJson(["list", "items"]) as any[];
    const by = (n: string) => list.find((i) => i.name === n);
    const l = by("KW login");
    assert.ok(l, `bw sees: ${list.map((i) => i.name).join(", ")}`);
    assert.equal(l.login.username, "kw-user");
    assert.equal(l.login.password, "kw-Pass-1!");
    assert.equal(l.login.totp, "JBSWY3DPEHPK3PXP");
    assert.deepEqual(l.login.uris.map((u: any) => [u.uri, u.match ?? null]), [["https://kw.example.test/login", 1], ["https://alt.example.test", null]]);
    assert.equal(l.notes, "multi\nline");
    assert.equal(l.favorite, true);
    assert.deepEqual(l.fields.map((f: any) => [f.name, f.value, f.type]), [["text", "plain", 0], ["hidden", "secret", 1], ["bool", "true", 2]]);
    assert.equal(l.passwordHistory?.[0]?.password, "old-1");
    assert.equal(by("KW card").card.number, "4111111111111111");
    assert.equal(by("KW note").notes, "Кириллица и emoji 🔑");
    assert.equal(by("KW identity").identity.lastName, "Ward");
    const k = by("KW ssh");
    assert.ok(k, "ssh key item missing in bw");
    assert.equal(k.sshKey?.publicKey, ssh.publicKey);
    assert.equal(k.sshKey?.keyFingerprint, ssh.fingerprint);
  });

  test("Keyward reads items written by bw", async () => {
    const tpl = await bwJson(["get", "template", "item"]);
    const loginTpl = await bwJson(["get", "template", "item.login"]);
    const uriTpl = await bwJson(["get", "template", "item.login.uri"]);
    const item = {
      ...tpl,
      name: "BW login",
      notes: "from the official client",
      login: { ...loginTpl, username: "bw-user", password: "bw-Pass-2?", totp: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", uris: [{ ...uriTpl, uri: "https://bw.example.test", match: null }] },
      fields: [{ name: "bw-field", value: "v", type: 1 }],
    };
    await bw(["create", "item", encode(item)]);
    const noteTpl = await bwJson(["get", "template", "item.securenote"]);
    await bw(["create", "item", encode({ ...tpl, type: 2, name: "BW note", notes: "ünïcödé", login: null, secureNote: noteTpl })]);

    const data = await sync(s);
    const views = await Promise.all(data.ciphers.map((c: any) => decryptCipher(c, s.ring)));
    const v = views.find((x) => x.name === "BW login");
    assert.ok(v, `Keyward sees: ${views.map((x) => x.name).join(", ")}`);
    assert.deepEqual(v.errors, []);
    assert.equal(v.login?.username, "bw-user");
    assert.equal(v.login?.password, "bw-Pass-2?");
    assert.equal(v.login?.totp, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
    assert.equal(v.login?.uris[0]?.uri, "https://bw.example.test");
    assert.equal(v.fields[0]?.value, "v");
    assert.equal(views.find((x) => x.name === "BW note")?.notes, "ünïcödé");
  });

  test("bw edits an item Keyward wrote; Keyward still reads it", async () => {
    const l = ((await bwJson(["list", "items", "--search", "KW login"])) as any[]).find((i) => i.name === "KW login");
    l.login.password = "edited-by-bw";
    await bw(["edit", "item", l.id, encode(l)]);
    const data = await sync(s);
    const v = await decryptCipher(data.ciphers.find((c: any) => c.id === l.id), s.ring);
    assert.equal(v.login?.password, "edited-by-bw");
    assert.equal(v.fields.length, 3);
    assert.deepEqual(v.errors, []);
  });
});
