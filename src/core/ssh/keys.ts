// OpenSSH private-key parsing/serialisation and WebCrypto key import for signing.
// Supports unencrypted ed25519, ecdsa-sha2-nistp{256,384,521} and ssh-rsa keys (the formats
// Bitwarden stores for SSH-key items).
import { sha256 } from "../crypto/primitives.ts";
import { concat, fromB64, randomBytes, toB64, utf8 } from "../util/bytes.ts";

// ---------- wire helpers ----------
export class Reader {
  o = 0;
  readonly b: Uint8Array;
  constructor(b: Uint8Array) {
    this.b = b;
  }
  u32(): number {
    if (this.o + 4 > this.b.length) throw new Error("truncated");
    const v = ((this.b[this.o] << 24) | (this.b[this.o + 1] << 16) | (this.b[this.o + 2] << 8) | this.b[this.o + 3]) >>> 0;
    this.o += 4;
    return v;
  }
  bytes(n: number): Uint8Array {
    if (this.o + n > this.b.length) throw new Error("truncated");
    const v = this.b.subarray(this.o, this.o + n);
    this.o += n;
    return v;
  }
  str(): Uint8Array {
    return this.bytes(this.u32());
  }
  text(): string {
    return new TextDecoder().decode(this.str());
  }
  get done() {
    return this.o >= this.b.length;
  }
}

export function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}
export function sshString(b: Uint8Array | string): Uint8Array {
  const v = typeof b === "string" ? utf8(b) : b;
  return concat(u32(v.length), v);
}
/** SSH mpint: big-endian two's complement, minimal, with a leading 0 if the top bit is set. */
export function mpint(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  let v = b.subarray(i);
  if (v[0] & 0x80) v = concat(new Uint8Array([0]), v);
  return sshString(v);
}

const b64u = (b: Uint8Array) => toB64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unpad = (b: Uint8Array) => {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
};
const pad = (b: Uint8Array, n: number) => (b.length >= n ? b.subarray(b.length - n) : concat(new Uint8Array(n - b.length), b));

// ---------- parsed key ----------
export interface SshKey {
  type: "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" | "ssh-rsa";
  publicBlob: Uint8Array;
  comment: string;
  // private parts
  ed25519Seed?: Uint8Array;
  ecdsa?: { curve: "P-256" | "P-384" | "P-521"; Q: Uint8Array; d: Uint8Array };
  rsa?: { n: Uint8Array; e: Uint8Array; d: Uint8Array; iqmp: Uint8Array; p: Uint8Array; q: Uint8Array };
}

const CURVES = { nistp256: ["P-256", 32], nistp384: ["P-384", 48], nistp521: ["P-521", 66] } as const;

export function parseOpenSshPrivateKey(pem: string): SshKey {
  const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/.exec(pem);
  if (!m) throw new Error("Not an OpenSSH private key");
  const raw = fromB64(m[1].replace(/\s+/g, ""));
  const magic = utf8("openssh-key-v1\0");
  if (!magic.every((c, i) => raw[i] === c)) throw new Error("Bad OpenSSH key header");
  const r = new Reader(raw.subarray(magic.length));
  const cipher = r.text();
  r.text(); // kdfname
  r.str(); // kdfoptions
  if (cipher !== "none") throw new Error("Passphrase-protected keys are not supported — remove the passphrase first (ssh-keygen -p)");
  const n = r.u32();
  if (n !== 1) throw new Error("Multiple keys in one file are not supported");
  const publicBlob = r.str();
  const p = new Reader(r.str());
  if (p.u32() !== p.u32()) throw new Error("Corrupt private key (check bytes differ)");
  const type = p.text() as SshKey["type"];
  let key: SshKey;
  if (type === "ssh-ed25519") {
    p.str(); // pk
    const sk = p.str();
    key = { type, publicBlob, comment: "", ed25519Seed: sk.slice(0, 32) };
  } else if (type.startsWith("ecdsa-sha2-")) {
    const curveName = p.text() as keyof typeof CURVES;
    const Q = p.str();
    const d = p.str();
    const c = CURVES[curveName];
    if (!c) throw new Error(`Unsupported curve ${curveName}`);
    key = { type, publicBlob, comment: "", ecdsa: { curve: c[0], Q: Q.slice(), d: pad(unpad(d), c[1]).slice() } };
  } else if (type === "ssh-rsa") {
    const n2 = p.str(), e = p.str(), d = p.str(), iqmp = p.str(), pp = p.str(), q = p.str();
    key = { type, publicBlob, comment: "", rsa: { n: n2.slice(), e: e.slice(), d: d.slice(), iqmp: iqmp.slice(), p: pp.slice(), q: q.slice() } };
  } else throw new Error(`Unsupported key type ${type}`);
  key.comment = p.text();
  return key;
}

export async function fingerprint(publicBlob: Uint8Array): Promise<string> {
  return "SHA256:" + toB64(await sha256(publicBlob)).replace(/=+$/, "");
}

export function publicKeyLine(k: Pick<SshKey, "type" | "publicBlob" | "comment">): string {
  return `${k.type} ${toB64(k.publicBlob)}${k.comment ? " " + k.comment : ""}`;
}

export async function describeOpenSshPrivateKey(pem: string): Promise<{ publicKey: string; fingerprint: string; type: string } | null> {
  if (!pem.includes("BEGIN OPENSSH PRIVATE KEY")) return null;
  const k = parseOpenSshPrivateKey(pem);
  return { publicKey: publicKeyLine({ ...k, comment: "" }), fingerprint: await fingerprint(k.publicBlob), type: k.type };
}

function wrapPem(body: Uint8Array): string {
  const b = toB64(body).replace(/(.{70})/g, "$1\n").replace(/\n$/, "");
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

export async function generateEd25519(comment = ""): Promise<{ privateKey: string; publicKey: string; fingerprint: string }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" } as any, true, ["sign", "verify"])) as CryptoKeyPair;
  const pk = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const seed = pkcs8.slice(pkcs8.length - 32);
  const publicBlob = concat(sshString("ssh-ed25519"), sshString(pk));
  const check = randomBytes(4);
  let priv = concat(check, check, sshString("ssh-ed25519"), sshString(pk), sshString(concat(seed, pk)), sshString(comment));
  const padLen = (8 - (priv.length % 8)) % 8;
  priv = concat(priv, Uint8Array.from({ length: padLen }, (_, i) => i + 1));
  const body = concat(utf8("openssh-key-v1\0"), sshString("none"), sshString("none"), sshString(new Uint8Array(0)), u32(1), sshString(publicBlob), sshString(priv));
  seed.fill(0);
  return { privateKey: wrapPem(body), publicKey: publicKeyLine({ type: "ssh-ed25519", publicBlob, comment: "" }), fingerprint: await fingerprint(publicBlob) };
}

// ---------- WebCrypto import for signing (SSH agent) ----------
const ED25519_PKCS8_PREFIX = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

function big(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}
function bytesOf(v: bigint): Uint8Array {
  const hex = v.toString(16);
  const h = hex.length % 2 ? "0" + hex : hex;
  return Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
}

export async function importForSigning(k: SshKey): Promise<{ alg: any; key: CryptoKey }> {
  if (k.ed25519Seed) {
    const key = await crypto.subtle.importKey("pkcs8", concat(ED25519_PKCS8_PREFIX, k.ed25519Seed), { name: "Ed25519" } as any, false, ["sign"]);
    return { alg: { name: "Ed25519" }, key };
  }
  if (k.ecdsa) {
    const n = k.ecdsa.curve === "P-256" ? 32 : k.ecdsa.curve === "P-384" ? 48 : 66;
    const Q = k.ecdsa.Q;
    const jwk: JsonWebKey = { kty: "EC", crv: k.ecdsa.curve, x: b64u(Q.subarray(1, 1 + n)), y: b64u(Q.subarray(1 + n)), d: b64u(k.ecdsa.d), ext: false };
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: k.ecdsa.curve }, false, ["sign"]);
    return { alg: { name: "ECDSA", hash: k.ecdsa.curve === "P-256" ? "SHA-256" : k.ecdsa.curve === "P-384" ? "SHA-384" : "SHA-512" }, key };
  }
  if (k.rsa) {
    const d = big(k.rsa.d), p = big(k.rsa.p), q = big(k.rsa.q);
    const jwk = (hash: string): JsonWebKey => ({
      kty: "RSA", n: b64u(unpad(k.rsa!.n)), e: b64u(unpad(k.rsa!.e)), d: b64u(unpad(k.rsa!.d)), p: b64u(unpad(k.rsa!.p)), q: b64u(unpad(k.rsa!.q)),
      dp: b64u(bytesOf(d % (p - 1n))), dq: b64u(bytesOf(d % (q - 1n))), qi: b64u(unpad(k.rsa!.iqmp)), alg: hash, ext: false,
    });
    return { alg: { name: "RSASSA-PKCS1-v1_5", jwk }, key: null as any };
  }
  throw new Error("unsupported key");
}

/** SSH agent sign: returns the ssh "signature" blob (string algo ‖ string sig). flags: 2 = rsa-sha2-256, 4 = rsa-sha2-512. */
export async function sshSign(k: SshKey, data: Uint8Array, flags = 0): Promise<Uint8Array> {
  if (k.ed25519Seed) {
    const { key } = await importForSigning(k);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" } as any, key, new Uint8Array(data)));
    return concat(sshString("ssh-ed25519"), sshString(sig));
  }
  if (k.ecdsa) {
    const { alg, key } = await importForSigning(k);
    const sig = new Uint8Array(await crypto.subtle.sign(alg, key, new Uint8Array(data)));
    const half = sig.length / 2;
    return concat(sshString(k.type), sshString(concat(mpint(sig.subarray(0, half)), mpint(sig.subarray(half)))));
  }
  if (k.rsa) {
    const algo = flags & 4 ? "rsa-sha2-512" : flags & 2 ? "rsa-sha2-256" : "ssh-rsa";
    const hash = algo === "rsa-sha2-512" ? "SHA-512" : algo === "rsa-sha2-256" ? "SHA-256" : "SHA-1";
    const { alg } = await importForSigning(k);
    const jwk = alg.jwk(hash === "SHA-1" ? "RS1" : hash === "SHA-256" ? "RS256" : "RS512");
    delete (jwk as any).alg;
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new Uint8Array(data)));
    return concat(sshString(algo), sshString(sig));
  }
  throw new Error("unsupported key");
}
