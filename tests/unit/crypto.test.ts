import { describe, expect, it } from "vitest";
import { decryptBuffer, decryptString, encryptBuffer, encryptString, parseEnc, EncStringError, rsaDecrypt, rsaEncrypt } from "../../src/core/crypto/encstring.ts";
import { deriveMasterKey, masterPasswordHash, stretchKey, assertKdfSafe, readKdf } from "../../src/core/crypto/kdf.ts";
import { decryptUserKey, wrapUserKey, decryptPrivateKey, decryptOrgKey } from "../../src/core/crypto/keys.ts";
import { argon2 } from "../../src/core/crypto/argon2.ts";
import { SymKey } from "../../src/core/crypto/symkey.ts";
import { generateRsaKeyPair, importRsaOaepPublic, hkdfExpand } from "../../src/core/crypto/primitives.ts";
import { fromB64, toB64, toHex, utf8, fromHex } from "../../src/core/util/bytes.ts";

describe("bytes", () => {
  it("base64 roundtrip incl. url-safe and padding-less", () => {
    for (let n = 0; n < 40; n++) {
      const b = crypto.getRandomValues(new Uint8Array(n));
      expect(toHex(fromB64(toB64(b)))).toBe(toHex(b));
      expect(toHex(fromB64(toB64(b).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_")))).toBe(toHex(b));
    }
    expect(() => fromB64("ab$c")).toThrow();
  });
});

describe("kdf", () => {
  it("PBKDF2 master key + server hash match Python hashlib", async () => {
    const kdf = { type: 0 as const, iterations: 5000, memory: null, parallelism: null };
    const mk = await deriveMasterKey("p4ssw0rd", " User@Example.com ", kdf);
    expect(toB64(mk)).toBe("8GBPhJKlXsUD3rEf7HMRmkMl2vqT1zftjsWDf1fo0+k=");
    expect(await masterPasswordHash(mk, "p4ssw0rd", 1)).toBe("xfhcWVbbpzNGYAAN1KziRm0+y4B9Dd11uXDgzDHBYLE=");
  });

  it("Argon2id matches the reference implementation (argon2-cffi)", async () => {
    const raw = await argon2({ password: utf8("password"), salt: utf8("somesalt"), passes: 2, memorySize: 65536, parallelism: 1, tagLength: 32 });
    expect(toHex(raw)).toBe("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7");
    const kdf = { type: 1 as const, iterations: 3, memory: 64, parallelism: 4 };
    const mk = await deriveMasterKey("p4ssw0rd", "user@example.com", kdf, argon2);
    expect(toB64(mk)).toBe("NwZSR5kdJferucm3HzgIZrB+8ix7fTZDzpnEzXv2B3I=");
  });

  it("refuses downgraded KDF parameters", () => {
    expect(() => assertKdfSafe({ type: 0, iterations: 1000, memory: null, parallelism: null })).toThrow();
    expect(() => assertKdfSafe({ type: 1, iterations: 1, memory: 64, parallelism: 4 })).toThrow();
    expect(() => assertKdfSafe({ type: 1, iterations: 3, memory: 8, parallelism: 4 })).toThrow();
  });

  it("reads prelogin in every shape Vaultwarden sends", () => {
    expect(readKdf({ kdf: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null })).toEqual({ type: 0, iterations: 600000, memory: null, parallelism: null });
    expect(readKdf({ kdfSettings: { kdfType: 1, iterations: 3, memory: 64, parallelism: 4 } })).toEqual({ type: 1, iterations: 3, memory: 64, parallelism: 4 });
  });

  it("HKDF-Expand matches RFC 5869 test case 1 expand step", async () => {
    const prk = fromHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    const okm = await hkdfExpand(prk, fromHex("f0f1f2f3f4f5f6f7f8f9"), 42);
    expect(toHex(okm)).toBe("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
  });
});

describe("encstring", () => {
  it("type 2 roundtrip and MAC check", async () => {
    const k = SymKey.random();
    const e = await encryptString("héllo — мир", k);
    expect(e.startsWith("2.")).toBe(true);
    expect(await decryptString(e, k)).toBe("héllo — мир");
    const [t, rest] = e.split(".");
    const [iv, ct, mac] = rest.split("|");
    const tampered = `${t}.${iv}|${ct}|${toB64(new Uint8Array(32))}`;
    await expect(decryptString(tampered, k)).rejects.toThrow(/MAC/);
    await expect(decryptString(e, SymKey.random())).rejects.toThrow(/MAC/);
    void mac;
  });

  it("parses legacy un-prefixed strings and rejects junk per field", () => {
    expect(parseEnc("aaaa|bbbb|cccc").type).toBe(2);
    expect(parseEnc("aaaa|bbbb").type).toBe(0);
    expect(() => parseEnc("2.only|two")).toThrow(EncStringError);
    expect(() => parseEnc("")).toThrow(EncStringError);
  });

  it("encrypted buffers (attachments) roundtrip", async () => {
    const k = SymKey.random();
    const data = crypto.getRandomValues(new Uint8Array(1000));
    const enc = await encryptBuffer(data, k);
    expect(enc[0]).toBe(2);
    expect(toHex(await decryptBuffer(enc, k))).toBe(toHex(data));
  });
});

describe("key hierarchy", () => {
  it("user key wrap/unwrap with stretched master key", async () => {
    const mk = crypto.getRandomValues(new Uint8Array(32));
    const uk = SymKey.random();
    const prot = await wrapUserKey(uk, mk);
    expect((await decryptUserKey(prot, mk)).toB64()).toBe(uk.toB64());
    const st = await stretchKey(mk);
    expect(st.raw.length).toBe(64);
  });

  it("RSA-OAEP-SHA1 org key unwrap (type 4)", async () => {
    const uk = SymKey.random();
    const { publicSpki, privatePkcs8 } = await generateRsaKeyPair();
    const encPriv = await encryptBuffer(privatePkcs8, uk).then(() => import("../../src/core/crypto/encstring.ts").then((m) => m.encryptBytes(privatePkcs8, uk)));
    const priv = await decryptPrivateKey(encPriv, uk);
    const orgKey = SymKey.random();
    const encOrg = await rsaEncrypt(orgKey.raw, await importRsaOaepPublic(publicSpki));
    expect(encOrg.startsWith("4.")).toBe(true);
    expect((await decryptOrgKey(encOrg, priv)).toB64()).toBe(orgKey.toB64());
    expect(toB64(await rsaDecrypt(encOrg, priv.sha1))).toBe(orgKey.toB64());
  });
});
