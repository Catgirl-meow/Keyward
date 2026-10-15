import { hkdfExpand, pbkdf2Sha256, sha256 } from "./primitives.ts";
import { SymKey } from "./symkey.ts";
import { toB64, utf8 } from "../util/bytes.ts";

export const KdfType = { PBKDF2_SHA256: 0, Argon2id: 1 } as const;
export type KdfType = (typeof KdfType)[keyof typeof KdfType];

export interface Kdf {
  type: KdfType;
  iterations: number;
  /** Argon2 memory in MiB */
  memory: number | null;
  parallelism: number | null;
}

/** Injected so the service worker never has to load WASM. */
export type Argon2Fn = (p: {
  password: Uint8Array;
  salt: Uint8Array;
  passes: number;
  memorySize: number; // KiB
  parallelism: number;
  tagLength: number;
}) => Promise<Uint8Array> | Uint8Array;

export class KdfError extends Error {}

/** Reads prelogin / token / sync KDF fields in any casing and shape. */
export function readKdf(o: Record<string, any>): Kdf {
  const s = o.kdfSettings ?? o.kdf ?? o;
  const type = Number(s.kdfType ?? s.type ?? o.kdf ?? 0) as KdfType;
  return {
    type,
    iterations: Number(s.iterations ?? o.kdfIterations ?? 600000),
    memory: (s.memory ?? o.kdfMemory) == null ? null : Number(s.memory ?? o.kdfMemory),
    parallelism: (s.parallelism ?? o.kdfParallelism) == null ? null : Number(s.parallelism ?? o.kdfParallelism),
  };
}

/** Same downgrade guard as the official client: refuse weak parameters a hostile server could send. */
export function assertKdfSafe(k: Kdf): void {
  if (k.type === KdfType.PBKDF2_SHA256) {
    if (!(k.iterations >= 5000)) throw new KdfError("PBKDF2 iterations below 5000 — refusing");
    if (k.iterations > 10_000_000) throw new KdfError("PBKDF2 iterations unreasonably high");
  } else if (k.type === KdfType.Argon2id) {
    if (!(k.iterations >= 2) || !(k.memory! >= 16) || !(k.parallelism! >= 1)) throw new KdfError("Argon2 parameters too weak — refusing");
    if (k.memory! > 1024 || k.parallelism! > 16 || k.iterations > 10) throw new KdfError("Argon2 parameters out of range");
  } else {
    throw new KdfError(`unknown KDF type ${k.type}`);
  }
}

export const normalizeEmail = (e: string) => e.trim().toLowerCase();

export async function deriveMasterKey(password: string, email: string, kdf: Kdf, argon2?: Argon2Fn): Promise<Uint8Array> {
  assertKdfSafe(kdf);
  const pw = utf8(password);
  const salt = normalizeEmail(email);
  if (kdf.type === KdfType.PBKDF2_SHA256) return pbkdf2Sha256(pw, utf8(salt), kdf.iterations, 32);
  if (!argon2) throw new KdfError("Argon2id is not available in this context");
  return argon2({
    password: pw,
    salt: await sha256(salt),
    passes: kdf.iterations,
    memorySize: kdf.memory! * 1024,
    parallelism: kdf.parallelism!,
    tagLength: 32,
  });
}

/** The value sent to the server as `password` (1 iteration) or stored locally for offline verification (2). */
export async function masterPasswordHash(masterKey: Uint8Array, password: string, iterations: 1 | 2 = 1): Promise<string> {
  return toB64(await pbkdf2Sha256(masterKey, utf8(password), iterations, 32));
}

/** 32-byte master key → 64-byte key via HKDF-Expand("enc") ‖ HKDF-Expand("mac"). */
export async function stretchKey(key32: Uint8Array): Promise<SymKey> {
  const enc = await hkdfExpand(key32, "enc", 32);
  const mac = await hkdfExpand(key32, "mac", 32);
  const raw = new Uint8Array(64);
  raw.set(enc, 0);
  raw.set(mac, 32);
  return new SymKey(raw);
}
