import { importAesCbc, importHmacKey } from "./primitives.ts";
import { randomBytes, toB64, fromB64 } from "../util/bytes.ts";

/**
 * A Bitwarden symmetric key: 32 bytes (legacy AES-only) or 64 bytes (AES-256 enc ‖ HMAC-SHA256 mac).
 * CryptoKey objects are imported lazily and cached, because importKey per field is the
 * dominant cost when decrypting many items.
 */
export class SymKey {
  readonly raw: Uint8Array<ArrayBuffer>;
  readonly enc: Uint8Array<ArrayBuffer>;
  readonly mac: Uint8Array<ArrayBuffer> | null;
  #aes?: Promise<CryptoKey>;
  #hmac?: Promise<CryptoKey>;

  constructor(raw: Uint8Array) {
    if (raw.length !== 32 && raw.length !== 64) throw new Error(`unsupported symmetric key length ${raw.length}`);
    this.raw = new Uint8Array(raw);
    this.enc = this.raw.slice(0, 32);
    this.mac = raw.length === 64 ? this.raw.slice(32, 64) : null;
  }

  static random(): SymKey {
    return new SymKey(randomBytes(64));
  }

  static fromB64(b64: string): SymKey {
    return new SymKey(fromB64(b64));
  }

  toB64(): string {
    return toB64(this.raw);
  }

  aes(): Promise<CryptoKey> {
    return (this.#aes ??= importAesCbc(this.enc));
  }

  hmac(): Promise<CryptoKey> {
    if (!this.mac) throw new Error("key has no MAC part");
    return (this.#hmac ??= importHmacKey(this.mac));
  }
}
