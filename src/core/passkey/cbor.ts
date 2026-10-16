// The CBOR subset WebAuthn needs: unsigned/negative ints, byte and text strings, arrays, maps
// (int or text keys, encoded in the order given, which callers keep canonical), booleans, null.
import { concat, fromUtf8, utf8 } from "../util/bytes.ts";

export type CborValue = number | Uint8Array | string | boolean | null | CborValue[] | Map<number | string, CborValue>;

function head(major: number, n: number): Uint8Array {
  const m = major << 5;
  if (n < 24) return Uint8Array.of(m | n);
  if (n < 0x100) return Uint8Array.of(m | 24, n);
  if (n < 0x10000) return Uint8Array.of(m | 25, n >> 8, n & 0xff);
  if (n < 0x100000000) return Uint8Array.of(m | 26, n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  throw new RangeError("cbor: length too large");
}

export function encode(v: CborValue): Uint8Array {
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new TypeError("cbor: only integers");
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (v instanceof Uint8Array) return concat(head(2, v.length), v);
  if (typeof v === "string") {
    const b = utf8(v);
    return concat(head(3, b.length), b);
  }
  if (v === false) return Uint8Array.of(0xf4);
  if (v === true) return Uint8Array.of(0xf5);
  if (v === null) return Uint8Array.of(0xf6);
  if (Array.isArray(v)) return concat(head(4, v.length), ...v.map(encode));
  if (v instanceof Map) {
    const parts: Uint8Array[] = [head(5, v.size)];
    for (const [k, x] of v) parts.push(encode(k), encode(x));
    return concat(...parts);
  }
  throw new TypeError("cbor: unsupported value");
}

/** Decodes one item; `end` is the offset after it (authenticator data is followed by extensions). */
export function decode(b: Uint8Array, at = 0): { value: CborValue; end: number } {
  let o = at;
  const byte = () => {
    if (o >= b.length) throw new RangeError("cbor: truncated");
    return b[o++];
  };
  const arg = (info: number): number => {
    if (info < 24) return info;
    const n = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : 0;
    if (!n) throw new RangeError("cbor: unsupported length");
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + byte();
    return v;
  };
  const item = (depth: number): CborValue => {
    if (depth > 16) throw new RangeError("cbor: too deep");
    const ib = byte();
    const major = ib >> 5;
    const info = ib & 31;
    if (major === 7) {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22 || info === 23) return null;
      throw new RangeError("cbor: unsupported simple value");
    }
    const n = arg(info);
    switch (major) {
      case 0:
        return n;
      case 1:
        return -1 - n;
      case 2:
      case 3: {
        if (o + n > b.length) throw new RangeError("cbor: truncated");
        const s = b.slice(o, o + n);
        o += n;
        return major === 2 ? s : fromUtf8(s);
      }
      case 4:
        return Array.from({ length: n }, () => item(depth + 1));
      case 5: {
        const m = new Map<number | string, CborValue>();
        for (let i = 0; i < n; i++) {
          const k = item(depth + 1);
          if (typeof k !== "number" && typeof k !== "string") throw new TypeError("cbor: unsupported map key");
          m.set(k, item(depth + 1));
        }
        return m;
      }
    }
    throw new RangeError("cbor: unsupported major type");
  };
  const value = item(0);
  return { value, end: o };
}
