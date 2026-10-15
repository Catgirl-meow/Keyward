// Byte/string helpers shared by every context (SW, pages, content scripts, Vitest).

const te = new TextEncoder();
const td = new TextDecoder();

export const utf8 = (s: string): Uint8Array<ArrayBuffer> => te.encode(s) as Uint8Array<ArrayBuffer>;
export const fromUtf8 = (b: Uint8Array): string => td.decode(b);

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_LOOKUP = new Int16Array(256).fill(-1);
for (let i = 0; i < 64; i++) B64_LOOKUP[B64.charCodeAt(i)] = i;
B64_LOOKUP["-".charCodeAt(0)] = 62; // accept base64url too
B64_LOOKUP["_".charCodeAt(0)] = 63;

export function toB64(bytes: Uint8Array): string {
  let out = "";
  const n = bytes.length;
  let i = 0;
  for (; i + 2 < n; i += 3) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[v >> 18] + B64[(v >> 12) & 63] + B64[(v >> 6) & 63] + B64[v & 63];
  }
  if (i < n) {
    const v = (bytes[i] << 16) | ((i + 1 < n ? bytes[i + 1] : 0) << 8);
    out += B64[v >> 18] + B64[(v >> 12) & 63] + (i + 1 < n ? B64[(v >> 6) & 63] : "=") + "=";
  }
  return out;
}

/** Decodes standard or url-safe base64, with or without padding. Throws on garbage. */
export function fromB64(s: string): Uint8Array<ArrayBuffer> {
  let len = s.length;
  while (len > 0 && (s.charCodeAt(len - 1) === 61 /* = */ || s.charCodeAt(len - 1) <= 32)) len--;
  const out = new Uint8Array(((len * 3) >> 2) + 3);
  let o = 0, acc = 0, bits = 0;
  for (let i = 0; i < len; i++) {
    const c = s.charCodeAt(i);
    if (c <= 32) continue; // tolerate whitespace / newlines (PEM bodies)
    const v = B64_LOOKUP[c];
    if (v < 0) throw new Error("invalid base64");
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 255;
    }
  }
  return out.slice(0, o);
}

export const toB64Url = (b: Uint8Array): string =>
  toB64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const fromB64Url = fromB64;

export function toHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16);
  return s;
}

export function fromHex(h: string): Uint8Array<ArrayBuffer> {
  const clean = h.replace(/[^0-9a-f]/gi, "");
  const out = new Uint8Array(clean.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Constant-time comparison (length is not secret). */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** Copies into a fresh ArrayBuffer-backed array (WebCrypto rejects SharedArrayBuffer views). */
export const own = (b: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(b);

export function wipe(b: Uint8Array | null | undefined): void {
  if (b) b.fill(0);
}
