// TOTP / HOTP / Steam Guard codes (RFC 4226 / 6238) via WebCrypto HMAC.
import { importHmacKey, hmac } from "../crypto/primitives.ts";

export interface OtpSpec {
  kind: "totp" | "hotp" | "steam";
  secret: Uint8Array<ArrayBuffer>;
  algorithm: "SHA-1" | "SHA-256" | "SHA-512";
  digits: number;
  period: number;
  counter: number;
  issuer: string | null;
  account: string | null;
}

export function base32Decode(input: string): Uint8Array<ArrayBuffer> {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const s = input.toUpperCase().replace(/[\s=-]/g, "");
  const out: number[] = [];
  let bits = 0, value = 0;
  for (const ch of s) {
    const v = alphabet.indexOf(ch);
    if (v < 0) throw new Error("invalid base32");
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 255);
    }
  }
  return new Uint8Array(out);
}

export function parseOtp(raw: string | null | undefined): OtpSpec | null {
  if (!raw) return null;
  const s = raw.trim();
  try {
    if (/^steam:\/\//i.test(s)) {
      return { kind: "steam", secret: base32Decode(s.slice(8)), algorithm: "SHA-1", digits: 5, period: 30, counter: 0, issuer: "Steam", account: null };
    }
    if (/^otpauth:\/\//i.test(s)) {
      const u = new URL(s);
      const kind = u.hostname.toLowerCase() === "hotp" ? "hotp" : "totp";
      const p = u.searchParams;
      const alg = (p.get("algorithm") || "SHA1").toUpperCase().replace("-", "");
      const label = decodeURIComponent(u.pathname.replace(/^\//, ""));
      const [labelIssuer, labelAccount] = label.includes(":") ? label.split(/:(.*)/s) : [null, label];
      const issuer = p.get("issuer") || labelIssuer;
      const isSteam = (issuer ?? "").toLowerCase() === "steam" && p.get("encoder") === "steam";
      return {
        kind: isSteam ? "steam" : kind,
        secret: base32Decode(p.get("secret") || ""),
        algorithm: alg === "SHA256" ? "SHA-256" : alg === "SHA512" ? "SHA-512" : "SHA-1",
        digits: isSteam ? 5 : Math.min(10, Math.max(1, Number(p.get("digits")) || 6)),
        period: Math.max(1, Number(p.get("period")) || 30),
        counter: Number(p.get("counter")) || 0,
        issuer: issuer || null,
        account: labelAccount?.trim() || null,
      };
    }
    // Plain base32 secret.
    const secret = base32Decode(s);
    if (!secret.length) return null;
    return { kind: "totp", secret, algorithm: "SHA-1", digits: 6, period: 30, counter: 0, issuer: null, account: null };
  } catch {
    return null;
  }
}

const STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY";

export async function hotp(spec: OtpSpec, counter: number): Promise<string> {
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const mac = await hmac(await importHmacKey(spec.secret, spec.algorithm), msg);
  const off = mac[mac.length - 1] & 0xf;
  let bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  if (spec.kind === "steam") {
    let code = "";
    for (let i = 0; i < 5; i++) {
      code += STEAM_CHARS[bin % STEAM_CHARS.length];
      bin = Math.floor(bin / STEAM_CHARS.length);
    }
    return code;
  }
  return String(bin % 10 ** spec.digits).padStart(spec.digits, "0");
}

export interface OtpCode {
  code: string;
  /** seconds left in this period (TOTP) */
  remaining: number;
  period: number;
}

export async function otpCode(spec: OtpSpec, now = Date.now()): Promise<OtpCode> {
  if (spec.kind === "hotp") return { code: await hotp(spec, spec.counter), remaining: 0, period: 0 };
  const t = Math.floor(now / 1000);
  return { code: await hotp(spec, Math.floor(t / spec.period)), remaining: spec.period - (t % spec.period), period: spec.period };
}

/** "123456" → "123 456", "12345678" → "1234 5678" (Keyguard groups digits). */
export function formatCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}
