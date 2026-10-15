// Page/Worker-only Argon2id loader (~8 KB incl. inlined WASM). Never import from the service worker.
import setupWasm from "argon2id/lib/setup.js";
import simd from "argon2id/dist/simd.wasm";
import noSimd from "argon2id/dist/no-simd.wasm";
import type { Argon2Fn } from "./kdf.ts";

let fn: Promise<(p: any) => Uint8Array> | null = null;

export const argon2: Argon2Fn = async (p) => {
  fn ??= setupWasm(simd, noSimd);
  const hash = await fn;
  return hash(p);
};

/** Drops the 65 MB WASM memory after use (unlock is rare). */
export function releaseArgon2(): void {
  fn = null;
}
