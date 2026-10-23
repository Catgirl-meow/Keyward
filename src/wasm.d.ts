declare module "*.wasm" {
  const instantiate: (imports: WebAssembly.Imports) => Promise<WebAssembly.WebAssemblyInstantiatedSource>;
  export default instantiate;
}
declare module "argon2id/lib/setup.js" {
  const setupWasm: (simd: any, noSimd: any) => Promise<(p: any) => Uint8Array>;
  export default setupWasm;
}
declare const __CHROMIUM__: boolean;
declare const __FIREFOX__: boolean;
declare const __DEV__: boolean;
declare const __VERSION__: string;
declare const __DEFAULT_SERVER__: string;
declare module "icon:*" {
  const d: string;
  export default d;
}
declare module "*.css";
declare module "*.txt" {
  const text: string;
  export default text;
}
