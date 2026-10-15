import { readFileSync } from "node:fs";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    {
      name: "wasm-inline",
      enforce: "pre",
      load(id) {
        if (!id.endsWith(".wasm")) return null;
        const b64 = readFileSync(id).toString("base64");
        return `const b=Uint8Array.from(atob(${JSON.stringify(b64)}),c=>c.charCodeAt(0));export default (i)=>WebAssembly.instantiate(b,i);`;
      },
    },
  ],
  define: { __CHROMIUM__: "true", __FIREFOX__: "false", __DEV__: "true", __VERSION__: '"test"' },
  oxc: { jsx: { runtime: "automatic", importSource: "preact" } },
  test: {
    include: ["tests/unit/**/*.test.ts", "tests/unit/**/*.test.tsx"],
    environment: "node",
    testTimeout: 30000,
    server: { deps: { inline: ["argon2id"] } },
  },
});
