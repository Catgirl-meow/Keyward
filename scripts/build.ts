// Build both browser targets with esbuild. Usage:
//   node scripts/build.ts [--target=chromium|firefox] [--watch] [--dev]
import * as esbuild from "esbuild";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { manifest, CHROMIUM_KEY_FILE, type Target } from "./manifest.ts";

const root = new URL("..", import.meta.url).pathname;
const args = new Map(process.argv.slice(2).map((a) => (a.includes("=") ? a.slice(2).split("=") : [a.slice(2), "1"])) as [string, string][]);
const targets: Target[] = args.get("target") ? [args.get("target") as Target] : ["chromium", "firefox"];
const watch = args.has("watch");
const dev = args.has("dev") || watch;
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

const wasmPlugin: esbuild.Plugin = {
  name: "wasm-inline",
  setup(b) {
    b.onLoad({ filter: /\.wasm$/ }, (a) => {
      const b64 = readFileSync(a.path).toString("base64");
      return {
        contents: `const b=Uint8Array.from(atob(${JSON.stringify(b64)}),c=>c.charCodeAt(0));export default (i)=>WebAssembly.instantiate(b,i);`,
        loader: "js",
      };
    });
  },
};

// Inline Material Symbols as tiny SVG path strings: `import home from "icon:home"`, `icon:home?fill`.
const iconPlugin: esbuild.Plugin = {
  name: "material-symbols",
  setup(b) {
    b.onResolve({ filter: /^icon:/ }, (a) => ({ path: a.path.slice(5), namespace: "icon" }));
    b.onLoad({ filter: /.*/, namespace: "icon" }, (a) => {
      const [name, q] = a.path.split("?");
      const file = join(root, "node_modules/@material-symbols/svg-400/outlined", `${name}${q === "fill" ? "-fill" : ""}.svg`);
      const svg = readFileSync(file, "utf8");
      const d = [...svg.matchAll(/ d="([^"]+)"/g)].map((m) => m[1]).join(" ");
      return { contents: `export default ${JSON.stringify(d)};`, loader: "js" };
    });
  },
};

function common(target: Target): esbuild.BuildOptions {
  return {
    bundle: true,
    minify: !dev && !process.env.KW_NOMINIFY,
    sourcemap: dev ? "inline" : false,
    target: target === "chromium" ? ["chrome130"] : ["firefox140"],
    legalComments: "none",
    logLevel: "warning",
    jsx: "automatic",
    jsxImportSource: "preact",
    define: {
      __CHROMIUM__: String(target === "chromium"),
      __FIREFOX__: String(target === "firefox"),
      __DEV__: String(dev),
      __VERSION__: JSON.stringify(pkg.version),
    },
    plugins: [wasmPlugin, iconPlugin],
    loader: { ".woff2": "file", ".svg": "text", ".txt": "text" },
    charset: "utf8",
    drop: dev ? [] : ["debugger"],
  };
}

const PAGE_ENTRIES: Record<string, string> = {
  popup: "src/ui/apps/popup/main.tsx",
  vault: "src/ui/apps/vault/main.tsx",
  menu: "src/ui/apps/menu/main.tsx",
  savebar: "src/ui/apps/savebar/main.tsx",
  passkey: "src/ui/apps/passkey/main.tsx",
};
const SCRIPT_ENTRIES: Record<string, string> = {
  bg: "src/background/index.ts",
  "cs/boot": "src/content/bootstrap.ts",
  "cs/autofill": "src/content/autofill/index.ts",
  "cs/passkey-main": "src/content/passkey.main.ts",
  "cs/passkey-relay": "src/content/passkey.relay.ts",
  "cs/webauthn2fa": "src/content/webauthn2fa.ts",
};

async function buildTarget(target: Target) {
  // KW_DIST: build somewhere else (two sessions testing at once must not share dist/).
  const out = join(process.env.KW_DIST ? resolve(process.env.KW_DIST) : join(root, "dist"), target);
  if (!watch) rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });

  const scripts = Object.fromEntries(Object.entries(SCRIPT_ENTRIES).filter(([, src]) => existsSync(join(root, src))));
  if (target === "chromium" && existsSync(join(root, "src/background/offscreen.ts"))) scripts["offscreen"] = "src/background/offscreen.ts";
  const pages = Object.fromEntries(Object.entries(PAGE_ENTRIES).filter(([, src]) => existsSync(join(root, src))));

  const scriptOpts: esbuild.BuildOptions = {
    ...common(target),
    entryPoints: Object.fromEntries(Object.entries(scripts).map(([k, v]) => [k, join(root, v)])),
    outdir: out,
    format: "iife",
  };
  const pageOpts: esbuild.BuildOptions = {
    ...common(target),
    entryPoints: Object.fromEntries(Object.entries(pages).map(([k, v]) => [k, join(root, v)])),
    outdir: join(out, "ui"),
    format: "esm",
    splitting: true,
    chunkNames: "c-[hash]",
    external: ["*.woff2", "/icons/*"],
    assetNames: "a-[name]-[hash]",
    metafile: true,
  };

  writeStatic(target, out);
  if (watch) {
    const c1 = await esbuild.context(scriptOpts);
    const c2 = await esbuild.context(pageOpts);
    await Promise.all([c1.watch(), c2.watch()]);
    console.log(`[${target}] watching…`);
    return;
  }
  const [rs, rp] = await Promise.all([esbuild.build({ ...scriptOpts, metafile: true }), esbuild.build(pageOpts)]);
  preloadChunks(out, rp.metafile!);
  mkdirSync(join(root, ".cache"), { recursive: true });
  writeFileSync(join(root, ".cache", `meta-${target}.json`), JSON.stringify({ scripts: rs.metafile, pages: rp.metafile }));
  report(target, out);
}

function writeStatic(target: Target, out: string) {
  const key = existsSync(join(root, CHROMIUM_KEY_FILE)) ? readFileSync(join(root, CHROMIUM_KEY_FILE), "utf8").trim() : null;
  writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest(target, pkg.version, key), null, dev ? 2 : 0));
  cpSync(join(root, "static"), out, { recursive: true });
  if (target !== "chromium") rmSync(join(out, "offscreen.html"), { force: true });
  const fonts = join(out, "fonts");
  mkdirSync(fonts, { recursive: true });
  for (const [from, to] of [
    ["@fontsource-variable/roboto/files/roboto-latin-wght-normal.woff2", "roboto-latin.woff2"],
    ["@fontsource-variable/roboto/files/roboto-latin-ext-wght-normal.woff2", "roboto-latin-ext.woff2"],
    ["@fontsource-variable/roboto/files/roboto-cyrillic-wght-normal.woff2", "roboto-cyrillic.woff2"],
    ["@fontsource/roboto-mono/files/roboto-mono-latin-400-normal.woff2", "roboto-mono-latin.woff2"],
  ]) cpSync(join(root, "node_modules", from), join(fonts, to));
}

/** Adds <link rel="modulepreload"> for each page's static chunks, so the browser fetches them in
 * parallel with the entry instead of discovering them one level at a time. */
function preloadChunks(out: string, meta: esbuild.Metafile) {
  for (const page of Object.keys(PAGE_ENTRIES)) {
    const html = join(out, `${page}.html`);
    const entry = Object.keys(meta.outputs).find((o) => o.endsWith(`/ui/${page}.js`));
    if (!entry || !existsSync(html)) continue;
    const seen = new Set<string>();
    const visit = (o: string) => {
      for (const i of meta.outputs[o]?.imports ?? []) {
        if (i.kind !== "import-statement" || seen.has(i.path)) continue;
        seen.add(i.path);
        visit(i.path);
      }
    };
    visit(entry);
    const links = [...seen].map((p) => `<link rel="modulepreload" href="ui/${p.split("/").pop()}">`).join("\n");
    const src = readFileSync(html, "utf8");
    writeFileSync(html, src.replace(`<script type="module" src="ui/${page}.js">`, `${links}\n<script type="module" src="ui/${page}.js">`));
  }
}

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

function report(target: Target, out: string) {
  let total = 0;
  const rows: [string, number, number][] = [];
  for (const f of walk(out)) {
    const buf = readFileSync(f);
    total += buf.length;
    if (/\.(js|css|html)$/.test(f)) rows.push([relative(out, f), buf.length, gzipSync(buf).length]);
  }
  rows.sort((a, b) => b[1] - a[1]);
  console.log(`\n[${target}] ${(total / 1024).toFixed(1)} KB unpacked`);
  for (const [f, s, g] of rows.slice(0, 14)) console.log(`  ${f.padEnd(34)} ${(s / 1024).toFixed(1).padStart(7)} KB  ${(g / 1024).toFixed(1).padStart(6)} KB gz`);
}

for (const t of targets) await buildTarget(t);
