// Release packages. Builds both targets, lints the Firefox build and zips everything:
//   node scripts/package.ts
//     dist/keyward-<version>-chromium.zip   Helium / Chromium (load unpacked, or drag into chrome://extensions)
//     dist/keyward-<version>-firefox.xpi    LibreWolf, unsigned (signed releases: npm run release)
//     dist/keyward-source.zip               the committed source, for AMO's review of minified code
// KW_DIST builds somewhere other than dist/, as for scripts/build.ts.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const out = process.env.KW_DIST ? resolve(process.env.KW_DIST) : join(root, "dist");
const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const run = (cmd: string, args: string[], cwd = root) => execFileSync(cmd, args, { cwd, stdio: "inherit" });

if (execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trim()) {
  console.warn("! Uncommitted changes: the packages are built from the working tree, the source archive from HEAD.");
}

run("node", ["scripts/build.ts"]);

// Errors fail the release. Expected warnings: Preact's dangerouslySetInnerHTML support (unused)
// and a manifest key Firefox for Android lacks (Keyward doesn't target Android).
const lint = JSON.parse(execFileSync("npx", ["web-ext", "lint", "--source-dir", join(out, "firefox"), "--output", "json"], { cwd: root, encoding: "utf8" }));
for (const m of [...lint.errors, ...lint.warnings]) console.log(`  lint ${m.code} ${m.file ?? ""}`);
if (lint.errors.length) throw new Error(`web-ext lint: ${lint.errors.length} errors`);

const files = {
  chromium: join(out, `keyward-${version}-chromium.zip`),
  firefox: join(out, `keyward-${version}-firefox.xpi`),
  source: join(out, "keyward-source.zip"),
};
for (const f of Object.values(files)) rmSync(f, { force: true });
// -X: no extra file attributes, so the same build zips to the same bytes.
run("zip", ["-q", "-r", "-X", files.chromium, "."], join(out, "chromium"));
run("zip", ["-q", "-r", "-X", files.firefox, "."], join(out, "firefox"));
run("git", ["archive", "--format=zip", "-o", files.source, "HEAD"]);

console.log("");
for (const f of Object.values(files)) {
  if (!existsSync(f)) throw new Error(`missing ${f}`);
  const sha = createHash("sha256").update(readFileSync(f)).digest("hex");
  console.log(`${(statSync(f).size / 1024).toFixed(0).padStart(6)} KB  ${sha.slice(0, 16)}  ${f.replace(root, "")}`);
}
