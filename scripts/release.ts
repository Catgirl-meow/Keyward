// Release: package, have Mozilla sign the Firefox build (unlisted), tag and publish a GitHub release.
//   node scripts/release.ts [--bump=patch|minor|major] [--draft] [--dry-run] [--any-branch]
// AMO_JWT_ISSUER and AMO_JWT_SECRET come from the environment or the git-ignored .env. They are
// handed to web-ext through its own environment only, never on a command line or in the output.
//   --bump      raise the version in package.json, commit it, and release that
//   --draft     publish the GitHub release as a draft
//   --dry-run   package and run the checks, but don't sign, tag or publish
// A signed .xpi is kept in dist/signed/ with the commit it was built from, so a run that fails
// after signing can be repeated without asking Mozilla to sign the same version twice (it won't).
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PUBLIC_SERVER, setting } from "./config.ts";

const root = new URL("..", import.meta.url).pathname;
const dist = join(root, "dist");
const args = new Map(process.argv.slice(2).map((a) => (a.includes("=") ? a.slice(2).split("=") : [a.slice(2), "1"])) as [string, string][]);
const dryRun = args.has("dry-run");

const git = (...a: string[]) => execFileSync("git", a, { cwd: root, encoding: "utf8" }).trim();
const gitOk = (...a: string[]) => {
  try {
    execFileSync("git", a, { cwd: root, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
};
const run = (cmd: string, a: string[], env: NodeJS.ProcessEnv = process.env) => execFileSync(cmd, a, { cwd: root, stdio: "inherit", env });
const fail = (msg: string): never => {
  console.error(`✗ ${msg}`);
  process.exit(1);
};
const unquote = (v: string | undefined) => v?.replace(/^(["'])(.*)\1$/, "$2");

// Secrets must never reach git: .env has to be ignored and untracked.
if (existsSync(join(root, ".env"))) {
  if (!gitOk("check-ignore", "-q", ".env")) fail(".env is not git-ignored. Add it to .gitignore first.");
  if (gitOk("ls-files", "--error-unmatch", ".env")) fail(".env is tracked by git. Run `git rm --cached .env` and rotate the AMO keys.");
}

const apiKey = unquote(setting("AMO_JWT_ISSUER"));
const apiSecret = unquote(setting("AMO_JWT_SECRET"));
if (!dryRun && (!apiKey || !apiSecret)) fail("AMO_JWT_ISSUER and AMO_JWT_SECRET are not set (see .env.example).");

if (git("status", "--porcelain")) fail("The working tree has uncommitted changes. Commit or stash them first.");

const readVersion = () => JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version as string;
let version = readVersion();
let tag = `v${version}`;
const remoteTag = () => git("ls-remote", "--tags", "origin", `refs/tags/${tag}`);

// The tag already exists when CI runs on a pushed tag: release exactly that commit.
const tagged = gitOk("rev-parse", "-q", "--verify", `refs/tags/${tag}`);
if (tagged) {
  if (args.has("bump")) fail(`${tag} already exists; --bump would release a different version than the tag.`);
  if (git("rev-list", "-n1", tag) !== git("rev-parse", "HEAD")) fail(`${tag} exists but points at another commit. Raise the version (--bump=patch).`);
} else {
  const branch = git("rev-parse", "--abbrev-ref", "HEAD");
  if (branch !== "main" && !args.has("any-branch")) fail(`Releases are cut from main, not ${branch} (--any-branch overrides).`);
  run("git", ["fetch", "-q", "origin", branch, "--tags"]);
  if (git("rev-list", "--count", `HEAD..origin/${branch}`) !== "0") fail(`origin/${branch} has commits you don't have. Pull first.`);

  const bump = args.get("bump");
  if (bump) {
    if (!["patch", "minor", "major"].includes(bump)) fail(`--bump takes patch, minor or major, not ${bump}.`);
    if (!dryRun) {
      run("npm", ["version", bump, "--no-git-tag-version"]);
      version = readVersion();
      tag = `v${version}`;
      run("git", ["commit", "-q", "-m", `Release ${version}`, "--", "package.json", "package-lock.json"]);
    }
  }
  if (gitOk("rev-parse", "-q", "--verify", `refs/tags/${tag}`) || remoteTag()) fail(`${tag} is already tagged. Raise the version (--bump=patch).`);
}
const commit = git("rev-parse", "HEAD");
console.log(`Releasing Keyward ${version} from ${commit.slice(0, 12)}${dryRun ? " (dry run)" : ""}`);

// A public build: the login screen's server preset is never the personal one from .env.
const buildEnv: NodeJS.ProcessEnv = { ...process.env, KW_DEFAULT_SERVER: PUBLIC_SERVER };
delete buildEnv.AMO_JWT_ISSUER;
delete buildEnv.AMO_JWT_SECRET;
run("node", ["scripts/package.ts"], buildEnv);

const chromiumZip = join(dist, `keyward-${version}-chromium.zip`);
const sourceZip = join(dist, "keyward-source.zip");

// Personal info check: the personal server's host must not appear anywhere in the build.
const personal = setting("KW_DEFAULT_SERVER");
const host = personal && personal !== PUBLIC_SERVER ? new URL(personal).hostname : null;
if (host) {
  const walk = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));
  const hits = [...walk(join(dist, "chromium")), ...walk(join(dist, "firefox"))].filter((f) => readFileSync(f).includes(host));
  if (hits.length) fail(`The build contains your server's address (${hits.map((f) => f.replace(root, "")).join(", ")}).`);
  console.log("✓ Build doesn't contain your server's address");
}
const geckoId = JSON.parse(readFileSync(join(dist, "firefox", "manifest.json"), "utf8")).browser_specific_settings.gecko.id;
console.log(`  Firefox add-on id (public in the release): ${geckoId}`);

if (dryRun) {
  console.log("Dry run: stopping before signing.");
  process.exit(0);
}

// Sign, or reuse a signature made from this same commit by an earlier, interrupted run.
const signedDir = join(dist, "signed");
const signedXpi = join(signedDir, `keyward-${version}-firefox.xpi`);
const stamp = `${signedXpi}.commit`;
if (existsSync(signedXpi) && existsSync(stamp) && readFileSync(stamp, "utf8").trim() === commit) {
  console.log(`✓ Reusing ${signedXpi.replace(root, "")}, signed earlier from this commit`);
} else {
  const inbox = join(signedDir, "incoming");
  rmSync(inbox, { recursive: true, force: true });
  mkdirSync(inbox, { recursive: true });
  // WEB_EXT_* variables are web-ext's own way to take options, so the keys stay off the command line.
  const signEnv = { ...buildEnv, WEB_EXT_API_KEY: apiKey, WEB_EXT_API_SECRET: apiSecret };
  try {
    run("npx", ["web-ext", "sign", "--no-config-discovery", "--channel=unlisted", "--source-dir", join(dist, "firefox"), "--artifacts-dir", inbox, "--upload-source-code", sourceZip, "--approval-timeout=900000"], signEnv);
  } catch {
    fail("Mozilla didn't sign the build (web-ext's message is above). Nothing was tagged or published.");
  }
  const got = readdirSync(inbox).filter((f) => f.endsWith(".xpi"));
  if (got.length !== 1) fail(`Expected one signed .xpi from Mozilla, got ${got.length}.`);
  renameSync(join(inbox, got[0]), signedXpi);
  rmSync(inbox, { recursive: true });
  writeFileSync(stamp, `${commit}\n`);
  console.log(`✓ Signed by Mozilla: ${signedXpi.replace(root, "")}`);
}

const assets = [signedXpi, chromiumZip, sourceZip];
const sums = join(dist, "SHA256SUMS");
writeFileSync(sums, assets.map((f) => `${createHash("sha256").update(readFileSync(f)).digest("hex")}  ${f.split("/").pop()}\n`).join(""));

// Push the release commit (if --bump made one) and the tag together, so neither lands alone.
// A tag left local by an interrupted run is pushed on its own.
if (!tagged) run("git", ["tag", "-a", tag, "-m", `Keyward ${version}`]);
if (!remoteTag()) {
  const branch = git("rev-parse", "--abbrev-ref", "HEAD");
  run("git", ["push", "--atomic", "origin", ...(branch === "HEAD" ? [] : [`HEAD:refs/heads/${branch}`]), `refs/tags/${tag}`]);
}

const notes = [
  "**Firefox / LibreWolf:** `about:addons` → gear menu → **Install Add-on From File…** → `keyward-" + version + "-firefox.xpi` (signed by Mozilla).",
  "**Helium / Chromium:** unzip `keyward-" + version + "-chromium.zip` and load it unpacked, see [INSTALL.md](docs/INSTALL.md).",
  "",
].join("\n");
const ghArgs = ["release", "create", tag, ...assets, sums, "--verify-tag", "--title", `Keyward ${version}`, "--notes", notes, "--generate-notes"];
if (args.has("draft")) ghArgs.push("--draft");
if (version.includes("-")) ghArgs.push("--prerelease");
run("gh", ghArgs, buildEnv);

console.log("");
for (const f of [...assets, sums]) console.log(`${(statSync(f).size / 1024).toFixed(0).padStart(6)} KB  ${f.replace(root, "")}`);
console.log(`✓ Released ${tag}`);
