// Build settings that differ per deployment, read from the environment or from a git-ignored
// `.env` in the project root (see .env.example). The defaults suit a public build.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const file = join(root, ".env");
const dotenv: Record<string, string> = existsSync(file)
  ? Object.fromEntries(readFileSync(file, "utf8").split("\n").filter((l) => /^\s*[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]))
  : {};
/** A setting from the environment or `.env`; also read by scripts/release.ts for the AMO keys. */
export const setting = (k: string): string | undefined => process.env[k] || dotenv[k] || undefined;
const get = (k: string, d: string) => setting(k) ?? d;

/** Server preset of a public build. Releases always use it, whatever `.env` says. */
export const PUBLIC_SERVER = "https://vault.bitwarden.com";

export const config = {
  /** Server preset on the login screen. */
  defaultServer: get("KW_DEFAULT_SERVER", PUBLIC_SERVER),
  /** Firefox add-on id; keep it stable once an .xpi is signed with it. */
  geckoId: get("KW_GECKO_ID", "keyward@keyward.extension"),
};
