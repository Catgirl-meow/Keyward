// Build settings that differ per deployment, read from the environment or from a git-ignored
// `.env` in the project root (see .env.example). The defaults suit a public build.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const file = join(root, ".env");
const dotenv: Record<string, string> = existsSync(file)
  ? Object.fromEntries(readFileSync(file, "utf8").split("\n").filter((l) => /^\s*[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]))
  : {};
const get = (k: string, d: string) => process.env[k] || dotenv[k] || d;

export const config = {
  /** Server preset on the login screen. */
  defaultServer: get("KW_DEFAULT_SERVER", "https://vault.bitwarden.com"),
  /** Firefox add-on id; keep it stable once an .xpi is signed with it. */
  geckoId: get("KW_GECKO_ID", "keyward@keyward.extension"),
};
