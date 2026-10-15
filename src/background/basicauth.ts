// HTTP basic/digest auth: answer the browser's credential request when exactly one login matches.
// Each request gets one try; a second challenge for the same request falls through to the
// browser's own dialog, so a wrong saved password can't loop.
import { parseUrl } from "../core/url/match.ts";
import { CipherType } from "../core/vault/types.ts";
import { loadSettings } from "../platform/settings.ts";
import { unlockedCtx } from "./ctx.ts";

const tried = new Set<string>();

async function credentials(d: chrome.webRequest.OnAuthRequiredDetails): Promise<chrome.webRequest.BlockingResponse> {
  try {
    if (d.isProxy || d.tabId < 0 || tried.has(d.requestId)) return {};
    tried.add(d.requestId);
    if (tried.size > 200) tried.delete(tried.values().next().value!);
    const s = await loadSettings();
    if (!s.autofill.basicAuth) return {};
    const { matchesFor, loadView } = await import("./autofill.ts");
    const logins = (await matchesFor(d.url)).filter((m) => m.type === CipherType.Login && !m.rp);
    // Several logins for the host: take the one whose saved URI is uniquely the most specific
    // (same host and a path the request starts with), else let the browser ask.
    const req = new URL(d.url);
    const score = (uri: string | null) => {
      const u = parseUrl(uri);
      if (!u || u.host !== (req.port ? `${req.hostname}:${req.port}` : req.hostname)) return 0;
      const path = new URL(u.href).pathname.replace(/\/$/, "");
      return path && req.pathname.startsWith(path) ? 2 + path.length : 1;
    };
    const ranked = logins.map((m) => ({ m, s: score(m.uri) })).sort((a, b) => b.s - a.s);
    if (!ranked.length || (ranked.length > 1 && ranked[0].s === ranked[1].s)) return {};
    const v = await loadView(await unlockedCtx(), ranked[0].m.id);
    if (!v.login?.username && !v.login?.password) return {};
    return { authCredentials: { username: v.login.username ?? "", password: v.login.password ?? "" } };
  } catch {
    return {};
  }
}

export function installBasicAuth() {
  const filter = { urls: ["<all_urls>"] };
  if (__CHROMIUM__) {
    chrome.webRequest.onAuthRequired.addListener((d, cb) => void credentials(d).then((r) => cb?.(r)), filter, ["asyncBlocking"]);
  } else {
    (browser as any).webRequest.onAuthRequired.addListener((d: chrome.webRequest.OnAuthRequiredDetails) => credentials(d), filter, ["blocking"]);
  }
}

declare const browser: unknown;
