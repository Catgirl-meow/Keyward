// Autofill fixture site: static form pages plus the few server steps the multi-step and
// save-prompt tests need. Served on :8090 under several *.localhost names, which browsers resolve
// to loopback, so frames can be same-site or cross-site.
//   node tests/fixtures/server.ts        → serve until Ctrl+C (manual testing)
import { createServer, type IncomingMessage, type Server } from "node:http";
import { readFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { totpNow } from "../lib/vw.ts";
import { rpRoute } from "./rp.ts";

export const FX = {
  port: Number(process.env.KW_FIXTURE_PORT) || 8090,
  url: (host: keyof typeof HOSTS, path = "/") => `http://${HOSTS[host]}:${FX.port}${path}`,
  login: { user: "alice@example.test", pass: "Plain-Pass-1", totp: "JBSWY3DPEHPK3PXP" },
  mailfence: { user: "kay", pass: "Mf-Pass-2", totp: "GEZDGNBVGY3TQOJQ" },
  other: { user: "framed", pass: "Frame-Pass-3" },
  basic: { user: "basic", pass: "Basic-Pass-4" },
};
export const HOSTS = { login: "login.localhost", mailfence: "mailfence.localhost", other: "other.localhost", shop: "shop.localhost" } as const;

const dir = new URL("./forms/", import.meta.url).pathname;
const TYPES: Record<string, string> = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript" };

async function body(req: IncomingMessage): Promise<Record<string, string>> {
  let raw = "";
  for await (const c of req) raw += c;
  if ((req.headers["content-type"] ?? "").includes("json")) return JSON.parse(raw || "{}");
  return Object.fromEntries(new URLSearchParams(raw));
}

async function codeOk(secret: string, code: string) {
  return code === (await totpNow(secret)) || code === (await totpNow(secret, -30));
}

const page = (title: string, h1: string, id = "ok") =>
  `<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/style.css"><title>${title}</title><h1 id="${id}">${h1}</h1>`;

export function startFixtures(port = FX.port): Promise<Server> {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    const redirect = (to: string) => res.writeHead(303, { location: to }).end();
    try {
      if (req.method === "POST") {
        const b = await body(req);
        if (url.pathname.startsWith("/rp/")) {
          const r = await rpRoute(url.pathname, b, `http://${req.headers.host}`);
          if (r) return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(r));
        }
        switch (url.pathname) {
          case "/done":
          case "/signup":
          case "/changed":
            return redirect("/welcome.html");
          case "/check":
            // Always "wrong password": the login form comes back.
            return redirect("/plain.html?error=1");
          case "/mailfence/usw": {
            // Like mailfence.com: the login form and the 2FA form both post here, and the 2FA
            // step is this POST's response (same URL), not a redirect.
            const twoFa = (error: boolean) => {
              const html = readFileSync(join(dir, "mailfence/2fa.html"), "utf8");
              return res.writeHead(200, { "content-type": TYPES[".html"] }).end(error ? html.replace("error-message hidden", "error-message") : html);
            };
            if ("UserID" in b) return b.UserID === FX.mailfence.user && b.Password === FX.mailfence.pass ? twoFa(false) : redirect("/mailfence/login.html?error=1");
            const ok = b.mode === "totp" ? await codeOk(FX.mailfence.totp, b.totp ?? "") : false;
            return ok ? redirect("/mailfence/inbox.html") : twoFa(true);
          }
          case "/verify": {
            const ok = b.u === FX.login.user && b.p === FX.login.pass && (await codeOk(FX.login.totp, b.code ?? ""));
            const html = page("Result", ok ? `Welcome, ${b.u}` : "Wrong credentials", ok ? "ok" : "bad");
            return res.writeHead(200, { "content-type": TYPES[".html"] }).end(html);
          }
        }
        return res.writeHead(404).end();
      }
      if (url.pathname === "/basic") {
        const want = "Basic " + Buffer.from(`${FX.basic.user}:${FX.basic.pass}`).toString("base64");
        if (req.headers.authorization === want) return res.writeHead(200, { "content-type": TYPES[".html"] }).end(page("Basic", "Authorized"));
        return res.writeHead(401, { "www-authenticate": 'Basic realm="Keyward fixtures"' }).end("auth required");
      }
      if (url.pathname === "/") {
        const list = readdirSync(dir).filter((f) => f.endsWith(".html")).map((f) => `<li><a href="/${f}">${f}</a></li>`).join("");
        return res.writeHead(200, { "content-type": TYPES[".html"] }).end(`<!doctype html><title>Fixtures</title><ul>${list}<li><a href="/mailfence/login.html">mailfence</a></li><li><a href="/basic">basic auth</a></li></ul>`);
      }
      const file = normalize(join(dir, url.pathname));
      if (!file.startsWith(dir) || !existsSync(file) || !statSync(file).isFile()) return res.writeHead(404).end("not found");
      res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store" }).end(readFileSync(file));
    } catch (e) {
      res.writeHead(500).end(String(e));
    }
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    // "::" also accepts IPv4 on Linux: *.localhost may resolve to either.
    server.listen(port, "::", () => resolve(server));
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await startFixtures();
  console.log(`fixtures on ${Object.values(HOSTS).map((h) => `http://${h}:${FX.port}/`).join("  ")}`);
}
