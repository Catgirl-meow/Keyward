// HTTPS → HTTP proxy for clients that refuse plain http (the official bw CLI). A throwaway
// self-signed certificate is created in .cache/tls on first use.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { request } from "node:http";
import { createServer, type Server } from "node:https";
import { join } from "node:path";

const dir = join(new URL("../..", import.meta.url).pathname, ".cache/tls");
export const CERT = join(dir, "cert.pem");

function ensureCert() {
  if (existsSync(CERT)) return;
  mkdirSync(dir, { recursive: true });
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "3650",
    "-keyout", join(dir, "key.pem"), "-out", CERT, "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
  ], { stdio: "ignore" });
}

export function startTlsProxy(target: string, port = 8443): Promise<{ url: string; server: Server }> {
  ensureCert();
  const t = new URL(target);
  const server = createServer({ cert: readFileSync(CERT), key: readFileSync(join(dir, "key.pem")) }, (req, res) => {
    const up = request(
      { host: t.hostname, port: t.port || 80, method: req.method, path: req.url, headers: { ...req.headers, host: t.host } },
      (r) => {
        res.writeHead(r.statusCode ?? 502, r.headers);
        r.pipe(res);
      },
    );
    up.on("error", () => res.writeHead(502).end());
    req.pipe(up);
  });
  return new Promise((ok) => server.listen(port, "127.0.0.1", () => ok({ url: `https://localhost:${port}`, server })));
}
