// Minimal Bitwarden/Vaultwarden HTTP client. One shared refresh at a time; every response is
// camelized so callers never care about Vaultwarden's mixed PascalCase/camelCase.
import { camelize, decodeJwt } from "../util/json.ts";

export interface ServerUrls {
  base: string;
  api: string;
  identity: string;
  icons: string;
  notifications: string;
  webVault: string;
}

export function serverUrls(base: string): ServerUrls {
  let b = base.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(b)) b = "https://" + b;
  return { base: b, api: b + "/api", identity: b + "/identity", icons: b + "/icons", notifications: b + "/notifications", webVault: b };
}

export interface ClientInfo {
  deviceType: number; // 2 = Chrome extension, 3 = Firefox extension
  deviceName: string;
  deviceId: string;
  clientVersion: string;
}

export interface Tokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number; // epoch ms
}

export interface TokenStore {
  get(): Promise<Tokens | null>;
  set(t: Tokens | null): Promise<void>;
}

export class ApiError extends Error {
  readonly status: number;
  readonly body: any;
  constructor(status: number, message: string, body: any) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
  get loggedOut(): boolean {
    return this.status === 401 || this.body?.error === "invalid_grant";
  }
}

export class OfflineError extends Error {
  constructor(cause: unknown, message = "Server unreachable") {
    super(message);
    this.name = "OfflineError";
    this.cause = cause;
  }
}

export function errorMessage(body: any, status: number): string {
  if (status === 429) return "Too many requests: the server is rate limiting this device. Wait a moment and try again.";
  if (!body) return `HTTP ${status}`;
  if (typeof body === "string") return body.slice(0, 300) || `HTTP ${status}`;
  const em = body.errorModel ?? body;
  const ve = em.validationErrors;
  if (ve && typeof ve === "object") {
    const first = Object.values(ve).flat()[0];
    if (typeof first === "string" && first) return first;
  }
  // Rocket's own error pages (a request body it couldn't parse, an unknown route) answer
  // {"error": {"code", "reason", "description"}}.
  const rocket = typeof body.error === "object" && body.error ? body.error : null;
  if (rocket) return `The server rejected the request: ${rocket.reason ?? "error"} (HTTP ${rocket.code ?? status})`;
  const text = [em.message, body.error_description, body.error].find((t) => typeof t === "string" && t);
  return text ?? `HTTP ${status}`;
}

type Base = "api" | "identity" | "abs";

/** A server that accepts the connection but never answers would otherwise hold a sync, save or
 * login (and every vault write queued behind it) until the browser gives up, which can take many
 * minutes. Generous enough for a big /sync body on a slow link. */
export const REQUEST_TIMEOUT_MS = 60_000;

export interface RequestOpts {
  base?: Base;
  auth?: boolean;
  form?: boolean;
  raw?: boolean; // return the Response untouched (downloads)
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** ms for the whole exchange, body included (for `raw`, only until the headers); 0 = no limit. */
  timeout?: number;
}

export class Api {
  #refreshing: Promise<Tokens> | null = null;
  readonly urls: ServerUrls;
  readonly client: ClientInfo;
  readonly tokens: TokenStore | null;
  readonly fetchImpl: typeof fetch;

  constructor(urls: ServerUrls, client: ClientInfo, tokens: TokenStore | null = null, fetchImpl: typeof fetch = fetch.bind(globalThis)) {
    this.urls = urls;
    this.client = client;
    this.tokens = tokens;
    this.fetchImpl = fetchImpl;
  }

  baseHeaders(): Record<string, string> {
    return {
      Accept: "application/json",
      "Device-Type": String(this.client.deviceType),
      "Bitwarden-Client-Name": "browser",
      "Bitwarden-Client-Version": this.client.clientVersion,
    };
  }

  url(path: string, base: Base = "api"): string {
    if (base === "abs" || /^https?:\/\//.test(path)) return path.startsWith("/") ? this.urls.base + path : path;
    return (base === "api" ? this.urls.api : this.urls.identity) + path;
  }

  /** One exchange: send, wait for the answer, read its body (a raw success's body is the caller's
   * to read). A network failure or no answer within `timeout` ms is an OfflineError; the caller's
   * own abort passes through. The timer races the fetch rather than trusting the abort alone. */
  async #fetch(url: string, init: RequestInit, raw = false, timeout = REQUEST_TIMEOUT_MS): Promise<{ res: Response; body: any }> {
    const ctl = new AbortController();
    const signal = init.signal ? AbortSignal.any([init.signal, ctl.signal]) : ctl.signal;
    const exchange = (async () => {
      try {
        const res = await this.fetchImpl(url, { cache: "no-store", credentials: "omit", ...init, signal });
        return { res, body: raw && res.ok ? null : await readBody(res) };
      } catch (e) {
        if ((e as Error)?.name === "AbortError" && !ctl.signal.aborted) throw e;
        throw new OfflineError(e);
      }
    })();
    if (timeout <= 0) return exchange;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        ctl.abort();
        reject(new OfflineError(null, `Server didn't respond in ${Math.round(timeout / 1000)} s`));
      }, timeout);
    });
    try {
      return await Promise.race([exchange, expired]);
    } finally {
      clearTimeout(timer);
    }
  }

  async accessToken(force = false): Promise<string> {
    if (!this.tokens) throw new ApiError(401, "Not logged in", null);
    const t = await this.tokens.get();
    if (!t) throw new ApiError(401, "Not logged in", null);
    if (!force && t.expiresAt - Date.now() > 60_000) return t.accessToken;
    this.#refreshing ??= this.#refresh(t).finally(() => (this.#refreshing = null));
    return (await this.#refreshing).accessToken;
  }

  async #refresh(t: Tokens): Promise<Tokens> {
    const clientId = decodeJwt(t.accessToken)?.client_id ?? "browser";
    const { res, body } = await this.#fetch(this.url("/connect/token", "identity"), {
      method: "POST",
      headers: { ...this.baseHeaders(), "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
      body: new URLSearchParams({ grant_type: "refresh_token", client_id: clientId, refresh_token: t.refreshToken }),
    });
    if (!res.ok) {
      const err = new ApiError(res.status, errorMessage(body, res.status), body);
      if (res.status === 400 || res.status === 401) await this.tokens!.set(null);
      throw err;
    }
    const next = tokensFrom(body, t.refreshToken);
    await this.tokens!.set(next);
    return next;
  }

  async request<T = any>(method: string, path: string, body?: unknown, opts: RequestOpts = {}): Promise<T> {
    const auth = opts.auth ?? true;
    const doFetch = async (forceRefresh: boolean) => {
      const headers: Record<string, string> = { ...this.baseHeaders(), ...opts.headers };
      if (auth) headers.Authorization = "Bearer " + (await this.accessToken(forceRefresh));
      let payload: BodyInit | undefined;
      if (body instanceof FormData || body instanceof Blob || body instanceof ArrayBuffer) payload = body as BodyInit;
      else if (opts.form) {
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
        payload = new URLSearchParams(body as Record<string, string>);
      } else if (body !== undefined) {
        headers["Content-Type"] = "application/json; charset=utf-8";
        payload = JSON.stringify(body);
      }
      return this.#fetch(this.url(path, opts.base), { method, headers, body: payload, signal: opts.signal }, opts.raw, opts.timeout);
    };
    let { res, body: data } = await doFetch(false);
    if (res.status === 401 && auth) ({ res, body: data } = await doFetch(true));
    if (!res.ok) throw new ApiError(res.status, errorMessage(data, res.status), opts.raw ? null : data);
    return (opts.raw ? res : data) as T;
  }

  get<T = any>(path: string, opts?: RequestOpts) {
    return this.request<T>("GET", path, undefined, opts);
  }
  post<T = any>(path: string, body?: unknown, opts?: RequestOpts) {
    return this.request<T>("POST", path, body, opts);
  }
  put<T = any>(path: string, body?: unknown, opts?: RequestOpts) {
    return this.request<T>("PUT", path, body, opts);
  }
  delete<T = any>(path: string, body?: unknown, opts?: RequestOpts) {
    return this.request<T>("DELETE", path, body, opts);
  }

  /** Identity token endpoint: returns status + body without throwing (400 carries 2FA data). */
  async identityToken(form: Record<string, string>): Promise<{ status: number; body: any }> {
    const { res, body } = await this.#fetch(this.url("/connect/token", "identity"), {
      method: "POST",
      headers: { ...this.baseHeaders(), "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
      body: new URLSearchParams(form),
    });
    return { status: res.status, body };
  }
}

async function readBody(res: Response): Promise<any> {
  if (res.status === 204) return null;
  const text = await res.text();
  if (!text) return null;
  try {
    return camelize(JSON.parse(text));
  } catch {
    return text;
  }
}

export function tokensFrom(body: any, prevRefresh?: string): Tokens {
  return {
    accessToken: body.access_token,
    refreshToken: body.refresh_token || prevRefresh || "",
    expiresAt: Date.now() + (Number(body.expires_in) || 3600) * 1000,
  };
}
