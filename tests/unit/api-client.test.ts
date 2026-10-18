import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Api, errorMessage, OfflineError, REQUEST_TIMEOUT_MS, serverUrls, type Tokens } from "../../src/core/api/client.ts";

const CLIENT = { deviceType: 2, deviceName: "test", deviceId: "dev", clientVersion: "test" };

function apiWith(fetchImpl: (url: string, init: RequestInit) => Promise<Response>) {
  let tokens: Tokens | null = { accessToken: "a.e30.s", refreshToken: "r", expiresAt: Date.now() + 3_600_000 };
  const store = { get: async () => tokens, set: async (t: Tokens | null) => void (tokens = t) };
  const stub = vi.fn(fetchImpl);
  return { api: new Api(serverUrls("https://vw.test"), CLIENT, store, stub as unknown as typeof fetch), stub };
}

/** Like the real fetch: settles only when told to, or rejects once its signal aborts. */
function pending() {
  let resolve!: (r: Response) => void;
  const fetchImpl = (_url: string, init: RequestInit) =>
    new Promise<Response>((res, rej) => {
      resolve = res;
      if (init.signal?.aborted) return rej(init.signal.reason);
      init.signal?.addEventListener("abort", () => rej(init.signal!.reason));
    });
  return { fetchImpl, resolve: (r: Response) => resolve(r) };
}

/** A body stream the test feeds by hand. */
function stream() {
  let ctl!: ReadableStreamDefaultController<Uint8Array>;
  const body = new ReadableStream<Uint8Array>({ start: (c) => void (ctl = c) });
  return { body, push: (s: string) => ctl.enqueue(new TextEncoder().encode(s)), end: () => ctl.close() };
}

const signalOf = (stub: ReturnType<typeof vi.fn>) => (stub.mock.calls[0][1] as RequestInit).signal!;

describe("api client timeout", () => {
  beforeEach(() => void vi.useFakeTimers());
  afterEach(() => void vi.useRealTimers());

  it("gives up on a server that never answers, as an OfflineError, and aborts the fetch", async () => {
    // Ignores its signal entirely: the timeout must not depend on fetch honouring the abort.
    const { api, stub } = apiWith(() => new Promise<Response>(() => {}));
    const p = api.get("/sync");
    const settled = vi.fn();
    p.then(settled, settled);

    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS - 1);
    expect(settled).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    const err = await p.catch((e) => e);
    expect(err).toBeInstanceOf(OfflineError);
    expect(err.message).toMatch(/didn't respond in 60 s/);
    expect(signalOf(stub).aborted).toBe(true);
  });

  it("counts the body: headers then silence still times out", async () => {
    const s = stream();
    const { api } = apiWith(async () => new Response(s.body, { status: 200 }));
    const p = api.post("/ciphers", { name: "x" });
    const check = expect(p).rejects.toBeInstanceOf(OfflineError);
    s.push('{"id":');
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS);
    await check;
  });

  it("times out the login token call too", async () => {
    const { api } = apiWith(pending().fetchImpl);
    const p = api.identityToken({ grant_type: "password" });
    const check = expect(p).rejects.toBeInstanceOf(OfflineError);
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS);
    await check;
  });

  it("an answer in time clears the timer and goes through", async () => {
    const { api, stub } = apiWith(async () => Response.json({ Id: "1", Name: "n" }));
    await expect(api.get("/ciphers/1")).resolves.toEqual({ id: "1", name: "n" });
    expect(vi.getTimerCount()).toBe(0);
    expect(signalOf(stub).aborted).toBe(false);
  });

  it("timeout: 0 (attachment upload) waits as long as the server takes", async () => {
    const f = pending();
    const { api, stub } = apiWith(f.fetchImpl);
    const form = new FormData();
    form.append("data", new Blob([new Uint8Array(1024)]), "blob");
    const p = api.request("POST", "/ciphers/1/attachment/2", form, { timeout: 0 });
    await vi.advanceTimersByTimeAsync(30 * 60_000);
    expect(signalOf(stub).aborted).toBe(false);
    f.resolve(new Response(null, { status: 200 }));
    await expect(p).resolves.toBeNull();
  });

  it("raw (attachment download): the limit covers the headers, never the transfer", async () => {
    const s = stream();
    const { api, stub } = apiWith(async () => new Response(s.body, { status: 200 }));
    const res = await api.request<Response>("GET", "https://vw.test/attachments/1/2?token=t", undefined, { base: "abs", raw: true, auth: false });
    const bytes = res.arrayBuffer();
    s.push("chunk 1,");
    await vi.advanceTimersByTimeAsync(5 * REQUEST_TIMEOUT_MS);
    s.push("chunk 2");
    s.end();
    expect(new TextDecoder().decode(await bytes)).toBe("chunk 1,chunk 2");
    expect(signalOf(stub).aborted).toBe(false);
  });

  it("raw: a server that never sends headers still times out", async () => {
    const { api } = apiWith(pending().fetchImpl);
    const p = api.request("GET", "https://vw.test/attachments/1/2", undefined, { base: "abs", raw: true, auth: false });
    const check = expect(p).rejects.toBeInstanceOf(OfflineError);
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS);
    await check;
  });

  it("the caller's own abort stays an AbortError", async () => {
    const { api } = apiWith(pending().fetchImpl);
    const ac = new AbortController();
    const p = api.get("/sync", { signal: ac.signal });
    ac.abort();
    const err = await p.catch((e) => e);
    expect(err).not.toBeInstanceOf(OfflineError);
    expect(err.name).toBe("AbortError");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a refused connection is still the plain OfflineError", async () => {
    const { api } = apiWith(async () => {
      throw new TypeError("fetch failed");
    });
    const err = await api.get("/sync").catch((e) => e);
    expect(err).toBeInstanceOf(OfflineError);
    expect(err.message).toBe("Server unreachable");
  });
});

describe("errorMessage", () => {
  it("reads Rocket's error page instead of showing [object Object]", () => {
    const body = { error: { code: 422, reason: "Unprocessable Entity", description: "The request was well-formed but was unable to be followed due to semantic errors." } };
    expect(errorMessage(body, 422)).toBe("The server rejected the request: Unprocessable Entity (HTTP 422)");
  });
  it("prefers the Bitwarden error model's message", () => {
    expect(errorMessage({ message: "The model state is invalid.", validationErrors: { "": ["Invalid user cipher"] }, object: "error" }, 400)).toBe("Invalid user cipher");
    expect(errorMessage({ error: "invalid_grant", error_description: "Username or password is incorrect." }, 400)).toBe("Username or password is incorrect.");
  });
  it("explains a rate limit (a proxy's HTML page or the server's)", () => {
    expect(errorMessage("<html>429 Too Many Requests</html>", 429)).toMatch(/^Too many requests/);
  });
  it("never returns a non-string", () => {
    expect(errorMessage({ validationErrors: { a: [{ x: 1 }] } }, 400)).toBe("HTTP 400");
  });
});
