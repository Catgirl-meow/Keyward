// Passkey shim, in the page's own world at document_start (registered only while a vault is
// unlocked and passkeys are on). It wraps navigator.credentials.create/get: requests go as
// JSON to Keyward's relay content script by window.postMessage; anything Keyward doesn't answer
// (no passkey for the site, a security key asked for, the user's choice) goes to the browser's
// own implementation. Results are built to look like the browser's: PublicKeyCredential
// prototypes, toJSON(), getClientExtensionResults(), getTransports(), getPublicKey()…
// Self-contained: no imports (it ships into every https page).
(() => {
  const w = window as any;
  if (w.__kwPk || !isSecureContext || !navigator.credentials || typeof PublicKeyCredential === "undefined") return;
  Object.defineProperty(w, "__kwPk", { value: 1 });
  const C = CredentialsContainer.prototype;
  const nativeCreate = C.create;
  const nativeGet = C.get;
  const P = PublicKeyCredential as any;

  const bytes = (b: BufferSource) => (b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer, b.byteOffset, b.byteLength));
  const enc = (b: BufferSource) => {
    let s = "";
    for (const x of bytes(b)) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const dec = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)).buffer;
  const desc = (l?: readonly PublicKeyCredentialDescriptor[]) => l?.map((d) => ({ type: d.type, id: enc(d.id), transports: d.transports ? [...d.transports] : undefined }));
  const plain = <T>(o: T): T | undefined => (o == null ? undefined : JSON.parse(JSON.stringify(o)));

  const waiting = new Map<string, (r: any) => void>();
  addEventListener("message", (e) => {
    const d = e.data;
    if (e.source === window && d?.kwPk === "res" && waiting.has(d.id)) waiting.get(d.id)!(d.r);
  });

  /** `timeout` null: no time limit (an autofill request waits for the user's pick). */
  function call(kind: string, options: unknown, signal?: AbortSignal | null, timeout?: number | null): Promise<any> {
    return new Promise((resolve, reject) => {
      const abortErr = () => signal?.reason ?? new DOMException("The operation was aborted.", "AbortError");
      if (signal?.aborted) return reject(abortErr());
      const id = Math.random().toString(36).slice(2);
      const end = () => {
        clearTimeout(t);
        signal?.removeEventListener("abort", onAbort);
        waiting.delete(id);
      };
      const stop = (err: unknown) => {
        end();
        postMessage({ kwPk: "cancel", id }, "*");
        reject(err);
      };
      const onAbort = () => stop(abortErr());
      const t = timeout === null ? 0 : setTimeout(() => stop(new DOMException("The operation either timed out or was not allowed.", "NotAllowedError")), Math.min(Math.max(timeout || 300_000, 30_000), 600_000));
      signal?.addEventListener("abort", onAbort);
      waiting.set(id, (r) => {
        end();
        resolve(r);
      });
      postMessage({ kwPk: "req", id, kind, options }, "*");
    });
  }

  const define = <T extends object>(o: T, props: Record<string, unknown>): T => {
    for (const k of Object.keys(props)) Object.defineProperty(o, k, { value: props[k], enumerable: true });
    return o;
  };

  function credential(j: any, created: boolean): PublicKeyCredential {
    const r = j.response;
    const resp = Object.create((created ? AuthenticatorAttestationResponse : AuthenticatorAssertionResponse).prototype);
    if (created) {
      const ad = dec(r.authenticatorData);
      const pub = dec(r.publicKey);
      define(resp, {
        clientDataJSON: dec(r.clientDataJSON),
        attestationObject: dec(r.attestationObject),
        getTransports: () => [...r.transports],
        getAuthenticatorData: () => ad.slice(0),
        getPublicKey: () => pub.slice(0),
        getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
      });
    } else {
      define(resp, { clientDataJSON: dec(r.clientDataJSON), authenticatorData: dec(r.authenticatorData), signature: dec(r.signature), userHandle: r.userHandle ? dec(r.userHandle) : null });
    }
    return define(Object.create(PublicKeyCredential.prototype), {
      id: j.id,
      rawId: dec(j.rawId),
      type: "public-key",
      authenticatorAttachment: j.authenticatorAttachment,
      response: resp,
      getClientExtensionResults: () => plain(j.clientExtensionResults),
      toJSON: () => plain(j),
    });
  }

  const raise = (r: any) => {
    throw r.error === "TypeError" ? new TypeError(r.message) : new DOMException(r.message, r.error);
  };

  async function create(this: CredentialsContainer, o?: CredentialCreationOptions): Promise<Credential | null> {
    const pk = o?.publicKey;
    if (!pk) return nativeCreate.call(this, o);
    let j;
    try {
      j = {
        rp: { id: pk.rp.id, name: pk.rp.name },
        user: { id: enc(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
        challenge: enc(pk.challenge),
        pubKeyCredParams: plain(pk.pubKeyCredParams),
        timeout: pk.timeout,
        excludeCredentials: desc(pk.excludeCredentials),
        authenticatorSelection: plain(pk.authenticatorSelection),
        attestation: pk.attestation,
        extensions: (pk.extensions as any)?.credProps ? { credProps: true } : undefined,
      };
    } catch {
      return nativeCreate.call(this, o);
    }
    const r = await call("create", j, o!.signal, pk.timeout);
    if (r?.ok) return credential(r.ok, true);
    if (r?.error) raise(r);
    return nativeCreate.call(this, o);
  }

  async function get(this: CredentialsContainer, o?: CredentialRequestOptions): Promise<Credential | null> {
    const pk = o?.publicKey;
    if (!pk) return nativeGet.call(this, o);
    const conditional = (o as any).mediation === "conditional";
    let j;
    try {
      j = { challenge: enc(pk.challenge), timeout: pk.timeout, rpId: pk.rpId, allowCredentials: desc(pk.allowCredentials), userVerification: pk.userVerification, mediation: conditional ? "conditional" : undefined };
    } catch {
      return nativeGet.call(this, o);
    }
    if (conditional) return race.call(this, o!, j);
    const r = await call("get", j, o!.signal, pk.timeout);
    if (r?.ok) return credential(r.ok, false);
    if (r?.error) raise(r);
    return nativeGet.call(this, o);
  }

  /** A conditional get(): Keyward's passkeys wait in the field's inline menu while the browser's
   * own autofill request runs too; the first the user picks answers, the other is withdrawn. */
  function race(this: CredentialsContainer, o: CredentialRequestOptions, j: object): Promise<Credential | null> {
    return new Promise((resolve, reject) => {
      const page = o.signal;
      const toBrowser = new AbortController();
      const toKeyward = new AbortController();
      const onAbort = () => toBrowser.abort(page!.reason);
      page?.addEventListener("abort", onAbort, { once: true });
      const done = () => page?.removeEventListener("abort", onAbort);
      let kwOut = false;
      let nativeErr: unknown = null;
      const keywardOut = () => {
        kwOut = true;
        if (nativeErr) (done(), reject(nativeErr));
      };
      const signal = page ? AbortSignal.any([page, toKeyward.signal]) : toKeyward.signal;
      call("get", j, signal, null).then(
        (r) => {
          if (r?.ok || r?.error) {
            toBrowser.abort();
            done();
            if (r.ok) resolve(credential(r.ok, false));
            else
              try {
                raise(r);
              } catch (e) {
                reject(e);
              }
          } else keywardOut(); // nothing for this site in Keyward: the browser's request alone
        },
        keywardOut,
      );
      nativeGet.call(this, { ...o, signal: toBrowser.signal }).then(
        (c) => {
          toKeyward.abort();
          done();
          resolve(c);
        },
        (e) => {
          nativeErr = page?.aborted ? page.reason : e;
          if (kwOut || page?.aborted) (done(), reject(nativeErr));
        },
      );
    });
  }

  const put = (o: object, k: string, v: unknown) => Object.defineProperty(o, k, { value: v, writable: true, configurable: true });
  put(C, "create", create);
  put(C, "get", get);
  // Keyward is a platform authenticator with user verification (the unlocked vault).
  put(P, "isUserVerifyingPlatformAuthenticatorAvailable", async () => true);
  // …that offers its passkeys in sign-in fields' autofill (the inline menu).
  put(P, "isConditionalMediationAvailable", async () => true);
  const caps = P.getClientCapabilities;
  if (caps) put(P, "getClientCapabilities", async () => ({ ...(await caps.call(P).catch(() => ({}))), conditionalGet: true, passkeyPlatformAuthenticator: true, userVerifyingPlatformAuthenticator: true }));
})();
