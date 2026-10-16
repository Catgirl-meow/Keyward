// Passkey dialog, shown in the page (top frame) when a site calls navigator.credentials.get()
// or create() and Keyward can answer: pick a passkey, or save a new one to a login. "Use browser
// or security key" hands the request back to the browser.
import "../../theme/base.css";
import "../../components/kit.css";
import "../menu/menu.css";
import "../savebar/savebar.css";
import "./passkey.css";
import { render } from "preact";
import { useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";
import { rpc, type PasskeyCtx } from "../../../platform/messages.ts";
import { loadSettings } from "../../../platform/settings.ts";
import { Avatar, Button, Icon, IconButton, SecretField, Select } from "../../components/kit.tsx";
import * as I from "../../icons/index.ts";
import { applyCachedTheme, applyTheme } from "../../theme/theme.ts";
import { verifyMasterPassword } from "../../data/master-password.ts";
import { overlayChannel, overlayToken } from "../../data/overlay-token.ts";

applyCachedTheme();

// Clicks count only when the dialog is really what the user sees (Chromium's IntersectionObserver
// v2) and has been up for a moment: a page can't trick the user into approving.
let reallyVisible = !(__CHROMIUM__ && "IntersectionObserver" in window);
if (!reallyVisible) {
  try {
    new IntersectionObserver((es) => (reallyVisible = es.some((e) => (e as any).isVisible)), { threshold: [1], trackVisibility: true, delay: 100 } as any).observe(document.documentElement);
  } catch {
    reallyVisible = true;
  }
}
const shownAt = performance.now();
const clickOk = (e?: Event) => !e || !(e instanceof MouseEvent) || e.detail === 0 || (e.isTrusted && performance.now() - shownAt >= 300 && reallyVisible);

type Action = { action: "use" | "save" | "fallback" | "cancel"; itemId?: string; credentialId?: string };

function Dialog() {
  const [ctx, setCtx] = useState<PasskeyCtx | null | undefined>(undefined);
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** an action waiting for the master password (protected item) */
  const [verify, setVerify] = useState<Action | null>(null);
  const [pw, setPw] = useState("");
  const port = useRef<MessagePort | null>(null);
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    void (async () => {
      const [token, s] = await Promise.all([overlayToken, loadSettings()]);
      applyTheme(s);
      port.current = (await overlayChannel).port;
      const c = await rpc("pk.ctx", { token }).catch(() => null);
      // A protected passkey picked in the inline menu: straight to the master password.
      const one = c?.kind === "get" && c.picked && c.passkeys.length === 1 ? c.passkeys[0] : null;
      if (one?.reprompt) setVerify({ action: "use", itemId: one.itemId, credentialId: one.credentialId });
      setCtx(c);
    })();
  }, []);
  useLayoutEffect(() => {
    port.current?.postMessage({ t: "size", h: root.current?.offsetHeight ?? 0 });
  });
  // Browsers ignore `autofocus` in a cross-origin frame: once the content script has focused
  // this frame, put the keyboard on the default choice (Enter confirms, Escape cancels) or on
  // the master password field.
  useEffect(() => {
    root.current?.querySelector<HTMLElement>("[data-default], form input")?.focus({ preventScroll: true });
  }, [ctx, verify]);

  async function decide(a: Action, e?: Event, verified = false) {
    if (busy || !clickOk(e)) return;
    const protectedItem =
      ctx?.kind === "get" ? ctx.passkeys.find((p) => p.itemId === a.itemId)?.reprompt : ctx?.kind === "create" ? ctx.targets.find((t) => t.itemId === a.itemId)?.reprompt : false;
    if ((a.action === "use" || a.action === "save") && protectedItem && !verified) return setVerify(a);
    setBusy(true);
    setError(null);
    try {
      await rpc("pk.decide", { token: await overlayToken, ...a });
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if (e.key === "Escape") void decide({ action: "cancel" });
    };
    addEventListener("keydown", on);
    return () => removeEventListener("keydown", on);
  });

  if (ctx === undefined) return <div ref={root} />;
  const close = <IconButton icon={I.close} label="Cancel" small onClick={(e: Event) => void decide({ action: "cancel" }, e)} />;
  const fallback = (
    <Button variant="text" disabled={busy} onClick={(e: Event) => void decide({ action: "fallback" }, e)}>
      Use browser or security key
    </Button>
  );

  if (ctx === null)
    return (
      <div ref={root} class="kwm kws kwp" role="dialog" aria-label="Passkey">
        <div class="kws-top">
          <div class="kwm-ico"><Icon d={I.passkey} size={20} /></div>
          <div class="text"><div class="title">This request has expired</div></div>
          {close}
        </div>
      </div>
    );

  if (verify)
    return (
      <div ref={root} class="kwm kws kwp" role="dialog" aria-label="Confirm it's you">
        <div class="kws-top">
          <div class="kwm-ico"><Icon d={I.lock} size={20} /></div>
          <div class="text">
            <div class="title">Confirm it's you</div>
            <div class="sub">This item is protected. Enter your master password.</div>
          </div>
          {close}
        </div>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            const ok = await verifyMasterPassword(pw).catch(() => false);
            setBusy(false);
            if (!ok) return setError("Invalid master password");
            const a = verify;
            setVerify(null);
            void decide(a, undefined, true);
          }}
        >
          <SecretField label="Master password" value={pw} onInput={setPw} autoFocus error={error} />
          <div class="kws-actions">
            <Button variant="text" onClick={() => (setVerify(null), setError(null))}>Back</Button>
            <Button type="submit" loading={busy} disabled={!pw}>Confirm</Button>
          </div>
        </form>
      </div>
    );

  if (ctx.kind === "get")
    return (
      <div ref={root} class="kwm kws kwp" role="dialog" aria-label="Sign in with a passkey">
        <div class="kws-top">
          <div class="kwm-ico"><Icon d={I.passkey} size={20} /></div>
          <div class="text">
            <div class="title">Sign in with a passkey</div>
            <div class="sub">{ctx.host}</div>
          </div>
          {close}
        </div>
        <div class="kwm-list" role="listbox">
          {ctx.passkeys.map((p, i) => (
            <button
              type="button"
              class="kwm-row kwp-row"
              data-default={i === 0 ? "" : undefined}
              disabled={busy}
              onClick={(e) => void decide({ action: "use", itemId: p.itemId, credentialId: p.credentialId }, e)}
            >
              <Avatar seed={p.itemId} name={p.itemName} />
              <div class="text">
                <div class="title">{p.userName || p.displayName || p.itemName}</div>
                <div class="sub">{p.itemName}</div>
              </div>
              {p.reprompt && <Icon d={I.lock} size={18} />}
            </button>
          ))}
        </div>
        {error && <div class="kwm-error">{error}</div>}
        <div class="kws-actions">{fallback}</div>
      </div>
    );

  const who = ctx.userName || ctx.displayName;
  return (
    <div ref={root} class="kwm kws kwp" role="dialog" aria-label="Save a passkey">
      <div class="kws-top">
        <div class="kwm-ico"><Icon d={I.passkey} size={20} /></div>
        <div class="text">
          <div class="title">{ctx.exists ? "Passkey already saved" : "Save a passkey?"}</div>
          <div class="sub">
            {who ? <b>{who}</b> : "A new passkey"} on {ctx.rpId}
          </div>
        </div>
        {close}
      </div>
      {ctx.exists ? (
        <div class="kwm-empty">Keyward already has a passkey for this account on {ctx.rpId}.</div>
      ) : (
        ctx.targets.length > 0 && (
          <div class="kws-folder">
            <Select
              label="Save to"
              value={target}
              onChange={setTarget}
              options={[["", "A new login"], ...ctx.targets.map((t) => [t.itemId, `${t.name}${t.userName ? ` (${t.userName})` : ""}${t.hasPasskey ? " — replaces its passkey" : ""}`] as [string, string])]}
            />
          </div>
        )
      )}
      {error && <div class="kwm-error">{error}</div>}
      <div class="kws-actions">
        {ctx.exists ? (
          <Button data-default="" onClick={(e: Event) => void decide({ action: "save" }, e)}>OK</Button>
        ) : (
          <>
            {fallback}
            <Button data-default="" loading={busy} onClick={(e: Event) => void decide({ action: "save", itemId: target || undefined }, e)}>
              Save
            </Button>
          </>
        )}
      </div>
    </div>
  );
}

render(<Dialog />, document.getElementById("app")!);
