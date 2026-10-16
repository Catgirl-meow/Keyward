// Inline autofill menu, shown in an iframe under a page's field. It gets its data from the
// background (which knows the tab and frame it belongs to) and talks to the field's content
// script over a port; the page itself never sees the list.
import "../../theme/base.css";
import "../../components/kit.css";
import "./menu.css";
import { render } from "preact";
import { useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";
import { generatePassphrase, generatePassword } from "../../../core/generator/password.ts";
import { loadAccounts } from "../../../platform/accounts.ts";
import { loadGeneratorPrefs } from "../../../platform/generator.ts";
import { listen, rpc, type RpcRes } from "../../../platform/messages.ts";
import { loadSettings, type Settings } from "../../../platform/settings.ts";
import { Avatar, Icon, Spinner } from "../../components/kit.tsx";
import * as I from "../../icons/index.ts";
import { applyCachedTheme, applyTheme } from "../../theme/theme.ts";
import { overlayChannel, overlayToken } from "../../data/overlay-token.ts";

applyCachedTheme();
type Ctx = RpcRes<"menu.ctx">;
type Item = Ctx["items"][number];
type Passkey = Ctx["passkeys"][number];
type Entry = { kind: "passkey"; pk: Passkey } | { kind: "item"; item: Item } | { kind: "generate"; value: string } | { kind: "open" } | { kind: "unlock" } | { kind: "force"; item: Item } | { kind: "back" };

const TYPE_ICON: Record<number, string> = { 1: I.key, 3: I.card, 4: I.badge };

// Visibility as the user sees it (Chromium's IntersectionObserver v2): a menu that is covered,
// transparent or transformed by the page doesn't accept clicks.
let reallyVisible = !(__CHROMIUM__ && "IntersectionObserver" in window);
if (!reallyVisible) {
  try {
    new IntersectionObserver((es) => (reallyVisible = es.some((e) => (e as any).isVisible)), { threshold: [1], trackVisibility: true, delay: 100 } as any).observe(document.documentElement);
  } catch {
    reallyVisible = true;
  }
}
const shownAt = performance.now();

function Menu() {
  const [ctx, setCtx] = useState<Ctx | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [server, setServer] = useState<string | null>(null);
  const [sel, setSel] = useState(-1);
  /** `sel` for the port's handler, current between renders */
  const selRef = useRef(-1);
  const [q, setQ] = useState("");
  const [gen, setGen] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The background wants a yes first (an https item on an http page): its reason, and the item.
  const [ask, setAsk] = useState<{ item: Item; text: string; at: number } | null>(null);
  const port = useRef<MessagePort | null>(null);
  const root = useRef<HTMLDivElement>(null);

  async function load() {
    const token = await overlayToken;
    const [c, s, a] = await Promise.all([rpc("menu.ctx", { token }), loadSettings(), loadAccounts()]);
    applyTheme(s);
    // The channel first: the first render with data reports its size through it.
    if (!port.current) {
      const { port: pt } = await overlayChannel;
      // The field keeps focus, so the content script forwards the arrow keys and Enter. They
      // arrive in order on this port and apply to the rows shown here, so a fast ArrowDown +
      // Enter neither waits for a round trip nor picks by an index from an older list.
      pt.onmessage = (e) => {
        const m = e.data;
        if (m?.t === "key") {
          const n = entriesRef.current.length;
          const s = selRef.current;
          if (m.k === "enter") {
            const en = entriesRef.current[s];
            if (en) void pickRef.current(en, false);
          } else if (n) select(m.k === "down" ? (s + 1) % n : s <= 0 ? n - 1 : s - 1);
        } else if (m?.t === "filter") {
          // Other rows now: nothing stays selected, so Enter can't pick one the user didn't see.
          setQ(String(m.q ?? ""));
          setAsk(null);
          select(-1);
        }
      };
      port.current = pt;
      pt.postMessage({ t: "ready" });
    }
    if (c.purpose === "newPassword" && !c.locked) {
      const p = await loadGeneratorPrefs();
      setGen(p.mode === "passphrase" ? await generatePassphrase(p.passphrase) : generatePassword(p.password));
    }
    setSettings(s);
    setServer(a.list.find((x) => x.id === a.active)?.server ?? null);
    setCtx(c);
    select(-1); // fresh rows (a sync or unlock may have changed them)
  }

  useEffect(() => {
    load().catch((e) => setError((e as Error).message));
    // Unlocking in the popup, or a sync, refreshes the list.
    return listen((m) => {
      if (m.kind === "lock" || m.kind === "vault") void load().catch(() => {});
    });
  }, []);

  const qq = q.trim().toLowerCase();
  const items = (ctx?.items ?? []).filter((i) => !qq || i.name.toLowerCase().includes(qq) || i.sub.toLowerCase().includes(qq));
  // The page waits for a passkey from this field: Keyward's come first.
  const passkeys = (ctx?.passkeys ?? []).filter((p) => !qq || [p.userName, p.displayName, p.itemName].some((x) => x?.toLowerCase().includes(qq)));
  const entries: Entry[] = ctx?.locked
    ? [{ kind: "unlock" }]
    : ask
      ? [{ kind: "force", item: ask.item }, { kind: "back" }]
      : [
          ...passkeys.map((pk) => ({ kind: "passkey" as const, pk })),
          ...items.map((item) => ({ kind: "item" as const, item })),
          ...(gen ? [{ kind: "generate" as const, value: gen }] : []),
          { kind: "open" },
        ];

  const entriesRef = useRef<Entry[]>([]);
  entriesRef.current = entries;

  // Size the iframe to the content; `n` is how many rows the keyboard can select.
  useLayoutEffect(() => {
    const h = root.current?.offsetHeight ?? 0;
    port.current?.postMessage({ t: "size", h: ctx ? h : 0, n: ctx ? entries.length : 0 });
  });

  const select = (i: number) => {
    selRef.current = i;
    setSel(i);
    port.current?.postMessage({ t: "sel", i });
  };

  async function pick(e: Entry, pointer: boolean) {
    if (busy) return;
    // A click right after the menu (or its warning) appears isn't aimed at what's there now.
    if (pointer && (performance.now() - Math.max(shownAt, ask?.at ?? 0) < 300 || !reallyVisible)) return;
    setError(null);
    if (e.kind === "back") {
      setAsk(null);
      return select(-1);
    }
    if (e.kind === "open" || e.kind === "unlock") {
      try {
        await chrome.action.openPopup();
      } catch {
        await rpc("ui.openPopup").catch(() => {});
      }
      return;
    }
    setBusy(true);
    try {
      const token = await overlayToken;
      if (e.kind === "passkey") {
        // Signed in (or, for a protected item, the passkey dialog asks for the master password):
        // the background closes the menu.
        const r = await rpc("menu.passkey", { token, itemId: e.pk.itemId, credentialId: e.pk.credentialId });
        if (r.error) setError(r.error);
        return;
      }
      const r = await rpc("menu.pick", e.kind === "generate" ? { token, generated: e.value } : { token, itemId: e.item.id, force: e.kind === "force" });
      if (r.reprompt) await rpc("ui.openPopup").catch(() => {});
      else if (r.confirm && e.kind === "item") {
        // Nothing selected, so a second Enter can't accept the warning by accident.
        setAsk({ item: e.item, text: r.confirm, at: performance.now() });
        select(-1);
      } else if (!r.filled) setError(r.error ?? "Couldn't fill this page");
      else setAsk(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const pickRef = useRef(pick);
  pickRef.current = pick;
  useEffect(() => {
    if (sel >= entries.length) select(entries.length - 1);
  }, [entries.length]);

  if (!ctx) return <div ref={root} class="kwm" />;
  const icon = (host: string | null) => (host && server && settings?.showFavicons ? `${server.replace(/\/+$/, "")}/icons/${encodeURIComponent(host)}/icon.png` : null);
  const empty = !ctx.locked && !items.length && !passkeys.length;
  const label =
    ctx.purpose === "otp" ? "Fill a verification code" : ctx.purpose === "card" ? "Cards" : ctx.purpose === "identity" ? "Identities" : ctx.host ? `Logins for ${ctx.host}` : "Logins";

  return (
    <div ref={root} class="kwm" role="listbox" aria-label="Keyward">
      <div class="kwm-head">
        <Icon d={I.passkey} size={16} />
        <span>{ctx.locked ? "Keyward is locked" : label}</span>
        {busy && <Spinner size={14} />}
      </div>
      {ask && <div class="kwm-ask" role="alert"><Icon d={I.warning} size={18} /><span>{ask.text}</span></div>}
      {empty && !ask && <div class="kwm-empty">{qq ? `Nothing matches “${q}”` : ctx.purpose === "newPassword" ? "No saved logins here" : "No saved logins for this site"}</div>}
      <div class="kwm-list">
        {entries.map((e, i) => {
          const common = {
            class: `kwm-row ${i === sel ? "sel" : ""}`,
            role: "option" as const,
            "aria-selected": i === sel,
            onMouseEnter: () => select(i),
            onClick: (ev: MouseEvent) => ev.isTrusted && void pick(e, true),
          };
          if (e.kind === "passkey")
            return (
              <div {...common}>
                <div class="kwm-ico"><Icon d={I.passkey} size={20} /></div>
                <div class="text">
                  <div class="title">{e.pk.userName || e.pk.displayName || e.pk.itemName}</div>
                  <div class="sub">Passkey · {e.pk.itemName}</div>
                </div>
                {e.pk.reprompt && <Icon d={I.lock} size={18} />}
              </div>
            );
          if (e.kind === "item")
            return (
              <div {...common}>
                <Avatar seed={e.item.id} name={e.item.name} src={icon(e.item.host)} icon={e.item.type !== 1 ? TYPE_ICON[e.item.type] : undefined} />
                <div class="text">
                  <div class="title">{e.item.name}</div>
                  {e.item.sub && <div class="sub">{e.item.sub}</div>}
                </div>
                {e.item.rp && <Icon d={I.lock} size={18} />}
                {ctx.purpose === "otp" && <Icon d={I.timer} size={18} />}
              </div>
            );
          if (e.kind === "generate")
            return (
              <div {...common}>
                <div class="kwm-ico"><Icon d={I.password} size={20} /></div>
                <div class="text">
                  <div class="title">Use a generated password</div>
                  <div class="sub mono">{e.value}</div>
                </div>
              </div>
            );
          if (e.kind === "force")
            return (
              <div {...common}>
                <div class="kwm-ico"><Icon d={I.keyboard} size={20} /></div>
                <div class="text">
                  <div class="title">Fill anyway</div>
                  <div class="sub">{e.item.name}</div>
                </div>
              </div>
            );
          if (e.kind === "back")
            return (
              <div {...common} class={`${common.class} kwm-foot`}>
                <div class="kwm-ico"><Icon d={I.close} size={18} /></div>
                <div class="text"><div class="title">Cancel</div></div>
              </div>
            );
          if (e.kind === "unlock")
            return (
              <div {...common}>
                <div class="kwm-ico"><Icon d={I.lockOpen} size={20} /></div>
                <div class="text"><div class="title">Unlock to fill</div></div>
              </div>
            );
          return (
            <div {...common} class={`${common.class} kwm-foot`}>
              <div class="kwm-ico"><Icon d={I.openInNew} size={18} /></div>
              <div class="text"><div class="title">Open Keyward</div></div>
            </div>
          );
        })}
      </div>
      {error && <div class="kwm-error">{error}</div>}
    </div>
  );
}

render(<Menu />, document.getElementById("app")!);
