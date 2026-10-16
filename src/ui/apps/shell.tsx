// Shared app shell for the popup (400×600, bottom bar) and the full-tab vault (rail + two panes).
import "../theme/base.css";
import "../components/kit.css";
import "./app.css";
import { signal } from "@preact/signals";
import { h, render, type ComponentChildren, type ComponentType } from "preact";
import { useEffect, useState } from "preact/hooks";
import type { Summary } from "../../core/vault/types.ts";
import { loadPending } from "../../platform/login.ts";
import { rpc, type PageMatch } from "../../platform/messages.ts";
import { ConfirmHost, EmptyState, Icon, MenuHost, Toasts, confirm, toast } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { applyCachedTheme } from "../theme/theme.ts";
import { account, addingAccount, boot, phase, syncNow, syncStatus, syncing } from "../data/app.ts";
import { direction, home, pop, push, stack, tab, type Route, type Tab } from "../data/nav.ts";
import { recentlyVerified } from "../data/reprompt.ts";
import { AccountButton } from "../screens/account-menu.tsx";
import { newItemMenu, selectedId, usePageMatches, VaultList } from "../screens/vault-list.tsx";

// Screens not needed for the first paint load as separate chunks. All of them start loading
// right after mount (local files, ~1 ms each), so navigation never waits on them in practice.
const loaded = signal(0);
function lazy<P>(load: () => Promise<ComponentType<P>>) {
  let C: ComponentType<P> | null = null;
  let p: Promise<void> | null = null;
  const start = () =>
    (p ??= load().then((c) => {
      C = c;
      loaded.value++;
    }));
  const L = (props: P) => {
    void loaded.value;
    if (!C) {
      void start();
      return null;
    }
    return h(C as ComponentType<any>, props as any);
  };
  L.preload = start;
  return L;
}
const auth = () => import("../screens/auth.tsx");
const LoginScreen = lazy(() => auth().then((m) => m.LoginScreen));
const UnlockScreen = lazy(() => auth().then((m) => m.UnlockScreen));
const GeneratorScreen = lazy(() => import("../screens/generator.tsx").then((m) => m.GeneratorScreen));
const ItemEdit = lazy(() => import("../screens/item-edit.tsx").then((m) => m.ItemEdit));
const ItemView = lazy(() => import("../screens/item-view.tsx").then((m) => m.ItemView));
const PasswordHistory = lazy(() => import("../screens/item-view.tsx").then((m) => m.PasswordHistory));
const RepromptSheet = lazy(() => import("../screens/item-view.tsx").then((m) => m.RepromptSheet));
const settingsMod = () => import("../screens/settings.tsx");
const SettingsScreen = lazy(() => settingsMod().then((m) => m.SettingsScreen));
const SettingsPage = lazy(() => settingsMod().then((m) => m.SettingsPage));
const watchtowerMod = () => import("../screens/watchtower.tsx");
const WatchtowerScreen = lazy(() => watchtowerMod().then((m) => m.WatchtowerScreen));
const WatchList = lazy(() => watchtowerMod().then((m) => m.WatchList));

export type Mode = "popup" | "tab";

const NAV: { id: Tab; label: string; icon: string; iconOn: string }[] = [
  { id: "vault", label: "Vault", icon: I.home, iconOn: I.homeFill },
  { id: "generator", label: "Generator", icon: I.password, iconOn: I.password },
  { id: "send", label: "Send", icon: I.send, iconOn: I.send },
  { id: "watchtower", label: "Watchtower", icon: I.shield, iconOn: I.shieldFill },
  { id: "settings", label: "Settings", icon: I.settings, iconOn: I.settings },
];

const wideMq = matchMedia("(min-width: 840px)");
const wide = signal(wideMq.matches);
wideMq.addEventListener("change", () => (wide.value = wideMq.matches));

let lastActivity = 0;
function activity() {
  const now = Date.now();
  if (now - lastActivity < 20_000) return;
  lastActivity = now;
  rpc("session.activity").catch(() => {});
}

function selectTab(t: Tab) {
  if (tab.value === t) {
    if (stack.value.length > 1) home(t);
    return;
  }
  tab.value = t;
  direction.value = "forward";
  stack.value = [{ name: "home" }];
  selectedId.value = null;
}

// ---------------------------------------------------------------- navigation bars
function NavBar() {
  return (
    <nav class="navbar" aria-label="Sections">
      {NAV.map((n) => {
        const on = tab.value === n.id;
        return (
          <button key={n.id} type="button" aria-current={on ? "page" : undefined} onClick={() => selectTab(n.id)}>
            <span class="pill"><Icon d={on ? n.iconOn : n.icon} /></span>
            {n.label}
          </button>
        );
      })}
    </nav>
  );
}

function Rail() {
  const st = syncStatus.value;
  return (
    <nav class="rail" aria-label="Sections">
      <button type="button" class="rail-fab" aria-label="New item" title="New item" onClick={(e) => { selectTab("vault"); newItemMenu(e.currentTarget as HTMLElement); }}>
        <Icon d={I.add} />
      </button>
      {NAV.map((n) => {
        const on = tab.value === n.id;
        return (
          <button key={n.id} type="button" aria-current={on ? "page" : undefined} onClick={() => selectTab(n.id)}>
            <span class="pill"><Icon d={on ? n.iconOn : n.icon} /></span>
            {n.label}
          </button>
        );
      })}
      <div class="grow" />
      <button type="button" class="rail-sync" title={st?.error ?? "Sync now"} onClick={() => void syncNow(true)}>
        <span class={`pill ${syncing.value ? "spin-slow" : ""}`}><Icon d={st && !st.ok ? I.cloudOff : syncing.value ? I.sync : I.cloudDone} /></span>
        {syncing.value ? "Syncing" : st && !st.ok ? "Offline" : "Synced"}
      </button>
      <AccountButton />
    </nav>
  );
}

// ---------------------------------------------------------------- routes
function Placeholder({ title, text }: { title: string; text: string }) {
  return (
    <div class="page-enter">
      <div class="topbar"><div class="heading" style={{ paddingLeft: "12px" }}>{title}</div></div>
      <EmptyState text={text} />
    </div>
  );
}

function tabRoot(t: Tab, mode: Mode, pm: ReturnType<typeof usePageMatches>, fill: (id: string) => void, open: (s: Summary) => void) {
  switch (t) {
    case "vault":
      return <VaultList popup={mode === "popup"} onOpen={open} pageMatches={pm} onFill={(m: PageMatch) => fill(m.id)} />;
    case "generator":
      return <GeneratorScreen />;
    case "send":
      return <Placeholder title="Send" text="Share text and files with end-to-end encryption. Coming in a later build." />;
    case "watchtower":
      return <WatchtowerScreen />;
    case "settings":
      return <SettingsScreen />;
  }
}

function routeView(r: Route, embedded: boolean, fill?: (id: string, verified?: boolean) => void): ComponentChildren {
  switch (r.name) {
    case "item":
      return <ItemView id={r.id} embedded={embedded} onFill={fill} />;
    case "edit":
      return <ItemEdit id={r.id} type={r.type} prefill={r.prefill} />;
    case "history":
      return <PasswordHistory id={r.id} />;
    case "settings-page":
      return <SettingsPage page={r.page} />;
    case "folders":
      return <SettingsPage page="folders" />;
    case "watch-list":
      return <WatchList check={r.check} />;
    default:
      return null;
  }
}

function Animated({ k, children }: { k: string; children: ComponentChildren }) {
  return (
    <div key={k} class={`route ${direction.value === "back" ? "page-back" : "page-enter"}`}>
      {children}
    </div>
  );
}

function routeKey(r: Route, depth: number): string {
  return `${depth}:${r.name}:${"id" in r ? r.id ?? "" : ""}:${"page" in r ? r.page : ""}:${"check" in r ? r.check : ""}`;
}

// ---------------------------------------------------------------- main layouts
function Unlocked({ mode }: { mode: Mode }) {
  const popup = mode === "popup";
  const pm = usePageMatches(popup);
  const s = stack.value;
  const top = s[s.length - 1];
  const twoPane = !popup && wide.value && tab.value === "vault";
  const [reprompt, setReprompt] = useState<((ok: boolean) => void) | null>(null);
  const askMasterPassword = () => new Promise<boolean>((resolve) => setReprompt(() => resolve));

  async function fill(id: string, verified = false) {
    const tabId = pm?.tabId;
    if (!tabId) return;
    verified ||= recentlyVerified();
    try {
      let r = await rpc("autofill.fill", { tabId, itemId: id, verified });
      // Master-password re-prompt: the background fills a protected item only once it's confirmed.
      if (r.reprompt) {
        if (!(await askMasterPassword())) return;
        verified = true;
        r = await rpc("autofill.fill", { tabId, itemId: id, verified });
      }
      // A cross-site frame, or an https item on an http page: the background asks first.
      if (r.confirm) {
        if (!(await confirm("Check before filling", r.confirm, "Fill"))) return;
        r = await rpc("autofill.fill", { tabId, itemId: id, verified, force: true });
      }
      if (r.filled) {
        if (r.totpCopied) toast("Filled · verification code copied", { tone: "ok" });
        setTimeout(() => window.close(), r.totpCopied ? 600 : 0);
      } else toast(r.error ?? "Nothing to fill on this page", { tone: "error" });
    } catch (e) {
      toast((e as Error).message, { tone: "error" });
    }
  }

  function open(item: Summary) {
    selectedId.value = item.id;
    if (twoPane) {
      direction.value = "forward";
      stack.value = [{ name: "home" }, { name: "item", id: item.id }];
    } else push({ name: "item", id: item.id });
  }

  useEffect(() => {
    // Esc goes back one screen (inputs handle Esc themselves first).
    const k = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !e.defaultPrevented && stack.value.length > 1 && !document.querySelector(".scrim, .menu")) {
        e.preventDefault();
        pop();
      }
    };
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, []);

  useEffect(() => {
    if (!twoPane && top.name !== "item") selectedId.value = null;
  }, [twoPane, top]);

  const root = tabRoot(tab.value, mode, pm, fill, open);
  const verify = reprompt && (
    <RepromptSheet
      onDone={() => {
        setReprompt(null);
        reprompt(true);
      }}
      onCancel={() => {
        setReprompt(null);
        reprompt(false);
      }}
    />
  );

  if (twoPane) {
    return (
      <div class="layout tab">
        <Rail />
        <div class="split">
          <section class="pane list" aria-label="Items">{root}</section>
          <section class="pane detail" aria-label="Details">
            {s.length > 1 ? (
              <Animated k={routeKey(top, s.length)}>{routeView(top, true)}</Animated>
            ) : (
              <EmptyState text="Select an item to see its details" icon={I.inventory} />
            )}
          </section>
        </div>
      </div>
    );
  }

  const body = (
    <main class="content" onPointerDown={activity} onKeyDown={activity}>
      {s.length > 1 ? <Animated k={routeKey(top, s.length)}>{routeView(top, false, popup ? fill : undefined)}</Animated> : <Animated k={`root:${tab.value}`}>{root}</Animated>}
      {tab.value === "vault" && s.length === 1 && (
        <button type="button" class="fab" onClick={(e) => newItemMenu(e.currentTarget as HTMLElement)}>
          <Icon d={I.add} />
          New
        </button>
      )}
      {verify}
    </main>
  );

  if (popup) {
    return (
      <div class="layout popup">
        {body}
        <NavBar />
      </div>
    );
  }
  return (
    <div class="layout tab">
      <Rail />
      <div class={`single ${tab.value === "vault" ? "" : "narrow"}`}>{body}</div>
    </div>
  );
}

function App({ mode }: { mode: Mode }) {
  const p = phase.value;
  if (p === "boot") return null;
  let screen: ComponentChildren;
  if (p === "login" || addingAccount.value) {
    screen = <LoginScreen onCancel={addingAccount.value && account.value ? () => (addingAccount.value = false) : undefined} />;
  } else if (p === "locked") {
    screen = <UnlockScreen key={account.value?.id} />;
  } else {
    return (
      <>
        <Unlocked mode={mode} />
        <Overlays />
      </>
    );
  }
  return (
    <>
      <div class={`layout auth-layout ${mode}`}>{screen}</div>
      <Overlays />
    </>
  );
}

function Overlays() {
  return (
    <>
      <MenuHost />
      <ConfirmHost />
      <Toasts />
    </>
  );
}

export async function mount(mode: Mode) {
  document.documentElement.dataset.mode = mode;
  applyCachedTheme();
  const el = document.getElementById("app")!;
  render(<App mode={mode} />, el);
  if (mode === "popup") {
    // The background locks on disconnect when "lock when the popup closes" is selected.
    chrome.runtime.connect({ name: "popup" });
  }
  const booting = boot();
  void UnlockScreen.preload();
  await booting;
  void ItemView.preload();
  setTimeout(() => [ItemEdit, GeneratorScreen, SettingsScreen, WatchtowerScreen].forEach((c) => void c.preload()), 50);
  if (await loadPending()) addingAccount.value = phase.value !== "login";
  // "Check on open": the background pushes the lock deadline and runs a cheap revision-date
  // check; a full sync happens only if something changed.
  if (phase.value === "unlocked") activity();
  const hash = location.hash.slice(1);
  if (hash.startsWith("item=") && phase.value === "unlocked") {
    tab.value = "vault";
    selectedId.value = hash.slice(5);
    stack.value = [{ name: "home" }, { name: "item", id: hash.slice(5) }];
  }
}
