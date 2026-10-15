// The autofill content script. Injected by the background into one frame, on demand: when the
// user focuses a field there (via the bootstrap), for an explicit fill, or for the next step
// of a multi-step login. Everything here reacts to events; nothing scans the page by itself.
import { allScopes, analyze, deepActive, isFillable, isVisible, kindInScope, purposeOf, scopeOf, type Analysis, type Fillable, type Purpose } from "./classify.ts";
import { filledByUs, fillScope, type FillPlan } from "./fill.ts";
import { Overlay } from "./overlay.ts";
import type { AfFillResult, AfMessage, CsMessage, FieldReply, FillPurpose, FillVia, ScanResult, ScopeInfo, SubmitData } from "./protocol.ts";

(() => {
  const w = window as any;
  if (w.__kwAf) return;
  w.__kwAf = 1;

  const newToken = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");

  const send = <T = unknown>(m: CsMessage): Promise<T | null> => {
    try {
      return chrome.runtime.sendMessage(m).catch(() => null) as Promise<T | null>;
    } catch {
      return Promise.resolve(null); // extension reloaded: this script is orphaned
    }
  };

  // ---------------------------------------------------------------- analysis
  const cache = new WeakMap<Node, { a: Analysis; n: number; at: number }>();
  function analysisFor(el: Element): Analysis {
    const root = scopeOf(el);
    const n = (root as ParentNode).querySelectorAll?.("input,select").length ?? 0;
    const hit = cache.get(root);
    if (hit && hit.n === n && performance.now() - hit.at < 2000 && hit.a.fields.every((f) => f.el.isConnected)) return hit.a;
    const a = analyze(root, { visibleOnly: true });
    cache.set(root, { a, n, at: performance.now() });
    return a;
  }

  function info(a: Analysis): ScopeInfo {
    return {
      type: a.type,
      hasUser: !!a.username,
      hasPw: !!a.password,
      hasNewPw: a.newPasswords.length > 0,
      hasOtp: a.otp.length > 0,
      emptyPw: !!a.password && !a.password.value,
      emptyOtp: a.otp.length > 0 && a.otp.every((b) => !b.value),
      card: Object.keys(a.card).length > 0,
      identity: Object.keys(a.identity).length > 0,
    };
  }

  /** The scope to fill for a purpose: the focused field's, else the best one in the frame. */
  function pickScope(purpose: FillPurpose): Analysis | null {
    const active = deepActive();
    const fits = (a: Analysis) =>
      purpose === "login" ? a.type === "login" || a.type === "change" || a.type === "username" || a.type === "otp" || a.type === "signup"
      : purpose === "totp" ? a.otp.length > 0
      : purpose === "generate" ? a.newPasswords.length > 0
      : purpose === "card" ? Object.keys(a.card).length > 0
      : Object.keys(a.identity).length > 0;
    if (isFillable(active)) {
      const a = analysisFor(active);
      if (fits(a)) return a;
    }
    const rank: Record<string, number> = { login: 0, change: 1, username: 2, otp: 3, signup: 4, card: 5, identity: 6, none: 9 };
    const all = allScopes().filter(fits);
    all.sort((x, y) => (purpose === "generate" ? Number(y.type === "signup") - Number(x.type === "signup") : 0) || rank[x.type] - rank[y.type] || inView(y) - inView(x));
    return all[0] ?? null;
  }
  const inView = (a: Analysis) => {
    const el = a.password ?? a.username ?? a.otp[0] ?? a.fields[0]?.el;
    if (!el) return 0;
    const r = el.getBoundingClientRect();
    return r.bottom > 0 && r.top < innerHeight ? 1 : 0;
  };

  function scan(): ScanResult {
    const active = deepActive();
    let focused: ScanResult["focused"] = null;
    if (isFillable(active)) {
      const a = analysisFor(active);
      focused = { ...info(a), purpose: purposeOf(kindInScope(active, a)) };
    }
    return { url: location.href, top: window === window.top, focused, scopes: allScopes().map(info) };
  }

  function fill(plan: FillPlan, via: FillVia, purpose: FillPurpose): AfFillResult {
    if (via === "menu" && !menu.ov?.trusted()) return { filled: [], otpField: false, error: "The menu was hidden or covered; nothing was filled." };
    const a = pickScope(purpose);
    if (!a) return { filled: [], otpField: false, error: "No matching fields on this page" };
    filling = true;
    let r;
    try {
      r = fillScope(a, plan, deepActive());
    } finally {
      filling = false;
    }
    if (via === "menu") closeMenu(true);
    return r;
  }

  // ---------------------------------------------------------------- inline menu
  const menu = {
    ov: null as Overlay | null,
    field: null as Fillable | null,
    purpose: null as Purpose,
    selected: -1,
    /** rows the menu page can select (reported with its size) */
    rows: 0,
    open: false,
    height: 0,
    raf: 0,
    layout: false,
  };

  function place() {
    menu.raf = 0;
    const ov = menu.ov;
    const el = menu.field;
    if (!ov || !el) return;
    if (!el.isConnected || !isVisible(el)) return closeMenu(true);
    const r = el.getBoundingClientRect();
    if (ov.icon) {
      const s = 24;
      let x = r.right - s - 6;
      const y = r.top + (r.height - s) / 2;
      // Stay clear of the site's own trailing buttons (show password, clear).
      for (let i = 0; i < 3; i++) {
        const under = document.elementsFromPoint(x + s / 2, y + s / 2).find((e) => e !== ov.host);
        if (!under || under === el || el.contains(under) || under.contains(el)) break;
        x -= 28;
      }
      ov.icon.style.cssText = `left:${x}px;top:${y}px`;
    }
    if (ov.iframe) {
      const width = Math.min(Math.max(r.width, 300), 380);
      const h = menu.height;
      const below = innerHeight - r.bottom;
      const top = below >= h + 8 || below >= r.top ? r.bottom + 4 : r.top - h - 4;
      const left = Math.max(8, Math.min(r.left, innerWidth - width - 8));
      ov.iframe.style.cssText = `left:${left}px;top:${top}px;width:${width}px;height:${h}px`;
    }
  }
  const schedule = () => (menu.raf ||= requestAnimationFrame(place));

  function layoutListeners(on: boolean) {
    if (on === menu.layout) return;
    menu.layout = on;
    const f = on ? addEventListener : removeEventListener;
    f("scroll", schedule, { capture: true, passive: true } as any);
    f("resize", schedule, { passive: true } as any);
  }

  function showFor(el: Fillable, purpose: Purpose, open: boolean) {
    if (menu.field !== el) closeMenu(true);
    menu.field = el;
    menu.purpose = purpose;
    const ov = (menu.ov ??= new Overlay());
    ov.mount(el);
    if (el.getBoundingClientRect().width >= 80) ov.showIcon(() => (menu.open ? closeMenu() : void openMenu()));
    layoutListeners(true);
    place();
    if (open) void openMenu();
  }

  async function openMenu() {
    if (!menu.field || !menu.ov || menu.open) return;
    menu.open = true;
    const a = analysisFor(menu.field);
    // The background records which frame and purpose the menu belongs to before the page asks.
    const token = newToken();
    await send({ kw: "cs", t: "menu", purpose: menu.purpose, scope: a.type, token });
    if (!menu.open || !menu.ov) return;
    menu.height = 0;
    menu.ov.frame("menu.html", token, onMenuMessage);
    place();
  }

  function closeMenu(all = false) {
    menu.selected = -1;
    menu.rows = 0;
    menu.open = false;
    menu.ov?.closeFrame();
    if (all) {
      menu.ov?.unmount();
      menu.field = null;
      layoutListeners(false);
    }
  }

  const toMenu = (m: unknown) => menu.ov?.port?.postMessage(m);

  function onMenuMessage(m: any) {
    if (m?.t === "ready") {
      if (menu.field?.value) toMenu({ t: "filter", q: menu.field.value });
    } else if (m?.t === "size") {
      menu.height = Math.max(0, Math.min(Number(m.h) || 0, 420));
      menu.rows = Math.max(0, Number(m.n) || 0);
      if (menu.selected >= menu.rows) menu.selected = menu.rows - 1;
      schedule();
    } else if (m?.t === "sel") menu.selected = Number(m.i);
    else if (m?.t === "close") {
      closeMenu();
      (menu.field as HTMLElement | null)?.focus({ preventScroll: true });
    }
  }

  addEventListener(
    "keydown",
    (e) => {
      if (!e.isTrusted || !menu.field || deepActive() !== menu.field) return;
      if (!menu.open) {
        if (e.key === "ArrowDown" && menu.ov?.mounted && !e.altKey && !e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          void openMenu();
        }
        return;
      }
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const n = menu.rows;
        if (!n) return;
        const s = menu.selected;
        menu.selected = e.key === "ArrowDown" ? (s + 1) % n : s <= 0 ? n - 1 : s - 1;
        toMenu({ t: "sel", i: menu.selected });
      } else if (e.key === "Enter" && menu.selected >= 0 && menu.ov?.port) {
        e.preventDefault();
        e.stopImmediatePropagation();
        toMenu({ t: "pick", i: menu.selected });
      } else if (e.key === "Escape") {
        e.preventDefault();
        closeMenu();
      } else if (e.key === "Tab") closeMenu();
    },
    true,
  );

  // Clicks elsewhere close the menu; clicks in our overlay (retargeted to the host) don't.
  addEventListener(
    "pointerdown",
    (e) => {
      if (!menu.ov?.mounted) return;
      const t = e.composedPath()[0];
      if (t === menu.field || e.composedPath().includes(menu.ov.host)) return;
      closeMenu(true);
    },
    true,
  );

  // ---------------------------------------------------------------- focus
  let focusSeq = 0;
  let filling = false;
  async function onFocus(el: Element | null) {
    if (filling || !isFillable(el)) return;
    if (menu.ov && el === menu.field) return;
    const seq = ++focusSeq;
    const a = analysisFor(el);
    const purpose = purposeOf(kindInScope(el, a));
    if (!purpose) return closeMenu(true);
    const r = await send<FieldReply>({ kw: "cs", t: "field", purpose, empty: !el.value, ...info(a) });
    if (seq !== focusSeq || deepActive() !== el || !r) return;
    if (r.icon) showFor(el, purpose, r.open && !el.value);
    else closeMenu(true);
  }

  addEventListener(
    "focusin",
    (e) => {
      if (filling) return;
      const t = e.composedPath()[0] as Element;
      if (menu.ov && e.composedPath().includes(menu.ov.host)) return;
      if (t !== menu.field && menu.ov?.mounted) closeMenu(true);
      void onFocus(t);
    },
    { capture: true, passive: true },
  );

  addEventListener(
    "input",
    (e) => {
      const t = e.composedPath()[0];
      if (e.isTrusted && t === menu.field && menu.open) toMenu({ t: "filter", q: (t as HTMLInputElement).value });
    },
    { capture: true, passive: true },
  );

  // ---------------------------------------------------------------- multi-step watcher
  // After a username-only fill on a single-page login, the password (or code) field appears in
  // the same document. Watch for it for a bounded time, then stop.
  let watcher: MutationObserver | null = null;
  function watch(ms: number) {
    watcher?.disconnect();
    let pending = 0;
    let last = "";
    const check = () => {
      pending = 0;
      for (const a of allScopes()) {
        const i = info(a);
        if ((i.hasPw && i.emptyPw) || (i.hasOtp && i.emptyOtp)) {
          const sig = `${i.type}:${i.hasPw}:${i.hasOtp}`;
          if (sig === last) return;
          last = sig;
          void send({ kw: "cs", t: "step", ...i });
          return;
        }
      }
    };
    watcher = new MutationObserver(() => (pending ||= window.setTimeout(check, 120)));
    watcher.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["type", "style", "class", "hidden", "aria-hidden"] });
    window.setTimeout(() => {
      watcher?.disconnect();
      watcher = null;
    }, ms);
  }

  // ---------------------------------------------------------------- save / update prompts
  // On submit (form submit, Enter, a click on a submit-like button) look at the scope's
  // password fields: if they hold something Keyward didn't put there, report it. Whether to
  // prompt is decided by the background after the page has moved on.
  const save = (() => {
    let lastSig = "";
    let lastAt = 0;
    const SUBMITISH = /\b(log ?in|sign ?(in|up)|submit|continue|next|save|register|create|join|change|update|confirm|reset|enter)\b|войти|вход|далее|продолж|сохран|регистр|создать|изменить|обновить|подтверд/i;
    const typed = (el: HTMLInputElement | null | undefined) => !!el?.value && filledByUs.get(el) !== el.value;

    /** Scope of a submit: the form, else the nearest ancestor holding a password field. */
    function scopeFor(el: Element): Node | null {
      const f = (el as HTMLInputElement).form ?? el.closest("form");
      if (f) return f;
      let cur: Element | null = el;
      for (let i = 0; cur && i < 8; i++) {
        if (cur.querySelector?.("input[type=password]") || (cur.shadowRoot && cur.shadowRoot.querySelector("input[type=password]"))) return cur;
        const p: Node | null = cur.parentNode;
        cur = p instanceof ShadowRoot ? p.host : (p as Element | null);
        if (cur && cur.getElementsByTagName("*").length > 1500) break;
      }
      return isFillable(el) ? scopeOf(el) : null;
    }

    function capture(from: EventTarget | null) {
      if (!(from instanceof Element)) return;
      const root = scopeFor(from);
      if (!root) return;
      const a = analyze(root, { visibleOnly: true });
      const pw = a.password;
      const np = a.newPasswords[0];
      const userStep = a.type === "username" && typed(a.username);
      if (!typed(pw) && !typed(np) && !userStep) return;
      const username = (a.username?.value ?? "").trim();
      const password = pw?.value ?? "";
      const newPassword = np?.value ?? "";
      const type: SubmitData["type"] = password && newPassword ? "change" : newPassword ? "signup" : "login";
      const sig = `${username}\u0000${password}\u0000${newPassword}`;
      if (sig === lastSig && Date.now() - lastAt < 3000) return;
      lastSig = sig;
      lastAt = Date.now();
      void send({ kw: "cs", t: "submit", data: { url: location.href, type, username, password, newPassword } });
      if (pw || np) watchGone((pw ?? np)!);
    }

    // A single-page app that logs in without navigating: report once the field is gone for 0.8 s.
    function watchGone(el: HTMLInputElement) {
      let goneSince = 0;
      const t0 = Date.now();
      const tick = () => {
        const gone = !el.isConnected || !isVisible(el);
        if (gone) goneSince ||= Date.now();
        else goneSince = 0;
        if (goneSince && Date.now() - goneSince >= 800) return void send({ kw: "cs", t: "submitDone" });
        if (Date.now() - t0 < 10_000) window.setTimeout(tick, 300);
      };
      window.setTimeout(tick, 300);
    }

    addEventListener("submit", (e) => e.isTrusted && capture(e.target), true);
    addEventListener(
      "keydown",
      (e) => {
        const t = e.composedPath()[0];
        if (e.isTrusted && e.key === "Enter" && t instanceof HTMLInputElement) capture(t);
      },
      true,
    );
    addEventListener(
      "click",
      (e) => {
        if (!e.isTrusted) return;
        const t = e.composedPath()[0];
        const b = t instanceof Element ? t.closest("button,input[type=submit],input[type=button],[role=button],a") : null;
        if (!b) return;
        const label = (b as HTMLInputElement).value || b.textContent || b.getAttribute("aria-label") || "";
        if ((b as HTMLButtonElement).type === "submit" || SUBMITISH.test(label)) capture(b);
      },
      true,
    );
    return {};
  })();
  void save;

  // ---------------------------------------------------------------- save bar
  let bar: Overlay | null = null;
  function showSavebar(token: string) {
    if (window !== window.top) return;
    bar ??= new Overlay();
    bar.mount(null);
    const f = bar.frame("savebar.html", token, (m: any) => {
      if (m?.t === "size" && bar?.iframe) bar.iframe.style.height = `${Math.min(Number(m.h) || 0, 400)}px`;
      else if (m?.t === "close") closeSavebar();
    });
    f.style.cssText = `left:${Math.max(8, innerWidth - 380 - 16)}px;top:16px;width:380px;height:0`;
  }
  function closeSavebar() {
    bar?.unmount();
  }

  // ---------------------------------------------------------------- background commands
  chrome.runtime.onMessage.addListener((m: AfMessage, sender, respond) => {
    if (sender.id !== chrome.runtime.id || (m as any)?.kw !== "af") return;
    switch (m.t) {
      case "scan":
        respond(scan());
        return;
      case "fill":
        respond(fill(m.plan, m.via, m.purpose));
        return;
      case "menuClose":
        closeMenu(true);
        return;
      case "watch":
        watch(m.ms);
        return;
      case "savebar":
        showSavebar(m.token);
        return;
      case "savebarClose":
        closeSavebar();
        return;
    }
  });

  addEventListener("pagehide", () => {
    closeMenu(true);
    closeSavebar();
  });

  // The field that brought us here.
  void onFocus(deepActive());
})();
