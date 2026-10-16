// Content bootstrap: injected into every frame, does nothing until the user focuses a field that
// could take a login, card or identity value. Then it asks the background once to inject the
// real autofill script into this frame. No page scan and no MutationObserver; the only other
// work is "fill on page load" below, a few cheap looks for a password field.
(() => {
  const w = window as any;
  if (w.__kw) return;
  w.__kw = 1;
  const SKIP = /^(hidden|submit|button|reset|image|file|checkbox|radio|range|color|search)$/;
  let asked = false;
  const relevant = (el: EventTarget | null): el is HTMLInputElement =>
    el instanceof HTMLInputElement && !SKIP.test(el.type) && !el.disabled && !el.readOnly;
  const ask = (el: HTMLInputElement) => {
    if (asked) return;
    asked = true;
    removeEventListener("focusin", onFocus, true);
    try {
      chrome.runtime.sendMessage({ kw: "cs", t: "focus", type: el.type, ac: el.autocomplete }).catch(() => {});
    } catch {
      // extension reloaded: this script is orphaned
    }
  };
  const onFocus = (e: FocusEvent) => {
    const t = (e.composedPath?.()[0] ?? e.target) as EventTarget | null;
    if (relevant(t)) ask(t);
  };
  addEventListener("focusin", onFocus, { capture: true, passive: true });
  const a = document.activeElement;
  if (relevant(a)) ask(a);

  // Fill on page load (Settings → Autofill, off by default): a password field shown at load, or
  // drawn a little later by a single-page app (also after its in-page navigations), asks the
  // background once per address; the background decides whether anything gets filled.
  let loadAsked = "";
  const loadCheck = () => {
    if (loadAsked === location.href) return;
    const pw = [...document.querySelectorAll<HTMLInputElement>("input[type=password]")].some((e) => e.offsetWidth > 1 && e.offsetHeight > 1 && !e.value);
    if (!pw) return;
    loadAsked = location.href;
    try {
      chrome.storage.local.get("settings").then((r: any) => r.settings?.autofill?.onPageLoad && chrome.runtime.sendMessage({ kw: "cs", t: "pageload" })).catch(() => {});
    } catch {}
  };
  const looks = (...ms: number[]) => ms.forEach((ms) => setTimeout(loadCheck, ms));
  looks(0, 1000, 3000);
  w.navigation?.addEventListener?.("currententrychange", () => looks(300, 1500, 3500));
})();
