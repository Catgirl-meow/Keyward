// Content bootstrap: injected into every frame, does nothing until the user focuses a field that
// could take a login, card or identity value. Then it asks the background once to inject the
// real autofill script into this frame. No page scan, no MutationObserver, no timers.
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
})();
