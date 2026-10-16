// Passkey relay, in the extension's isolated world next to passkey.main.ts. Carries the page's
// WebAuthn requests to the background and the answers back, and shows Keyward's passkey dialog
// (an extension page in a closed shadow root, like the inline menu) in the top frame.
import { Overlay } from "./autofill/overlay.ts";

(() => {
  const w = window as any;
  if (w.__kwPkRelay) return;
  w.__kwPkRelay = 1;

  /** page request id → background token */
  const reqs = new Map<string, string>();
  const toPage = (id: string, r: unknown) => window.postMessage({ kwPk: "res", id, r }, "*");

  addEventListener("message", async (e) => {
    const d = e.data;
    if (e.source !== window || typeof d?.id !== "string") return;
    if (d.kwPk === "cancel") {
      const token = reqs.get(d.id);
      reqs.delete(d.id);
      if (token) void chrome.runtime.sendMessage({ kw: "pk", t: "cancel", token }).catch(() => {});
      return;
    }
    if (d.kwPk !== "req" || (d.kind !== "create" && d.kind !== "get")) return;
    let r: any = null;
    try {
      r = await chrome.runtime.sendMessage({ kw: "pk", t: "begin", kind: d.kind, options: d.options });
    } catch {}
    if (r?.pending) reqs.set(d.id, r.pending);
    else toPage(d.id, r ?? { fallback: "Keyward is unavailable" });
  });

  let dialog: Overlay | null = null;
  /** the request the dialog is showing */
  let shown: string | null = null;
  function show(token: string) {
    if (window !== window.top) return;
    dialog?.unmount();
    shown = token;
    dialog = new Overlay();
    dialog.mount(document.activeElement);
    const width = Math.min(400, innerWidth - 16);
    const f = dialog.frame("passkey.html", token, (m: any) => {
      if (m?.t === "size" && dialog?.iframe) dialog.iframe.style.height = `${Math.min(Number(m.h) || 0, innerHeight - 32)}px`;
    });
    f.style.cssText = `left:${Math.round((innerWidth - width) / 2)}px;top:16px;width:${width}px;height:0`;
    f.addEventListener("load", () => f.focus(), { once: true });
  }
  function hide(token?: string) {
    if (token && token !== shown) return;
    dialog?.unmount();
    dialog = null;
    shown = null;
  }

  chrome.runtime.onMessage.addListener((m: any, sender) => {
    if (sender.id !== chrome.runtime.id) return;
    if (m?.kw === "pkd") m.t === "show" ? show(String(m.token)) : hide(m.token == null ? undefined : String(m.token));
    else if (m?.kw === "pkr") {
      // Close the dialog first: a browser fallback needs the page focused again.
      hide(String(m.token));
      for (const [id, token] of reqs) {
        if (token !== m.token) continue;
        reqs.delete(id);
        toPage(id, m.result);
      }
    }
  });
  addEventListener("pagehide", () => {
    hide();
    for (const token of reqs.values()) void chrome.runtime.sendMessage({ kw: "pk", t: "cancel", token }).catch(() => {});
    reqs.clear();
  });
})();
