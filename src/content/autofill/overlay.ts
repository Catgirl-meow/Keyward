// Page overlays (the inline menu and the save bar): an extension-page iframe inside a closed
// shadow root on a randomly named host in the top layer. The page can't read the iframe or
// script it; it can still style or move the host, so `trusted()` checks before acting on a click.
import keyIcon from "icon:passkey";

const HOST_CSS = [
  "all:initial",
  "display:block",
  "position:fixed",
  "inset:0 auto auto 0",
  "left:0",
  "top:0",
  "width:0",
  "height:0",
  "margin:0",
  "padding:0",
  "border:0",
  "background:transparent",
  "overflow:visible",
  "z-index:2147483647",
  "opacity:1",
  "visibility:visible",
  "transform:none",
  "filter:none",
  "clip-path:none",
  "mix-blend-mode:normal",
  "pointer-events:auto",
  "color-scheme:normal",
]
  .map((d) => d + "!important")
  .join(";");

const SHADOW_CSS = `
:host{all:initial}
.icon{position:absolute;box-sizing:border-box;width:24px;height:24px;padding:3px;border:0;border-radius:8px;background:#e8eaf6;
  box-shadow:0 1px 2px rgba(0,0,0,.25);cursor:pointer;display:flex;align-items:center;justify-content:center;opacity:.92}
.icon:hover{opacity:1;background:#d1d5f0}
.icon svg{width:18px;height:18px;fill:#3949ab}
@media (prefers-color-scheme:dark){.icon{background:#2b2d3a}.icon:hover{background:#363a52}.icon svg{fill:#9fa8da}}
iframe{position:absolute;border:0;border-radius:16px;background:transparent;color-scheme:normal;width:0;height:0;
  box-shadow:0 8px 28px rgba(0,0,0,.28),0 1px 3px rgba(0,0,0,.2);display:block}
`;

const rand = () => "kw-" + crypto.getRandomValues(new Uint32Array(2)).reduce((s, n) => s + n.toString(36), "");

/** Nearest open modal <dialog> around `el` (content outside it is inert). */
function modalOf(el: Element | null): HTMLDialogElement | null {
  for (let n: Node | null = el; n; n = n.parentNode instanceof ShadowRoot ? n.parentNode.host : n.parentNode) {
    if (n instanceof HTMLDialogElement && n.open && n.matches(":modal")) return n;
  }
  return null;
}

export class Overlay {
  readonly host: HTMLElement;
  readonly root: ShadowRoot;
  iframe: HTMLIFrameElement | null = null;
  icon: HTMLButtonElement | null = null;
  /** private channel to the frame's page */
  port: MessagePort | null = null;
  shownAt = 0;
  private helloOff: (() => void) | null = null;
  private tampered = false;
  private mo: MutationObserver;

  constructor() {
    this.host = document.createElement(rand());
    this.host.setAttribute("style", HOST_CSS);
    this.root = this.host.attachShadow({ mode: "closed" });
    const st = document.createElement("style");
    st.textContent = SHADOW_CSS;
    this.root.append(st);
    // Any change to the host by the page voids the overlay until it's rebuilt.
    this.mo = new MutationObserver(() => (this.tampered = true));
  }

  mount(near: Element | null) {
    const parent = modalOf(near) ?? document.documentElement;
    if (this.host.parentNode !== parent) parent.append(this.host);
    try {
      if (!this.host.hasAttribute("popover")) this.host.setAttribute("popover", "manual");
      if (!this.host.matches(":popover-open")) this.host.showPopover();
    } catch {}
    this.host.setAttribute("style", HOST_CSS);
    this.tampered = false;
    this.mo.disconnect();
    this.mo.observe(this.host, { attributes: true });
  }

  unmount() {
    this.mo.disconnect();
    this.host.remove();
    this.helloOff?.();
    this.port?.close();
    this.port = null;
    this.iframe = null;
    this.icon = null;
    this.root.querySelectorAll("iframe,.icon").forEach((e) => e.remove());
  }

  get mounted() {
    return this.host.isConnected;
  }

  showIcon(onClick: () => void): HTMLButtonElement {
    if (this.icon) return this.icon;
    const b = document.createElement("button");
    b.className = "icon";
    b.type = "button";
    b.tabIndex = -1;
    b.title = "Keyward";
    b.innerHTML = `<svg viewBox="0 -960 960 960" aria-hidden="true"><path d="${keyIcon}"/></svg>`;
    // mousedown, not click: keep the field focused.
    b.addEventListener("mousedown", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (e.isTrusted) onClick();
    });
    this.root.append(b);
    this.icon = b;
    return b;
  }

  hideIcon() {
    this.icon?.remove();
    this.icon = null;
  }

  /** The extension page in an iframe, with a private channel to it. The page says hello once
   * its listener is up; the answer (`token` and one end of a MessageChannel) goes by postMessage
   * to the extension's origin only, never in the URL, so the site can neither learn the token
   * nor listen in. Chromium serves a `use_dynamic_url` page from the static extension origin
   * after a redirect, so both origins are accepted, and the reply targets the one that spoke. */
  frame(page: string, token: string, onMessage: (m: any) => void): HTMLIFrameElement {
    if (this.iframe) return this.iframe;
    const f = document.createElement("iframe");
    const url = chrome.runtime.getURL(page);
    const origins = new Set([new URL(url).origin, __CHROMIUM__ ? `chrome-extension://${chrome.runtime.id}` : new URL(url).origin]);
    const ch = new MessageChannel();
    ch.port1.onmessage = (e) => this.iframe === f && onMessage(e.data);
    this.port?.close();
    this.port = ch.port1;
    this.helloOff?.();
    const hello = (e: MessageEvent) => {
      if (e.source !== f.contentWindow || e.data?.kwHello !== true || !origins.has(e.origin)) return;
      e.stopImmediatePropagation();
      this.helloOff?.();
      f.contentWindow!.postMessage({ kwToken: token }, e.origin, [ch.port2]);
    };
    addEventListener("message", hello, true);
    this.helloOff = () => {
      removeEventListener("message", hello, true);
      this.helloOff = null;
    };
    f.src = url;
    f.tabIndex = -1;
    f.setAttribute("allowtransparency", "true");
    f.setAttribute("scrolling", "no");
    this.root.append(f);
    this.iframe = f;
    this.shownAt = performance.now();
    return f;
  }

  closeFrame() {
    this.helloOff?.();
    this.port?.close();
    this.port = null;
    this.iframe?.remove();
    this.iframe = null;
  }

  /** Is the overlay really what the user sees and clicks? (DOM-clickjacking guard) */
  trusted(): boolean {
    if (this.tampered || !this.mounted || !this.iframe) return false;
    if (this.host.getAttribute("style") !== HOST_CSS) return false;
    const cs = getComputedStyle(this.host);
    if (cs.opacity !== "1" || cs.visibility !== "visible" || cs.display === "none" || cs.filter !== "none" || cs.clipPath !== "none" || cs.transform !== "none") return false;
    for (const el of [document.documentElement, document.body]) {
      if (!el) continue;
      const s = getComputedStyle(el);
      // Ancestor effects don't reach the top layer, but a host left in normal flow (no popover support) inherits them.
      if (!this.host.matches(":popover-open") && (Number(s.opacity) < 1 || s.filter !== "none")) return false;
    }
    const r = this.iframe.getBoundingClientRect();
    if (r.width < 40 || r.height < 20) return false;
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + Math.min(r.height / 2, 40));
    return hit === this.host;
  }
}

export { modalOf };
