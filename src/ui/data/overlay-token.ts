// Pages shown inside a web page (inline menu, save bar) get a one-time token and a private
// MessagePort from the content script by postMessage. The token identifies their session to
// the background; the port talks to the content script (in LibreWolf such frames have no
// tabs API, so tabs.connect isn't an option).
export interface OverlayChannel {
  token: string;
  port: MessagePort;
}

export const overlayChannel: Promise<OverlayChannel> = new Promise((resolve) => {
  const on = (e: MessageEvent) => {
    if (e.source !== window.parent || typeof e.data?.kwToken !== "string" || !e.ports[0]) return;
    removeEventListener("message", on);
    resolve({ token: e.data.kwToken, port: e.ports[0] });
  };
  addEventListener("message", on);
  // The content script answers only once this page is listening (no reliance on load timing).
  if (window.parent !== window) window.parent.postMessage({ kwHello: true }, "*");
});

export const overlayToken: Promise<string> = overlayChannel.then((c) => c.token);
