// Clicks in a frame shown inside a web page (inline menu, passkey dialog) count only when the
// frame is really what the user sees: Chromium's IntersectionObserver v2 says whether the page
// covers it, makes it transparent or transforms it. Elsewhere (LibreWolf) there's no such signal.
//
// The thresholds go below 1: on a fractionally scaled screen (5/3 on this laptop) a fully shown
// frame measures 99.8 %, so observing only "100 % in view" never reported the frame visible and
// every click was dropped.
let visible = !(__CHROMIUM__ && "IntersectionObserver" in window);
if (!visible) {
  try {
    new IntersectionObserver((es) => (visible = !!(es[es.length - 1] as any).isVisible), {
      threshold: [0, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 1],
      trackVisibility: true,
      delay: 100,
    } as any).observe(document.documentElement);
  } catch {
    visible = true;
  }
}

export const reallyVisible = () => visible;
