// Dev builds only: breadcrumbs into storage.local "kwdbg" (readable from tests in any browser,
// including frames whose console isn't reachable). Compiled out of production builds.
export function dbg(...parts: unknown[]): void {
  if (!__DEV__) return;
  const line = `${new Date().toISOString().slice(11, 23)} ${parts.map((p) => (typeof p === "string" ? p : JSON.stringify(p))).join(" ")}`;
  void chrome.storage.local.get("kwdbg").then((r) => chrome.storage.local.set({ kwdbg: [...((r.kwdbg as string[]) ?? []).slice(-200), line] }));
}
