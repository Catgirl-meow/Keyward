// Cheap favicon-host extraction for list rows (no PSL needed: the icon service takes any host).
export function faviconHostCheap(uris: string[]): string | null {
  for (const u of uris) {
    const m = /^(?:https?:\/\/)?([^/:?#\s]+)/i.exec(u.trim());
    if (m && m[1].includes(".") && !/^(chrome|about|moz-extension|file|data)/i.test(u)) return m[1].toLowerCase();
  }
  return null;
}
