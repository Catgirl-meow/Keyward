// Promise wrappers over chrome.storage. `session` is memory-only and (by default on Chromium,
// always on Firefox) unreadable from content scripts — the only place unlocked keys live.
type Area = chrome.storage.StorageArea;

function area(a: Area) {
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const r = await a.get(key);
      return r[key] as T | undefined;
    },
    async getMany(keys: string[]): Promise<Record<string, any>> {
      return a.get(keys);
    },
    set(key: string, value: unknown): Promise<void> {
      return a.set({ [key]: value });
    },
    setMany(obj: Record<string, unknown>): Promise<void> {
      return a.set(obj);
    },
    remove(key: string | string[]): Promise<void> {
      return a.remove(key);
    },
    async all(): Promise<Record<string, any>> {
      return a.get(null);
    },
  };
}

export const local = area(chrome.storage.local);
export const session = area(chrome.storage.session);

export function onChanged(cb: (changes: Record<string, chrome.storage.StorageChange>, area: string) => void): () => void {
  chrome.storage.onChanged.addListener(cb);
  return () => chrome.storage.onChanged.removeListener(cb);
}
