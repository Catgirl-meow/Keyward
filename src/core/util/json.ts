/** Lower-cases the first letter of every object key, recursively (Vaultwarden mixes PascalCase/camelCase). */
export function camelize<T = any>(v: any): T {
  if (Array.isArray(v)) return v.map(camelize) as T;
  if (v && typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) {
    const out: Record<string, any> = {};
    for (const k in v) {
      const c = k.charCodeAt(0);
      const nk = c >= 65 && c <= 90 ? String.fromCharCode(c + 32) + k.slice(1) : k;
      out[nk] = camelize(v[k]);
    }
    return out as T;
  }
  return v as T;
}

export function decodeJwt(token: string): Record<string, any> | null {
  try {
    const part = token.split(".")[1];
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const json = decodeURIComponent(
      Array.from(atob(b64 + "===".slice((b64.length + 3) % 4)), (c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join(""),
    );
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/** FNV-1a 32-bit, used for avatar hues and summary bucketing. */
export function fnv1a32(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

export function uuid(): string {
  return crypto.randomUUID();
}
