// Have I Been Pwned "Pwned Passwords" k-anonymity check: only the first 5 hex chars of the
// SHA-1 leave the device, and padding hides the response size.
import { sha1 } from "../crypto/primitives.ts";
import { toHex } from "../util/bytes.ts";

const cache = new Map<string, Promise<Map<string, number>>>();

async function range(prefix: string): Promise<Map<string, number>> {
  let p = cache.get(prefix);
  if (!p) {
    p = fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { "Add-Padding": "true" }, credentials: "omit", cache: "no-store" }).then(async (r) => {
      if (!r.ok) throw new Error(`HIBP HTTP ${r.status}`);
      const m = new Map<string, number>();
      for (const line of (await r.text()).split("\n")) {
        const [suffix, count] = line.trim().split(":");
        const n = Number(count);
        if (suffix && n > 0) m.set(suffix.toUpperCase(), n);
      }
      return m;
    });
    cache.set(prefix, p);
    p.catch(() => cache.delete(prefix));
  }
  return p;
}

/** Number of times the password appears in breaches (0 = not found). */
export async function pwnedCount(password: string): Promise<number> {
  const h = toHex(await sha1(password)).toUpperCase();
  return (await range(h.slice(0, 5))).get(h.slice(5)) ?? 0;
}
