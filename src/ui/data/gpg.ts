// GPG key items for the pages: Keyguard's fields decoded, and the vault's keys for the GPG tools.
// OpenPGP.js itself loads only when something needs it (pgp()).
import { useEffect, useState } from "preact/hooks";
import { decodeGpgFields, looksLikeGpgItem, type GpgKeyFields } from "../../core/gpg/fields.ts";
import type { CipherView, FieldView } from "../../core/vault/types.ts";
import { items, openItem } from "./app.ts";

export const pgp = () => import("../../core/gpg/pgp.ts");

export type GpgItem = { key: GpgKeyFields; rest: FieldView[] };

/** The item's GPG key and its other fields: null when it is no GPG item, undefined while decoding. */
export function useGpgFields(v: Pick<CipherView, "type" | "fields"> | null | undefined): GpgItem | null | undefined {
  const [state, setState] = useState<GpgItem | null | undefined>(undefined);
  useEffect(() => {
    if (!v) return setState(undefined);
    if (!looksLikeGpgItem(v)) return setState(null);
    let alive = true;
    void decodeGpgFields(v.fields).then((d) => alive && setState(d));
    return () => {
      alive = false;
    };
  }, [v]);
  return state;
}

export interface VaultGpgKey {
  id: string;
  name: string;
  /** the item asks for the master password before use */
  reprompt: boolean;
  key: GpgKeyFields;
}

/** Every GPG key item in the vault (not in trash), decoded. */
export async function vaultGpgKeys(): Promise<VaultGpgKey[]> {
  const ids = [...items.value.values()].filter((s) => s.gpg && !s.del).map((s) => s.id);
  const out = await Promise.all(
    ids.map(async (id) => {
      const r = await openItem(id).catch(() => null);
      const d = r && (await decodeGpgFields(r.view.fields));
      return d ? { id, name: r!.view.name, reprompt: r!.view.reprompt === 1, key: d.key } : null;
    }),
  );
  return out.filter((k): k is VaultGpgKey => !!k).sort((a, b) => a.name.localeCompare(b.name));
}

/** A file name for an exported key, from the item name: "Work key" → "Work_key.asc". */
export const ascName = (base: string, secret: boolean) => `${base.replace(/[^\p{L}\p{N}@._-]+/gu, "_").replace(/^_+|_+$/g, "") || "key"}${secret ? "-secret" : ""}.asc`;
