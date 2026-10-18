// Vault writes. The background is the only writer: it calls the API, stores the server's
// response, patches one summary bucket and broadcasts the change.
import { encryptString } from "../core/crypto/encstring.ts";
import { patchBuckets, writeAux, loadSnapshot } from "../core/store/summaries.ts";
import { decryptCipher, encryptCipher, summarize } from "../core/vault/cipher.ts";
import type { RawCipher } from "../core/vault/types.ts";
import { broadcast, type Handlers } from "../platform/messages.ts";
import { ApiError } from "../core/api/client.ts";
import { unlockedCtx, type UnlockedCtx } from "./ctx.ts";
import { syncAfterWrite, vaultTurn } from "./sync.ts";
import { decryptString } from "../core/crypto/encstring.ts";

async function storeCiphers(c: UnlockedCtx, raws: RawCipher[], removed: string[] = []) {
  await c.db.write(["ciphers"], (s) => {
    for (const r of raws) s("ciphers").put(r);
    for (const id of removed) s("ciphers").delete(id);
  });
  const sums = await Promise.all(raws.map(async (r) => summarize(await decryptCipher(r, c.ring))));
  await patchBuckets(c.db, c.cacheKey, sums, removed);
  broadcast({ kind: "vault", accountId: c.account.id, ids: [...raws.map((r) => r.id), ...removed] });
  return sums;
}

async function refetch(c: UnlockedCtx, ids: string[]) {
  const raws = await Promise.all(ids.map((id) => c.api.get<RawCipher>(`/ciphers/${id}`)));
  return storeCiphers(c, raws);
}

async function refreshAux(c: UnlockedCtx) {
  const [folders, snap] = await Promise.all([c.api.get("/folders"), loadSnapshot(c.db, c.cacheKey)]);
  const list = folders?.data ?? folders ?? [];
  await c.db.write(["folders"], (s) => {
    s("folders").clear();
    for (const f of list) s("folders").put(f);
  });
  snap.aux.folders = (
    await Promise.all(list.map(async (f: any) => ({ id: f.id, name: await decryptString(f.name, c.ring.user).catch(() => "⚠ Folder") })))
  ).sort((a: any, b: any) => a.name.localeCompare(b.name));
  await writeAux(c.db, c.cacheKey, snap.aux);
  broadcast({ kind: "vault", accountId: c.account.id, full: true });
}

const handlers: Handlers = {
  async "vault.save"({ accountId, view, collectionIds }) {
    const c = await unlockedCtx(accountId);
    const base = view.id ? await c.db.getCipher(view.id) : null;
    const { body } = await encryptCipher(view, c.ring, { base, useItemKey: true, encryptedFor: c.account.id });
    let raw: RawCipher;
    if (!view.id) {
      raw = view.organizationId
        ? await c.api.post("/ciphers/create", { cipher: body, collectionIds: collectionIds ?? [] })
        : await c.api.post("/ciphers", body);
    } else if (base && (base.organizationId ?? null) !== (view.organizationId ?? null) && view.organizationId) {
      // Moving a personal item into an organization ("share").
      raw = await c.api.put(`/ciphers/${view.id}/share`, { cipher: body, collectionIds: collectionIds ?? [] });
    } else {
      try {
        raw = await c.api.put(`/ciphers/${view.id}`, body);
      } catch (e) {
        // Changed elsewhere since we loaded it (lastKnownRevisionDate is stale): keep both
        // versions. The server's goes into the vault, ours is saved as a copy; nothing is lost.
        if (!(e instanceof ApiError && /out of date/i.test(e.message))) throw e;
        await refetch(c, [view.id]);
        const copy = { ...view, id: "", name: `${view.name} (conflict copy)`, attachments: [] };
        const enc = await encryptCipher(copy, c.ring, { useItemKey: true, encryptedFor: c.account.id });
        const made: RawCipher = copy.organizationId
          ? await c.api.post("/ciphers/create", { cipher: enc.body, collectionIds: collectionIds ?? view.collectionIds })
          : await c.api.post("/ciphers", enc.body);
        const [summary] = await storeCiphers(c, [made]);
        return { id: made.id, summary, conflict: true };
      }
      if (collectionIds && view.organizationId) {
        await c.api.put(`/ciphers/${view.id}/collections_v2`, { collectionIds }).catch(() => c.api.put(`/ciphers/${view.id}/collections`, { collectionIds }));
        raw = await c.api.get(`/ciphers/${view.id}`);
      }
    }
    const [summary] = await storeCiphers(c, [raw]);
    return { id: raw.id, summary };
  },

  async "vault.delete"({ accountId, ids, permanent }) {
    const c = await unlockedCtx(accountId);
    if (permanent) {
      if (ids.length === 1) await c.api.delete(`/ciphers/${ids[0]}`);
      else await c.api.delete("/ciphers", { ids });
      await storeCiphers(c, [], ids);
    } else {
      if (ids.length === 1) await c.api.put(`/ciphers/${ids[0]}/delete`);
      else await c.api.put("/ciphers/delete", { ids });
      await refetch(c, ids);
    }
  },

  async "vault.restore"({ accountId, ids }) {
    const c = await unlockedCtx(accountId);
    if (ids.length === 1) await c.api.put(`/ciphers/${ids[0]}/restore`);
    else await c.api.put("/ciphers/restore", { ids });
    await refetch(c, ids);
  },

  async "vault.archive"({ accountId, ids, archive }) {
    const c = await unlockedCtx(accountId);
    if (ids.length === 1) await c.api.put(`/ciphers/${ids[0]}/${archive ? "archive" : "unarchive"}`);
    else await c.api.put(`/ciphers/${archive ? "archive" : "unarchive"}`, { ids });
    await refetch(c, ids);
  },

  async "vault.move"({ accountId, ids, folderId }) {
    const c = await unlockedCtx(accountId);
    await c.api.put("/ciphers/move", { ids, folderId });
    await refetch(c, ids);
  },

  async "vault.refetch"({ accountId, ids }) {
    const c = await unlockedCtx(accountId);
    await refetch(c, ids);
  },

  async "vault.favorite"({ accountId, id, favorite }) {
    const c = await unlockedCtx(accountId);
    const raw = await c.db.getCipher(id);
    await c.api.put(`/ciphers/${id}/partial`, { folderId: raw?.folderId ?? null, favorite });
    await refetch(c, [id]);
  },

  async "folder.save"({ accountId, id, name }) {
    const c = await unlockedCtx(accountId);
    const body = { name: await encryptString(name, c.ring.user) };
    const r = id ? await c.api.put(`/folders/${id}`, body) : await c.api.post("/folders", body);
    await refreshAux(c);
    return { id: r.id };
  },

  async "folder.delete"({ accountId, id }) {
    const c = await unlockedCtx(accountId);
    await c.api.delete(`/folders/${id}`);
    await refreshAux(c);
  },
};

/** Server items per import request (Vaultwarden takes more; this keeps each request modest). */
const IMPORT_CHUNK = 500;

/**
 * Import: encrypts the items with the user key and sends them with POST /ciphers/import, then
 * syncs. Not a vault turn: the writes are all on the server, and the sync after them takes one.
 * A folder whose name already exists is reused; the server creates the others.
 */
export const importHandlers: Handlers = {
  async "vault.import"({ accountId, items, folders, relations }) {
    const c = await unlockedCtx(accountId);
    const folderIds = async () => {
      const list = await c.api.get("/folders");
      const all = list?.data ?? list ?? [];
      return new Map<string, string>(await Promise.all(all.map(async (f: any) => [await decryptString(f.name, c.ring.user).catch(() => ""), f.id] as [string, string])));
    };
    let existing = await folderIds();
    const folderOf = new Map(relations);
    for (let at = 0; at < items.length; at += IMPORT_CHUNK) {
      const chunk = items.slice(at, at + IMPORT_CHUNK);
      const ciphers = await Promise.all(
        chunk.map(async (v) => (await encryptCipher({ ...v, id: "", folderId: null, organizationId: null, collectionIds: [], attachments: [] }, c.ring, { useItemKey: true, encryptedFor: c.account.id })).body),
      );
      const used = [...new Set(chunk.flatMap((_, i) => (folderOf.has(at + i) ? [folderOf.get(at + i)!] : [])))];
      const body = {
        ciphers,
        folders: await Promise.all(used.map(async (j) => ({ id: existing.get(folders[j]) ?? null, name: await encryptString(folders[j], c.ring.user) }))),
        folderRelationships: chunk.flatMap((_, i) => (folderOf.has(at + i) ? [{ key: i, value: used.indexOf(folderOf.get(at + i)!) }] : [])),
      };
      await c.api.post("/ciphers/import", body);
      // Folders made by this request exist now: the next chunk must reuse them, not make more.
      if (at + IMPORT_CHUNK < items.length && used.some((j) => !existing.has(folders[j]))) existing = await folderIds();
    }
    const status = await syncAfterWrite(c.account.id);
    return { imported: items.length, synced: status.ok };
  },
};

/** Every write waits for a running sync (and the reverse): see vaultTurn. */
export const vaultHandlers: Handlers = Object.fromEntries(
  Object.entries(handlers).map(([name, h]) => [name, (arg: any, sender: chrome.runtime.MessageSender) => vaultTurn(() => Promise.resolve((h as any)(arg, sender)))]),
) as Handlers;
