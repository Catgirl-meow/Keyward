// Send writes. Like vault writes, the background stores the server's answer and tells open
// pages; a file Send's upload happens in the page that holds the file (see ui/data/sends.ts),
// which then asks for the stored copy to be refreshed.
import { loadPolicy } from "../platform/policy.ts";
import type { RawSend } from "../core/send/send.ts";
import { encryptSend } from "../core/send/send.ts";
import { decryptBytes } from "../core/crypto/encstring.ts";
import { toB64Url } from "../core/util/bytes.ts";
import { broadcast, type Handlers } from "../platform/messages.ts";
import { unlockedCtx, type UnlockedCtx } from "./ctx.ts";
import { vaultTurn } from "./sync.ts";

async function store(c: UnlockedCtx, raw: RawSend | null, removed?: string) {
  await c.db.write(["sends"], (s) => {
    if (raw) s("sends").put(raw);
    if (removed) s("sends").delete(removed);
  });
  broadcast({ kind: "sends", accountId: c.account.id });
}

const handlers: Handlers = {
  async "send.save"({ accountId, draft, password }) {
    const c = await unlockedCtx(accountId);
    const policy = await loadPolicy(c.account.id);
    if (policy?.disableSend) throw new Error("Your organization doesn't allow creating or editing Sends");
    if (policy?.sendShowEmail) draft = { ...draft, hideEmail: false };
    // Editing keeps the key material, so the link people already have keeps working.
    const old = draft.id ? await c.db.get<RawSend>("sends", draft.id) : undefined;
    if (draft.id && !old) throw new Error("This Send no longer exists");
    const material = old ? toB64Url(await decryptBytes(old.key, c.ring.user)) : undefined;
    const { body } = await encryptSend({ ...draft, material }, c.ring.user, password ?? null);
    const raw: RawSend = draft.id ? await c.api.put(`/sends/${draft.id}`, body) : await c.api.post("/sends", body);
    await store(c, raw);
    return { id: raw.id, accessId: raw.accessId };
  },

  async "send.delete"({ accountId, id }) {
    const c = await unlockedCtx(accountId);
    await c.api.delete(`/sends/${id}`);
    await store(c, null, id);
  },

  async "send.removePassword"({ accountId, id }) {
    const c = await unlockedCtx(accountId);
    await store(c, await c.api.put<RawSend>(`/sends/${id}/remove-password`));
  },

  async "send.refetch"({ accountId, id }) {
    const c = await unlockedCtx(accountId);
    await store(c, await c.api.get<RawSend>(`/sends/${id}`));
  },
};

/** Waits for a running sync like vault writes do: a full sync rewrites the sends store. */
export const sendHandlers: Handlers = Object.fromEntries(
  Object.entries(handlers).map(([name, h]) => [name, (arg: any, sender: chrome.runtime.MessageSender) => vaultTurn(() => Promise.resolve((h as any)(arg, sender)))]),
) as Handlers;
