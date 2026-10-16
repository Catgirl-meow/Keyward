// Sends for this page: read from IndexedDB and decrypted here; writes go to the background,
// except a file Send's upload, which happens here where the file is.
import { effect, signal } from "@preact/signals";
import { encryptBuffer } from "../../core/crypto/encstring.ts";
import { decryptSend, encryptSend, sendLink, type SendDraft, type SendView } from "../../core/send/send.ts";
import { apiFor } from "../../platform/accounts.ts";
import { listen, rpc } from "../../platform/messages.ts";
import { account, currentRing, rawSends, vaultOwner } from "./app.ts";

export const sends = signal<SendView[] | null>(null);
export const sendsError = signal<string | null>(null);

let owner: string | null = null;
let generation = 0;
effect(() => {
  const id = vaultOwner.value;
  if (id === owner) return;
  owner = id;
  generation++;
  sends.value = null;
  if (id) void loadSends();
});

listen((m) => {
  if ((m.kind === "sends" || (m.kind === "vault" && m.full)) && m.accountId === owner) void loadSends();
});

export async function loadSends(): Promise<void> {
  const gen = generation;
  const ring = currentRing();
  if (!ring) return;
  try {
    const views = await Promise.all((await rawSends()).map((r) => decryptSend(r, ring.user).catch(() => null)));
    if (gen !== generation) return;
    sends.value = views.filter((v): v is SendView => !!v).sort((a, b) => (b.revisionDate ?? "").localeCompare(a.revisionDate ?? ""));
    sendsError.value = null;
  } catch (e) {
    if (gen === generation) sendsError.value = (e as Error).message;
  }
}

export function linkOf(s: Pick<SendView, "accessId" | "material">): string {
  return sendLink(account.value!.server, s.accessId, s.material);
}

/** A new file Send: register it (POST /sends/file/v2), then upload the encrypted file. */
export async function createFileSend(draft: SendDraft, password: string | null, file: File): Promise<{ id: string }> {
  const ring = currentRing();
  if (!ring || !account.value) throw new Error("Vault is locked");
  const api = await apiFor(account.value);
  const { body, key } = await encryptSend({ ...draft, fileName: file.name }, ring.user, password);
  const data = await encryptBuffer(new Uint8Array(await file.arrayBuffer()), key);
  const r = await api.post("/sends/file/v2", { ...body, fileLength: data.length });
  const id: string = r.sendResponse?.id;
  try {
    const form = new FormData();
    // Vaultwarden checks that the part's filename is the encrypted file name.
    form.append("data", new Blob([data]), (body.file as { fileName: string }).fileName);
    // No timeout: the server answers once the whole file is in (see uploadAttachment).
    await api.request("POST", r.url ?? `/sends/${id}/file/${r.sendResponse?.file?.id}`, form, { base: String(r.url ?? "").startsWith("http") ? "abs" : "api", timeout: 0 });
  } catch (e) {
    // Don't leave a Send without its file behind.
    await api.delete(`/sends/${id}`).catch(() => {});
    throw e;
  }
  await rpc("send.refetch", { id });
  return { id };
}
