import { decryptBuffer, decryptBytes, encryptBuffer, encryptBytes, encryptString } from "../../core/crypto/encstring.ts";
import { SymKey } from "../../core/crypto/symkey.ts";
import { itemKey } from "../../core/vault/cipher.ts";
import type { AttachmentView, CipherView } from "../../core/vault/types.ts";
import { apiFor } from "../../platform/accounts.ts";
import { account, currentRing, rawItem } from "./app.ts";

async function keysFor(v: CipherView) {
  const ring = currentRing();
  const raw = await rawItem(v.id);
  if (!ring || !raw || !account.value) throw new Error("Vault is locked");
  return { key: await itemKey(raw, ring), api: await apiFor(account.value) };
}

export async function fetchAttachment(v: CipherView, a: AttachmentView): Promise<{ name: string; bytes: Uint8Array<ArrayBuffer> }> {
  const { key, api } = await keysFor(v);
  // Ask for a fresh download URL (Vaultwarden's links carry a short-lived token).
  const meta = await api.get(`/ciphers/${v.id}/attachment/${a.id}`).catch(() => null);
  const url = meta?.url ?? a.url;
  if (!url) throw new Error("No download URL");
  const res = await api.request<Response>("GET", url, undefined, { base: "abs", raw: true, auth: !/token=/.test(url) });
  const enc = new Uint8Array(await res.arrayBuffer());
  const attKey = a.key ? new SymKey(await decryptBytes(meta?.key ?? a.key, key)) : key;
  return { name: a.fileName ?? "attachment", bytes: await decryptBuffer(enc, attKey) };
}

export async function downloadAttachment(v: CipherView, a: AttachmentView): Promise<void> {
  const { name, bytes } = await fetchAttachment(v, a);
  saveBytes(name, bytes);
}

export function saveBytes(name: string, bytes: Uint8Array<ArrayBuffer>, type = "application/octet-stream") {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const el = document.createElement("a");
  el.href = url;
  el.download = name;
  document.body.append(el);
  el.click();
  el.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

/** Attachments v2 upload: register (encrypted name + wrapped key), then POST the encrypted blob. */
export async function uploadAttachment(v: CipherView, file: File): Promise<void> {
  const { key, api } = await keysFor(v);
  const attKey = SymKey.random();
  const data = await encryptBuffer(new Uint8Array(await file.arrayBuffer()), attKey);
  const reg = await api.post(`/ciphers/${v.id}/attachment/v2`, {
    key: await encryptBytes(attKey.raw, key),
    fileName: await encryptString(file.name, key),
    fileSize: data.length,
    adminRequest: false,
  });
  const form = new FormData();
  form.append("data", new Blob([data]), "blob");
  await api.request("POST", reg.url ?? `/ciphers/${v.id}/attachment/${reg.attachmentId}`, form, { base: reg.url?.startsWith("http") ? "abs" : "api" });
}

export async function deleteAttachment(v: CipherView, a: AttachmentView): Promise<void> {
  const { api } = await keysFor(v);
  await api.delete(`/ciphers/${v.id}/attachment/${a.id}`);
}
