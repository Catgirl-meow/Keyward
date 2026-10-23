// Typed request/response messaging between pages, content scripts and the background.
import type { SendDraft } from "../core/send/send.ts";
import type { CipherView, Summary } from "../core/vault/types.ts";

export interface SyncStatus {
  ok: boolean;
  at: number;
  total?: number;
  decrypted?: number;
  error?: string;
  offline?: boolean;
}

export interface PageMatch {
  id: string;
  name: string;
  sub: string;
  uri: string | null;
  type: number;
  totp: boolean;
  fav: boolean;
  rp: boolean;
}

export interface RpcMap {
  // session / accounts
  "auth.webauthn2fa": [{ remember: boolean }, { ok: boolean; error?: string }];
  "session.loginComplete": [{ accountId: string; userKey: string }, { synced: boolean; error?: string }];
  "session.unlocked": [{ accountId: string; userKey: string; via: "password" | "pin" }, { synced: boolean; error?: string }];
  "session.lock": [{ accountId?: string; all?: boolean }, void];
  "session.logout": [{ accountId: string }, void];
  "session.activity": [{ accountId?: string } | undefined, void];
  "sync.now": [{ accountId?: string; force?: boolean }, SyncStatus];
  // vault writes (background is the single writer)
  "vault.save": [{ accountId?: string; view: CipherView; collectionIds?: string[]; keepServer?: boolean }, { id: string; summary: Summary; conflict?: boolean }];
  "vault.delete": [{ accountId?: string; ids: string[]; permanent?: boolean }, void];
  "vault.restore": [{ accountId?: string; ids: string[] }, void];
  "vault.archive": [{ accountId?: string; ids: string[]; archive: boolean }, void];
  "vault.move": [{ accountId?: string; ids: string[]; folderId: string | null }, void];
  "vault.refetch": [{ accountId?: string; ids: string[] }, void];
  "vault.favorite": [{ accountId?: string; id: string; favorite: boolean }, void];
  "folder.save": [{ accountId?: string; id?: string | null; name: string }, { id: string }];
  "folder.delete": [{ accountId?: string; id: string }, void];
  /** relations: [item index, folder index] */
  "vault.import": [{ accountId?: string; items: CipherView[]; folders: string[]; relations: [number, number][] }, { imported: number; synced: boolean }];
  /** password: a new one, or null/absent to keep the current one */
  "send.save": [{ accountId?: string; draft: SendDraft; password?: string | null }, { id: string; accessId: string }];
  "send.delete": [{ accountId?: string; id: string }, void];
  "send.removePassword": [{ accountId?: string; id: string }, void];
  "send.refetch": [{ accountId?: string; id: string }, void];
  // autofill
  "autofill.pageMatches": [{ tabId?: number; url?: string }, { url: string; host: string; tabId?: number; matches: PageMatch[] }];
  "autofill.fill": [{ tabId: number; itemId: string; force?: boolean; verified?: boolean }, { filled: boolean; totpCopied?: boolean; error?: string; confirm?: string; reprompt?: boolean }];
  // inline menu (menu.html inside a page; the background knows its tab and parent frame)
  "menu.ctx": [{ token: string }, { tabId: number; frameId: number; purpose: string | null; host: string; locked: boolean; items: (PageMatch & { host: string | null })[]; passkeys: PasskeyOffer[] }];
  "menu.passkey": [{ token: string; itemId: string; credentialId: string }, { done: boolean; dialog?: boolean; error?: string }];
  "menu.pick": [{ token: string; itemId?: string; generated?: string; force?: boolean }, { filled: boolean; error?: string; reprompt?: boolean; confirm?: string }];
  // save prompt (savebar.html)
  "save.ctx": [{ token: string }, { kind: "save" | "update" | "locked" | "none"; tabId?: number; host: string; username: string; itemName?: string; folders?: { id: string; name: string }[]; type?: string }];
  "save.decide": [{ token: string; action: "save" | "update" | "never" | "dismiss"; folderId?: string | null }, void];
  // passkey dialog (passkey.html inside a page)
  "pk.ctx": [{ token: string }, PasskeyCtx | null];
  "pk.decide": [{ token: string; action: "use" | "save" | "fallback" | "cancel"; itemId?: string; credentialId?: string }, { done: boolean }];
  // clipboard
  "clipboard.copy": [{ text: string; sensitive?: boolean }, void];
  // misc
  "ui.openVault": [{ path?: string } | undefined, void];
  "ui.openPopup": [undefined, void];
  /** Whether the system is in dark mode, where the background can tell (Firefox); else null. */
  "ui.dark": [undefined, boolean | null];
}

export type RpcName = keyof RpcMap;
export type RpcArg<K extends RpcName> = RpcMap[K][0];
export type RpcRes<K extends RpcName> = RpcMap[K][1];

interface Envelope {
  kw: "rpc";
  name: string;
  arg: unknown;
}

export class RpcError extends Error {
  code?: string;
  constructor(message: string, code?: string) {
    super(message);
    this.name = "RpcError";
    this.code = code;
  }
}

export async function rpc<K extends RpcName>(name: K, ...[arg]: undefined extends RpcArg<K> ? [arg?: RpcArg<K>] : [arg: RpcArg<K>]): Promise<RpcRes<K>> {
  const res = await chrome.runtime.sendMessage({ kw: "rpc", name, arg } satisfies Envelope);
  if (!res) throw new RpcError(`no response for ${name}`);
  if (!res.ok) throw new RpcError(res.error, res.code);
  return res.value as RpcRes<K>;
}

export type Handler<K extends RpcName> = (arg: RpcArg<K>, sender: chrome.runtime.MessageSender) => Promise<RpcRes<K>> | RpcRes<K>;
export type Handlers = { [K in RpcName]?: Handler<K> };

/** Installs the background router. Only messages from our own extension are accepted. */
export function serve(handlers: Handlers, extra?: (msg: any, sender: chrome.runtime.MessageSender, respond: (r: any) => void) => boolean | void) {
  chrome.runtime.onMessage.addListener((msg: any, sender, respond) => {
    if (sender.id !== chrome.runtime.id) return false;
    if (msg?.kw !== "rpc") return extra ? extra(msg, sender, respond) ?? false : false;
    // RPC is for our own pages only; content scripts (web-page URLs) use their own messages.
    if (!/^(chrome|moz)-extension:\/\//.test(sender.url ?? "")) return false;
    const h = (handlers as any)[msg.name] as Handler<any> | undefined;
    if (!h) {
      respond({ ok: false, error: `unknown rpc ${msg.name}` });
      return false;
    }
    Promise.resolve()
      .then(() => h(msg.arg, sender))
      .then(
        (value) => respond({ ok: true, value }),
        (e: any) => respond({ ok: false, error: e?.message ?? String(e), code: e?.code ?? e?.name }),
      );
    return true;
  });
}

/** A passkey offered for a sign-in (the dialog, or the inline menu for an autofill request). */
export interface PasskeyOffer {
  itemId: string;
  credentialId: string;
  itemName: string;
  userName: string | null;
  displayName: string | null;
  reprompt: boolean;
}

export type PasskeyCtx =
  /** picked: the user chose this passkey in the inline menu (the dialog only confirms it) */
  | { kind: "get"; host: string; rpId: string; passkeys: PasskeyOffer[]; picked?: boolean }
  | {
      kind: "create";
      host: string;
      rpId: string;
      rpName: string | null;
      userName: string | null;
      displayName: string | null;
      /** excludeCredentials names a passkey already saved */
      exists: boolean;
      /** logins for this site the passkey can be added to */
      targets: { itemId: string; name: string; userName: string | null; hasPasskey: boolean; reprompt: boolean }[];
    };

/** Fan-out of "something changed" notices to every open extension page. */
export type Broadcast =
  | { kind: "vault"; accountId: string; ids?: string[]; full?: boolean }
  | { kind: "sends"; accountId: string }
  | { kind: "lock"; accountId: string | null }
  | { kind: "accounts" }
  | { kind: "sync"; accountId: string; status: SyncStatus }
  | { kind: "settings" };

let channel: BroadcastChannel | null = null;
export function broadcast(msg: Broadcast): void {
  (channel ??= new BroadcastChannel("keyward")).postMessage(msg);
}
export function listen(cb: (msg: Broadcast) => void): () => void {
  const ch = new BroadcastChannel("keyward");
  ch.onmessage = (e) => cb(e.data);
  return () => ch.close();
}
