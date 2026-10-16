import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import { formatCode, otpCode, parseOtp } from "../../core/totp/totp.ts";
import { CipherType, GPG_KIND, type CipherView } from "../../core/vault/types.ts";
import { isGpgFieldName, looksLikeGpgItem } from "../../core/gpg/fields.ts";
import { pwnedCount } from "../../core/watchtower/hibp.ts";
import { quickStrength, STRENGTH_LABEL } from "../../core/watchtower/strength.ts";
import { rpc } from "../../platform/messages.ts";
import { Badge, Banner, Button, ColoredPassword, EmptyState, Group, Icon, IconButton, Row, SecretField, Sheet, Spinner, TopBar, TotpRing, confirm, openMenu, toast } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { account, aux, folderNames, items, openItem, orgNames } from "../data/app.ts";
import { copyText } from "../data/clipboard.ts";
import { pop, push } from "../data/nav.ts";
import { verifyMasterPassword } from "../data/master-password.ts";
import { markVerified, recentlyVerified } from "../data/reprompt.ts";
import { ItemAvatar, TYPE_META } from "./vault-list.tsx";
import { downloadAttachment } from "../data/attachments.ts";
import { useGpgFields } from "../data/gpg.ts";
import { GpgKeyView } from "./gpg.tsx";

// ------------------------------------------------------------------ hooks
export function useTotp(totp: string | null | undefined) {
  const [state, setState] = useState<{ code: string; remaining: number; period: number } | null>(null);
  useEffect(() => {
    const spec = parseOtp(totp);
    if (!spec) {
      setState(null);
      return;
    }
    let alive = true;
    let timer = 0;
    const tick = async () => {
      const c = await otpCode(spec);
      if (!alive) return;
      setState(c);
      timer = window.setTimeout(tick, 1000 - (Date.now() % 1000) + 5);
    };
    void tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [totp]);
  return state;
}

export function RepromptSheet({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <Sheet center onClose={onCancel}>
      <h2>Confirm it's you</h2>
      <p class="t-body-m med" style={{ marginTop: 0 }}>This item is protected. Enter your master password to continue.</p>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          if (await verifyMasterPassword(pw, account.value)) {
            markVerified();
            onDone();
          } else {
            setErr("Invalid master password");
            setBusy(false);
          }
        }}
      >
        <SecretField label="Master password" value={pw} onInput={setPw} autoFocus error={err} />
        <div class="actions">
          <Button variant="text" onClick={onCancel}>Cancel</Button>
          <Button type="submit" loading={busy} disabled={!pw}>Confirm</Button>
        </div>
      </form>
    </Sheet>
  );
}

// ------------------------------------------------------------------ value rows
export function ValueRow({
  label, value, secret, mono, copy = true, what, badges, trailing, onClick, colored, multiline,
}: {
  label: string;
  value: string | null | undefined;
  secret?: boolean;
  mono?: boolean;
  copy?: boolean;
  what?: string;
  badges?: ComponentChildren;
  trailing?: ComponentChildren;
  onClick?: () => void;
  colored?: boolean;
  multiline?: boolean;
}) {
  const [shown, setShown] = useState(false);
  if (!value) return null;
  const display = secret && !shown ? "••••••••" : value;
  return (
    <Row
      title={<span class="label t-label-m med" style={{ display: "block", fontWeight: 500 }}>{label}</span>}
      sub={undefined}
      below={
        <div class="col" style={{ gap: "6px", width: "100%" }}>
          <div class={`val ${mono || (secret && shown) ? "mono" : ""}`} style={{ color: "var(--on-surface)", fontSize: "16px", lineHeight: "24px", wordBreak: "break-all", whiteSpace: multiline ? "pre-wrap" : undefined }}>
            {colored && shown ? <ColoredPassword value={value} /> : display}
          </div>
          {badges && <div class="row" style={{ gap: "8px", flexWrap: "wrap" }}>{badges}</div>}
        </div>
      }
      trailing={
        <>
          {trailing}
          {secret && <IconButton icon={shown ? I.eyeOff : I.eye} label={shown ? "Hide" : "Show"} onClick={(e) => { e.stopPropagation(); setShown(!shown); }} />}
          {copy && <IconButton icon={I.copy} label={`Copy ${what ?? label.toLowerCase()}`} onClick={(e) => { e.stopPropagation(); void copyText(value, what ?? label, !!secret); }} />}
        </>
      }
      onClick={onClick ?? (copy ? () => void copyText(value, what ?? label, !!secret) : undefined)}
    />
  );
}

function StrengthBadge({ pw }: { pw: string }) {
  const s = quickStrength(pw);
  return <Badge tone={s <= 1 ? "error" : s === 2 ? "warn" : "ok"} icon={s <= 1 ? I.gppMaybe : I.verified}>{STRENGTH_LABEL[s]}</Badge>;
}

function PwnedBadge({ pw }: { pw: string }) {
  const [state, setState] = useState<"idle" | "busy" | number | "error">("idle");
  if (state === "idle")
    return (
      <button class="badge outline" style={{ border: 0, cursor: "pointer" }} onClick={async (e) => { e.stopPropagation(); setState("busy"); try { setState(await pwnedCount(pw)); } catch { setState("error"); } }}>
        <Icon d={I.travelExplore} size={16} />
        Check for breaches
      </button>
    );
  if (state === "busy") return <Badge tone="outline"><Spinner size={14} /> Checking…</Badge>;
  if (state === "error") return <Badge tone="warn" icon={I.cloudOff}>Breach check failed</Badge>;
  return state > 0 ? <Badge tone="error" icon={I.warning}>Found in {state.toLocaleString()} breaches</Badge> : <Badge tone="ok" icon={I.verified}>Not found in breaches</Badge>;
}

function TotpRow({ totp }: { totp: string }) {
  const c = useTotp(totp);
  if (!c) return <ValueRow label="One-time password" value="Invalid TOTP secret" copy={false} />;
  return (
    <Row
      title={<span class="t-label-m med" style={{ display: "block" }}>One-time password</span>}
      below={
        <div class="row" style={{ gap: "10px", color: "var(--on-surface)" }}>
          <span class="mono" style={{ fontSize: "22px", lineHeight: "28px", letterSpacing: "1px" }}>{formatCode(c.code)}</span>
          {c.period > 0 && (
            <span class="row t-label-m" style={{ gap: "4px", color: c.remaining <= 5 ? "var(--error)" : "var(--on-surface-med)" }}>
              <TotpRing remaining={c.remaining} period={c.period} />
              <b class="mono">{c.remaining}</b>
            </span>
          )}
        </div>
      }
      trailing={<IconButton icon={I.copy} label="Copy code" onClick={(e) => { e.stopPropagation(); void copyText(c.code, "Code", false); }} />}
      onClick={() => void copyText(c.code, "Code", false)}
    />
  );
}

function fmtDate(d: string | null | undefined): string | null {
  if (!d) return null;
  const t = new Date(d);
  return isNaN(+t) ? d : t.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function launchable(uri: string): string | null {
  const u = /^[a-z][a-z0-9+.-]*:\/\//i.test(uri) ? uri : `https://${uri}`;
  return /^https?:\/\//i.test(u) ? u : null;
}

// ------------------------------------------------------------------ screen
export function ItemView({ id, embedded, onFill }: { id: string; embedded?: boolean; onFill?: (id: string, verified?: boolean) => void }) {
  const [view, setView] = useState<CipherView | null | undefined>(undefined);
  const [unlocked, setUnlocked] = useState(false);
  const [prompting, setPrompting] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    setView(undefined);
    setUnlocked(false);
  }, [id]);
  // Reload whenever this item's summary changes (restore, move, favorite, a sync from elsewhere).
  const sum = items.value.get(id);
  useEffect(() => {
    let alive = true;
    openItem(id).then((r) => alive && setView(r?.view ?? null));
    return () => {
      alive = false;
    };
  }, [id, sum?.rev, sum?.del, sum?.folder, sum?.fav, sum?.arch]);
  const gpg = useGpgFields(view);

  if (view === undefined) return <div style={{ padding: "48px", display: "grid", placeItems: "center" }}><Spinner /></div>;
  if (view === null) return <EmptyState text="This item no longer exists"><Button variant="tonal" onClick={pop}>Back</Button></EmptyState>;
  const v = view;
  const needsReprompt = v.reprompt === 1 && !unlocked && !recentlyVerified();
  const isGpg = looksLikeGpgItem(v) && gpg !== null;
  const s = { id: v.id, name: v.name, type: v.type, uris: v.login?.uris.map((u) => u.uri) ?? [], fav: v.favorite, rp: v.reprompt === 1, att: v.attachments.length > 0, pk: [], gpg: isGpg };
  // A GPG key item's own fields; its key fields show as the GPG key section instead.
  const fields = gpg ? gpg.rest : isGpg ? v.fields.filter((f) => !isGpgFieldName(f.name)) : v.fields;
  const l = v.login;
  const hidePw = !v.viewPassword;

  async function act(name: string, fn: () => Promise<unknown>, ok?: string) {
    try {
      await fn();
      if (ok) toast(ok, { tone: "ok" });
    } catch (e) {
      toast(`${name} failed: ${(e as Error).message}`, { tone: "error" });
    }
  }

  const menu = (e: MouseEvent) => {
    // currentTarget is null once the event has finished: keep the button for the submenu.
    const anchor = e.currentTarget as HTMLElement;
    openMenu(anchor, [
      ...(v.deletedDate
        ? [
            { icon: I.restore, label: "Restore", run: () => act("Restore", () => rpc("vault.restore", { ids: [v.id] }), "Restored") },
            {
              icon: I.del, label: "Delete forever", danger: true,
              run: async () => (await confirm("Delete forever?", "This can't be undone.", "Delete", true)) && act("Delete", async () => { await rpc("vault.delete", { ids: [v.id], permanent: true }); pop(); }),
            },
          ]
        : [
            { icon: I.edit, label: "Edit", run: () => push({ name: "edit", id: v.id }) },
            { icon: I.copy, label: "Clone", run: () => push({ name: "edit", type: v.type, prefill: { clone: v.id } }) },
            ...(isGpg ? [{ icon: I.keyVertical, label: "Use in GPG tools", run: () => push({ name: "gpg-tools", key: v.id }) }] : []),
            {
              icon: I.folder, label: "Move to folder…",
              run: () =>
                openMenu(anchor, [
                  { icon: I.remove, label: "No folder", run: () => act("Move", () => rpc("vault.move", { ids: [v.id], folderId: null }), "Moved") },
                  ...aux.value.folders.map((f) => ({ icon: I.folder, label: f.name, run: () => act("Move", () => rpc("vault.move", { ids: [v.id], folderId: f.id }), "Moved") })),
                ]),
            },
            v.archivedDate
              ? { icon: I.unarchive, label: "Unarchive", run: () => act("Unarchive", () => rpc("vault.archive", { ids: [v.id], archive: false }), "Unarchived") }
              : { icon: I.archive, label: "Archive", run: () => act("Archive", async () => { await rpc("vault.archive", { ids: [v.id], archive: true }); pop(); }, "Archived") },
            { divider: true, label: "" },
            {
              icon: I.del, label: "Move to trash", danger: true,
              run: async () => (await confirm("Move to trash?", `“${v.name}” can be restored from Trash.`, "Move to trash", true)) && act("Delete", async () => { await rpc("vault.delete", { ids: [v.id] }); pop(); }, "Moved to trash"),
            },
          ]),
    ]);
  };

  const body = (
    <>
      {v.errors.length > 0 && <Banner tone="warn">Some fields could not be decrypted: {v.errors.slice(0, 3).join("; ")}</Banner>}
      {v.deletedDate && <Banner tone="info" icon={I.del}>In trash since {fmtDate(v.deletedDate)}</Banner>}
      {v.archivedDate && <Banner tone="info" icon={I.archive}>Archived</Banner>}

      {l && (l.username || l.password || l.totp) && (
        <Group>
          <ValueRow label="Username" value={l.username} what="Username" />
          {!hidePw && (
            <ValueRow
              label="Password"
              value={l.password}
              secret
              colored
              what="Password"
              badges={l.password ? (
                <>
                  <StrengthBadge pw={l.password} />
                  <PwnedBadge pw={l.password} />
                  {l.passwordRevisionDate && <Badge tone="outline" icon={I.history}>Changed {new Date(l.passwordRevisionDate).toLocaleDateString()}</Badge>}
                </>
              ) : undefined}
            />
          )}
          {l.totp && <TotpRow totp={l.totp} />}
        </Group>
      )}

      {l && l.fido2Credentials.length > 0 && (
        <Group label="Passkeys">
          {l.fido2Credentials.map((f) => (
            <Row key={f.credentialId} leading={<Icon d={I.passkey} />} title={f.userName || f.userDisplayName || "Passkey"} sub={`${f.rpId} · created ${new Date(f.creationDate).toLocaleDateString()}`} />
          ))}
        </Group>
      )}

      {v.type === CipherType.Card && v.card && (
        <Group label="Card">
          <ValueRow label="Cardholder name" value={v.card.cardholderName} />
          <ValueRow label="Number" value={v.card.number?.replace(/(\d{4})(?=\d)/g, "$1 ")} secret mono what="Card number" />
          <ValueRow label="Brand" value={v.card.brand} copy={false} />
          <ValueRow label="Expiration" value={v.card.expMonth || v.card.expYear ? `${(v.card.expMonth ?? "").padStart(2, "0")} / ${v.card.expYear ?? ""}` : null} />
          <ValueRow label="Security code" value={v.card.code} secret mono what="Security code" />
        </Group>
      )}

      {v.type === CipherType.Identity && v.identity && (
        <>
          <Group label="Identity">
            <ValueRow label="Name" value={[v.identity.title, v.identity.firstName, v.identity.middleName, v.identity.lastName].filter(Boolean).join(" ")} />
            <ValueRow label="Username" value={v.identity.username} />
            <ValueRow label="Company" value={v.identity.company} />
            <ValueRow label="Email" value={v.identity.email} />
            <ValueRow label="Phone" value={v.identity.phone} />
          </Group>
          {(v.identity.ssn || v.identity.passportNumber || v.identity.licenseNumber) && (
            <Group label="Documents">
              <ValueRow label="National ID / SSN" value={v.identity.ssn} secret mono />
              <ValueRow label="Passport number" value={v.identity.passportNumber} secret mono />
              <ValueRow label="License number" value={v.identity.licenseNumber} secret mono />
            </Group>
          )}
          {(v.identity.address1 || v.identity.city || v.identity.country) && (
            <Group label="Address">
              <ValueRow
                label="Address"
                multiline
                value={[v.identity.address1, v.identity.address2, v.identity.address3, [v.identity.postalCode, v.identity.city, v.identity.state].filter(Boolean).join(" "), v.identity.country].filter(Boolean).join("\n")}
              />
            </Group>
          )}
        </>
      )}

      {v.type === CipherType.SshKey && v.sshKey && (
        <Group label="SSH key">
          <ValueRow label="Public key" value={v.sshKey.publicKey} mono />
          <ValueRow label="Fingerprint" value={v.sshKey.keyFingerprint} mono />
          <ValueRow label="Private key" value={v.sshKey.privateKey} secret mono multiline what="Private key" />
        </Group>
      )}

      {gpg && <GpgKeyView name={v.name} gkey={gpg.key} />}

      {l && l.uris.length > 0 && (
        <Group label="Websites">
          {l.uris.map((u, i) => {
            const href = launchable(u.uri);
            const insecure = /^http:\/\//i.test(u.uri);
            return (
              <Row
                key={i}
                leading={<Icon d={I.globe} />}
                title={<span class="ellipsis" style={{ display: "block", fontWeight: 400 }}>{u.uri}</span>}
                sub={u.match != null ? ["Base domain", "Host", "Starts with", "Exact", "Regular expression", "Never"][u.match] : undefined}
                below={insecure ? <Badge tone="warn" icon={I.warning}>Not secure (http)</Badge> : undefined}
                trailing={
                  <>
                    {href && <IconButton icon={I.openInNew} label="Open website" onClick={(e) => { e.stopPropagation(); void chrome.tabs.create({ url: href }); }} />}
                    <IconButton icon={I.copy} label="Copy URL" onClick={(e) => { e.stopPropagation(); void copyText(u.uri, "URL", false); }} />
                  </>
                }
                onClick={href ? () => void chrome.tabs.create({ url: href }) : undefined}
              />
            );
          })}
        </Group>
      )}

      {fields.length > 0 && (
        <Group label="Custom fields">
          {fields.map((f, i) =>
            f.type === 2 ? (
              <Row key={i} title={<span class="t-label-m med">{f.name}</span>} below={<span style={{ color: "var(--on-surface)" }}>{f.value === "true" ? "On" : "Off"}</span>} trailing={<Icon d={I.toggle} />} />
            ) : f.type === 3 ? (
              <Row key={i} title={<span class="t-label-m med">{f.name}</span>} below={<span style={{ color: "var(--on-surface)" }}>Linked to {LINKED[f.linkedId ?? -1] ?? "field"}</span>} trailing={<Icon d={I.link} />} />
            ) : (
              <ValueRow key={i} label={f.name ?? "Field"} value={f.value} secret={f.type === 1} />
            ),
          )}
        </Group>
      )}

      {v.notes && (
        <Group label="Notes">
          <ValueRow label="Notes" value={v.notes} multiline what="Notes" />
        </Group>
      )}

      {v.attachments.length > 0 && (
        <Group label="Attachments">
          {v.attachments.map((a) => (
            <Row key={a.id} leading={<Icon d={I.attach} />} title={a.fileName ?? "file"} sub={a.sizeName ?? undefined}
              trailing={<IconButton icon={I.download} label="Download" onClick={(e) => { e.stopPropagation(); void downloadAttachment(v, a).catch((err) => toast(`Download failed: ${err.message}`, { tone: "error" })); }} />}
              onClick={() => void downloadAttachment(v, a).catch((err) => toast(`Download failed: ${err.message}`, { tone: "error" }))} />
          ))}
        </Group>
      )}

      <Group label="Details">
        <Row leading={<Icon d={TYPE_META[isGpg ? GPG_KIND : v.type]?.icon ?? I.key} />} title={TYPE_META[isGpg ? GPG_KIND : v.type]?.label ?? "Item"} sub="Type" />
        <Row leading={<Icon d={I.folder} />} title={v.folderId ? folderNames.value.get(v.folderId) ?? "Folder" : "No folder"} sub="Folder" />
        {v.organizationId && <Row leading={<Icon d={I.group} />} title={orgNames.value.get(v.organizationId) ?? "Organization"} sub={v.collectionIds.map((c) => aux.value.collections.find((x) => x.id === c)?.name).filter(Boolean).join(", ") || "Organization"} />}
        {v.passwordHistory.length > 0 && <Row leading={<Icon d={I.history} />} title={`Password history (${v.passwordHistory.length})`} onClick={() => push({ name: "history", id: v.id })} trailing={<Icon d={I.chevron} />} />}
        <Row leading={<Icon d={I.schedule} />} title={fmtDate(v.revisionDate) ?? "—"} sub={`Modified${v.creationDate ? ` · created ${fmtDate(v.creationDate)}` : ""}`} />
      </Group>
      <div style={{ height: "96px" }} />
    </>
  );

  return (
    <div class="item-view" onScroll={(e) => setScrolled((e.currentTarget as HTMLElement).scrollTop > 4)}>
      <TopBar
        back={embedded ? undefined : pop}
        scrolled={scrolled}
        small
        title={
          <span class="row" style={{ gap: "12px" }}>
            <ItemAvatar s={s} />
            <span class="ellipsis" title={v.name}>{v.name}</span>
          </span>
        }
        actions={
          <>
            <IconButton icon={v.favorite ? I.starFill : I.star} label={v.favorite ? "Remove from favorites" : "Add to favorites"} on={v.favorite}
              onClick={() => act("Favorite", async () => { await rpc("vault.favorite", { id: v.id, favorite: !v.favorite }); setView({ ...v, favorite: !v.favorite }); })} />
            {!v.deletedDate && v.edit && <IconButton icon={I.edit} label="Edit" onClick={() => push({ name: "edit", id: v.id })} />}
            <IconButton icon={I.more} label="More" onClick={menu} />
          </>
        }
      />
      {needsReprompt ? (
        <>
          <EmptyState text="This item is protected by master password re-prompt." icon={I.lock}>
            <Button icon={I.lockOpen} onClick={() => setPrompting(true)}>Show item</Button>
          </EmptyState>
          {prompting && <RepromptSheet onDone={() => { setPrompting(false); setUnlocked(true); }} onCancel={() => setPrompting(false)} />}
        </>
      ) : (
        body
      )}
      {onFill && FILLABLE.has(v.type) && !v.deletedDate && !needsReprompt && (
        // Shown only once a protected item is unlocked here, so the fill counts as verified.
        <button class="fab" onClick={() => onFill(v.id, true)}>
          <Icon d={I.keyboard} />
          Fill
        </button>
      )}
    </div>
  );
}

/** Types the popup can fill into the page (through autofill.fill, like the "This site" list). */
const FILLABLE = new Set<CipherType>([CipherType.Login, CipherType.Card, CipherType.Identity]);

export const LINKED: Record<number, string> = {
  100: "Username", 101: "Password",
  300: "Cardholder name", 301: "Exp. month", 302: "Exp. year", 303: "Security code", 304: "Brand", 305: "Number",
  400: "Title", 401: "Middle name", 402: "Address 1", 403: "Address 2", 404: "Address 3", 405: "City", 406: "State", 407: "Postal code",
  408: "Country", 409: "Company", 410: "Email", 411: "Phone", 412: "SSN", 413: "Username", 414: "Passport number", 415: "License number",
  416: "First name", 417: "Last name", 418: "Full name",
};

export function PasswordHistory({ id }: { id: string }) {
  const [v, setV] = useState<CipherView | null>(null);
  useEffect(() => {
    openItem(id).then((r) => setV(r?.view ?? null));
  }, [id]);
  return (
    <div class="item-view">
      <TopBar back={pop} title="Password history" small />
      {!v ? (
        <div style={{ padding: "48px", display: "grid", placeItems: "center" }}><Spinner /></div>
      ) : v.passwordHistory.length === 0 ? (
        <EmptyState text="No earlier passwords" icon={I.history} />
      ) : (
        <Group>
          {v.passwordHistory.map((h, i) => (
            <Row
              key={i}
              title={<ColoredPassword value={h.password} />}
              sub={`Used until ${new Date(h.lastUsedDate).toLocaleString()}`}
              trailing={<IconButton icon={I.copy} label="Copy password" onClick={() => copyText(h.password, "Password")} />}
            />
          ))}
        </Group>
      )}
    </div>
  );
}
