import { useEffect, useMemo, useState } from "preact/hooks";
import { emptyView } from "../../core/vault/cipher.ts";
import { CipherType, GPG_KIND, IDENTITY_FIELDS, type CipherView, type FieldView, type ItemKind } from "../../core/vault/types.ts";
import { decodeGpgFields, encodeGpgFields, looksLikeGpgItem, type GpgKeyFields } from "../../core/gpg/fields.ts";
import { generatePassword, DEFAULT_PASSWORD } from "../../core/generator/password.ts";
import { parseOtp } from "../../core/totp/totp.ts";
import { quickStrength, STRENGTH_LABEL } from "../../core/watchtower/strength.ts";
import { rpc } from "../../platform/messages.ts";
import { Badge, Banner, Button, Group, Icon, IconButton, Row, SecretField, Select, Spinner, Switch, TextField, TopBar, confirm, openMenu, toast } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { aux, openItem, settings } from "../data/app.ts";
import { pop, replace } from "../data/nav.ts";
import { TYPE_META } from "./vault-list.tsx";
import { deleteAttachment, uploadAttachment } from "../data/attachments.ts";
import { loadGeneratorPrefs } from "./generator.tsx";
import { GpgKeyEditor } from "./gpg.tsx";

const MATCH_LABELS = ["Base domain", "Host", "Starts with", "Exact", "Regular expression", "Never"];

export function cardBrand(num: string | null): string | null {
  const n = (num ?? "").replace(/\D/g, "");
  if (/^4/.test(n)) return "Visa";
  if (/^(5[1-5]|2[2-7])/.test(n)) return "Mastercard";
  if (/^3[47]/.test(n)) return "Amex";
  if (/^220[0-4]/.test(n)) return "Mir";
  if (/^(6011|65|64[4-9])/.test(n)) return "Discover";
  if (/^35/.test(n)) return "JCB";
  if (/^3(0[0-5]|[68])/.test(n)) return "Diners Club";
  if (/^62/.test(n)) return "UnionPay";
  if (/^(5018|5020|5038|6304|6759|676[1-3])/.test(n)) return "Maestro";
  return null;
}

function Section({ label, children }: { label?: string; children: any }) {
  return (
    <>
      {label && <div class="section-label">{label}</div>}
      <div class="col" style={{ gap: "10px", margin: "0 16px" }}>{children}</div>
    </>
  );
}


/** A GPG key item's view without its key fields, and the key; other items as they are. */
async function splitGpg(view: CipherView): Promise<[CipherView, GpgKeyFields | null]> {
  const d = looksLikeGpgItem(view) ? await decodeGpgFields(view.fields) : null;
  return d ? [{ ...view, fields: d.rest }, d.key] : [view, null];
}

export function ItemEdit({ id, type, prefill }: { id?: string; type?: ItemKind; prefill?: Record<string, any> }) {
  const [v, setV] = useState<CipherView | null>(null);
  const [orig, setOrig] = useState<CipherView | null>(null);
  // A GPG key item's key (null for other items); kept apart from the custom fields it is stored in.
  const [gkey, setGkey] = useState<GpgKeyFields | null>(null);
  const [origKey, setOrigKey] = useState<GpgKeyFields | null>(null);
  const [cols, setCols] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      if (id) {
        const r = await openItem(id);
        if (r) {
          const [view, key] = await splitGpg(r.view);
          setV(structuredClone(view));
          setOrig(view);
          setGkey(key);
          setOrigKey(key);
          setCols(r.view.collectionIds);
        }
      } else if (prefill?.clone) {
        const r = await openItem(prefill.clone);
        if (r) {
          const [view, key] = await splitGpg(r.view);
          setV({ ...structuredClone(view), id: "", name: r.view.name + " (copy)", attachments: [], passwordHistory: [], revisionDate: null, creationDate: null });
          setGkey(key);
        }
      } else {
        const t = type === GPG_KIND ? CipherType.SecureNote : (type ?? CipherType.Login);
        const base = emptyView(t);
        if (type === GPG_KIND) setGkey({ privateKey: null, publicKey: null, fingerprint: null });
        if (t === CipherType.Login && prefill) {
          base.name = prefill.name ?? "";
          base.login!.username = prefill.username ?? null;
          base.login!.password = prefill.password ?? null;
          if (prefill.uri) base.login!.uris = [{ uri: prefill.uri, match: null }];
        }
        if (prefill?.folderId) base.folderId = prefill.folderId;
        setV(base);
      }
    })();
  }, [id, prefill?.clone]);

  const dirty = useMemo(() => JSON.stringify([v, gkey]) !== JSON.stringify([orig, origKey]), [v, orig, gkey, origKey]);
  if (!v) return <div style={{ padding: "48px", display: "grid", placeItems: "center" }}><Spinner /></div>;

  const set = (patch: Partial<CipherView>) => setV({ ...v, ...patch });
  const setLogin = (patch: Partial<NonNullable<CipherView["login"]>>) => setV({ ...v, login: { ...v.login!, ...patch } });
  const setCard = (patch: Partial<NonNullable<CipherView["card"]>>) => setV({ ...v, card: { ...v.card!, ...patch } });
  const setIdentity = (k: string, val: string) => setV({ ...v, identity: { ...v.identity!, [k]: val || null } });
  const setSsh = (patch: Partial<NonNullable<CipherView["sshKey"]>>) => setV({ ...v, sshKey: { ...v.sshKey!, ...patch } });
  const setField = (i: number, patch: Partial<FieldView>) => setV({ ...v, fields: v.fields.map((f, k) => (k === i ? { ...f, ...patch } : f)) });

  async function save() {
    if (!v!.name.trim()) {
      setErr("Name is required");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const next = structuredClone(v!);
      // Password history + revision date, as the official clients do.
      if (orig?.login && next.login && orig.login.password && orig.login.password !== next.login.password) {
        next.passwordHistory = [{ password: orig.login.password, lastUsedDate: new Date().toISOString() }, ...next.passwordHistory].slice(0, 5);
        next.login.passwordRevisionDate = new Date().toISOString();
      }
      if (next.login) next.login.uris = next.login.uris.filter((u) => u.uri.trim());
      if (next.type === CipherType.Card && next.card && !next.card.brand) next.card.brand = cardBrand(next.card.number);
      if (next.organizationId && !cols.length) throw new Error("Pick at least one collection");
      if (gkey) {
        if (!gkey.privateKey && !gkey.publicKey) throw new Error("Generate or import a key");
        next.fields = await encodeGpgFields(gkey, next.fields);
      }
      const r = await rpc("vault.save", { view: next, collectionIds: next.organizationId ? cols : undefined });
      if (r.conflict) {
        toast("This item was changed on another device. Your edit was saved as a copy.", { tone: "error", ms: 8000 });
        replace({ name: "item", id: r.id });
        return;
      }
      toast(id ? "Saved" : "Item created", { tone: "ok" });
      if (id) pop();
      else replace({ name: "item", id: r.id });
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    if (dirty && !(await confirm("Discard changes?", undefined, "Discard", true))) return;
    pop();
  }

  const l = v.login;
  const strength = l?.password ? quickStrength(l.password) : null;
  const totpOk = !l?.totp || !!parseOtp(l.totp);
  const orgCols = aux.value.collections.filter((c) => c.orgId === v.organizationId && !c.readOnly);

  return (
    <div class="item-edit" onKeyDown={(e) => { if ((e.ctrlKey || e.metaKey) && e.key === "s") { e.preventDefault(); void save(); } }}>
      <TopBar
        back={cancel}
        small
        title={id ? "Edit item" : gkey ? "New GPG key" : `New ${TYPE_META[v.type]?.label.toLowerCase() ?? "item"}`}
        actions={<Button variant="filled" loading={busy} onClick={save} icon={I.check} style={{ marginRight: "8px" }}>Save</Button>}
      />
      {err && <Banner tone="error">{err}</Banner>}

      <Section>
        <TextField label="Name" value={v.name} onInput={(x) => set({ name: x })} autoFocus={!id} />
      </Section>

      {l && (
        <Section label="Login">
          <TextField label="Username" value={l.username ?? ""} onInput={(x) => setLogin({ username: x || null })} autocomplete="off" />
          <SecretField
            label="Password"
            value={l.password ?? ""}
            onInput={(x) => setLogin({ password: x || null })}
            mono
            hint={strength != null ? <span class="row" style={{ gap: "6px" }}><Badge tone={strength <= 1 ? "error" : strength === 2 ? "warn" : "ok"}>{STRENGTH_LABEL[strength]}</Badge>{l.password?.length} characters</span> : undefined}
            extra={<IconButton icon={I.dice} label="Generate password" onClick={async () => setLogin({ password: generatePassword((await loadGeneratorPrefs()).password ?? DEFAULT_PASSWORD) })} />}
          />
          <TextField label="Authenticator key (TOTP)" value={l.totp ?? ""} onInput={(x) => setLogin({ totp: x || null })} mono error={totpOk ? null : "Not a valid TOTP secret or otpauth:// URI"} hint="Base32 secret, otpauth:// or steam:// URI" />
          {l.uris.map((u, i) => (
            <div class="row" style={{ gap: "4px" }} key={i}>
              <div class="grow">
                <TextField
                  label={l.uris.length > 1 ? `Website ${i + 1}` : "Website"}
                  value={u.uri}
                  onInput={(x) => setLogin({ uris: l.uris.map((w, k) => (k === i ? { ...w, uri: x } : w)) })}
                  type="url"
                  hint={u.match != null ? `Match: ${MATCH_LABELS[u.match]}` : undefined}
                />
              </div>
              <IconButton
                icon={I.tune}
                label="Match detection"
                onClick={(e) =>
                  openMenu(e.currentTarget as HTMLElement, [
                    { header: true, label: "Match detection" },
                    { icon: u.match == null ? I.check : I.globe, label: `Default (${MATCH_LABELS[settings.value.defaultUriMatch]})`, run: () => setLogin({ uris: l.uris.map((w, k) => (k === i ? { ...w, match: null } : w)) }) },
                    ...MATCH_LABELS.map((m, k) => ({ icon: u.match === k ? I.check : I.globe, label: m, run: () => setLogin({ uris: l.uris.map((w, j) => (j === i ? { ...w, match: k as any } : w)) }) })),
                  ])
                }
              />
              <IconButton icon={I.close} label="Remove website" onClick={() => setLogin({ uris: l.uris.filter((_, k) => k !== i) })} />
            </div>
          ))}
          <Button variant="tonal" icon={I.add} onClick={() => setLogin({ uris: [...l.uris, { uri: "", match: null }] })}>Add website</Button>
          {l.fido2Credentials.length > 0 && (
            <div class="group" style={{ margin: 0 }}>
              {l.fido2Credentials.map((f, i) => (
                <Row key={f.credentialId} leading={<Icon d={I.passkey} />} title={f.userName || "Passkey"} sub={f.rpId}
                  trailing={<IconButton icon={I.del} label="Remove passkey" onClick={async () => (await confirm("Remove passkey?", "You won't be able to sign in with it.", "Remove", true)) && setLogin({ fido2Credentials: l.fido2Credentials.filter((_, k) => k !== i) })} />} />
              ))}
            </div>
          )}
        </Section>
      )}

      {v.card && (
        <Section label="Card">
          <TextField label="Cardholder name" value={v.card.cardholderName ?? ""} onInput={(x) => setCard({ cardholderName: x || null })} />
          <SecretField label="Number" value={v.card.number ?? ""} onInput={(x) => setCard({ number: x || null, brand: cardBrand(x) ?? v.card!.brand })} inputMode="numeric" mono />
          <TextField label="Brand" value={v.card.brand ?? ""} onInput={(x) => setCard({ brand: x || null })} />
          <div class="row" style={{ gap: "10px" }}>
            <div class="grow"><TextField label="Exp. month" value={v.card.expMonth ?? ""} onInput={(x) => setCard({ expMonth: x || null })} inputMode="numeric" maxLength={2} /></div>
            <div class="grow"><TextField label="Exp. year" value={v.card.expYear ?? ""} onInput={(x) => setCard({ expYear: x || null })} inputMode="numeric" maxLength={4} /></div>
          </div>
          <SecretField label="Security code" value={v.card.code ?? ""} onInput={(x) => setCard({ code: x || null })} inputMode="numeric" mono />
        </Section>
      )}

      {v.identity && (
        <Section label="Identity">
          {IDENTITY_FIELDS.map((k) => (
            <TextField key={k} label={IDENTITY_LABELS[k]} value={(v.identity as any)[k] ?? ""} onInput={(x) => setIdentity(k, x)} />
          ))}
        </Section>
      )}

      {gkey && (
        <Section label="GPG key">
          <GpgKeyEditor value={gkey} onChange={setGkey} suggestName={(n) => n && setV((cur) => (cur && !cur.name.trim() ? { ...cur, name: n } : cur))} />
        </Section>
      )}

      {v.sshKey && (
        <Section label="SSH key">
          <SshKeyEditor value={v.sshKey} onChange={setSsh} />
        </Section>
      )}

      <Section label="Notes">
        <TextField label="Notes" value={v.notes ?? ""} onInput={(x) => set({ notes: x || null })} multiline />
      </Section>

      <Section label="Custom fields">
        {v.fields.map((f, i) => (
          <div class="row" style={{ gap: "4px", alignItems: "flex-start" }} key={i}>
            <div class="col grow" style={{ gap: "6px" }}>
              <TextField label="Field name" value={f.name ?? ""} onInput={(x) => setField(i, { name: x })} />
              {f.type === 2 ? (
                <label class="row item" style={{ borderRadius: "16px" }}><span class="grow">Value</span><Switch checked={f.value === "true"} onChange={(b) => setField(i, { value: String(b) })} /></label>
              ) : f.type === 1 ? (
                <SecretField label="Value" value={f.value ?? ""} onInput={(x) => setField(i, { value: x })} />
              ) : f.type === 0 ? (
                <TextField label="Value" value={f.value ?? ""} onInput={(x) => setField(i, { value: x })} />
              ) : (
                <div class="t-body-s med" style={{ padding: "0 16px" }}>Linked field</div>
              )}
            </div>
            <IconButton icon={I.close} label="Remove field" onClick={() => set({ fields: v.fields.filter((_, k) => k !== i) })} />
          </div>
        ))}
        <Button
          variant="tonal"
          icon={I.add}
          onClick={(e) =>
            openMenu(e.currentTarget as HTMLElement, [
              { icon: I.textFields, label: "Text", run: () => set({ fields: [...v.fields, { type: 0, name: "", value: "", linkedId: null }] }) },
              { icon: I.eyeOff, label: "Hidden", run: () => set({ fields: [...v.fields, { type: 1, name: "", value: "", linkedId: null }] }) },
              { icon: I.toggle, label: "Checkbox", run: () => set({ fields: [...v.fields, { type: 2, name: "", value: "false", linkedId: null }] }) },
            ])
          }
        >
          Add field
        </Button>
      </Section>

      <Section label="Options">
        <Select
          label="Folder"
          value={v.folderId ?? ""}
          onChange={(x) => set({ folderId: x || null })}
          options={[["", "No folder"], ...aux.value.folders.map((f) => [f.id, f.name] as [string, string])]}
        />
        {aux.value.orgs.length > 0 && (
          <Select
            label="Owner"
            value={v.organizationId ?? ""}
            onChange={(x) => { set({ organizationId: x || null }); setCols([]); }}
            options={[["", "My vault"], ...aux.value.orgs.map((o) => [o.id, o.name] as [string, string])]}
          />
        )}
        {v.organizationId && (
          <div class="group" style={{ margin: 0 }}>
            {orgCols.map((c) => (
              <Row key={c.id} leading={<Icon d={I.inventory} />} title={c.name}
                onClick={() => setCols(cols.includes(c.id) ? cols.filter((x) => x !== c.id) : [...cols, c.id])}
                trailing={<Switch checked={cols.includes(c.id)} label={c.name} onChange={(b) => setCols(b ? [...cols, c.id] : cols.filter((x) => x !== c.id))} />} />
            ))}
            {!orgCols.length && <Row title="No collections you can edit" />}
          </div>
        )}
        <div class="group" style={{ margin: 0 }}>
          <Row leading={<Icon d={I.star} />} title="Favorite" trailing={<Switch checked={v.favorite} onChange={(b) => set({ favorite: b })} />} onClick={() => set({ favorite: !v.favorite })} />
          <Row leading={<Icon d={I.lock} />} title="Master password re-prompt" sub="Ask for the master password before showing or filling" trailing={<Switch checked={v.reprompt === 1} onChange={(b) => set({ reprompt: b ? 1 : 0 })} />} onClick={() => set({ reprompt: v.reprompt === 1 ? 0 : 1 })} />
        </div>
      </Section>

      {id && orig && (
        <Section label="Attachments">
          <div class="group" style={{ margin: 0 }}>
            {orig.attachments.map((a) => (
              <Row key={a.id} leading={<Icon d={I.attach} />} title={a.fileName ?? "file"} sub={a.sizeName ?? undefined}
                trailing={<IconButton icon={I.del} label="Delete attachment" onClick={async () => {
                  if (!(await confirm("Delete attachment?", a.fileName ?? "", "Delete", true))) return;
                  try { await deleteAttachment(orig, a); await rpc("vault.refetch", { ids: [orig.id] }); const r = await openItem(orig.id); r && setOrig(r.view); toast("Deleted"); } catch (e) { toast((e as Error).message, { tone: "error" }); }
                }} />} />
            ))}
          </div>
          <label class="btn tonal has-icon" style={{ alignSelf: "flex-start" }}>
            <Icon d={I.upload} size={18} />
            Add attachment
            <input type="file" hidden onChange={async (e) => {
              const f = e.currentTarget.files?.[0];
              if (!f) return;
              if (f.size > 100 * 1024 * 1024) return toast("Files up to 100 MB", { tone: "error" });
              try {
                toast("Uploading…");
                await uploadAttachment(orig, f);
                await rpc("vault.refetch", { ids: [orig.id] });
                const r = await openItem(orig.id);
                r && setOrig(r.view);
                toast("Attachment added", { tone: "ok" });
              } catch (err) {
                toast(`Upload failed: ${(err as Error).message}`, { tone: "error" });
              }
            }} />
          </label>
        </Section>
      )}
      <div style={{ height: "48px" }} />
    </div>
  );
}

function SshKeyEditor({ value, onChange }: { value: NonNullable<CipherView["sshKey"]>; onChange: (p: Partial<NonNullable<CipherView["sshKey"]>>) => void }) {
  const [busy, setBusy] = useState(false);
  return (
    <>
      <SecretField label="Private key" value={value.privateKey ?? ""} onInput={async (x) => {
        onChange({ privateKey: x || null });
        try {
          const { describeOpenSshPrivateKey } = await import("../../core/ssh/keys.ts");
          const d = await describeOpenSshPrivateKey(x);
          if (d) onChange({ privateKey: x, publicKey: d.publicKey, keyFingerprint: d.fingerprint });
        } catch {}
      }} mono multiline />
      <TextField label="Public key" value={value.publicKey ?? ""} onInput={(x) => onChange({ publicKey: x || null })} mono />
      <TextField label="Fingerprint" value={value.keyFingerprint ?? ""} onInput={(x) => onChange({ keyFingerprint: x || null })} mono />
      <Button variant="tonal" icon={I.dice} loading={busy} onClick={async () => {
        setBusy(true);
        try {
          const { generateEd25519 } = await import("../../core/ssh/keys.ts");
          const k = await generateEd25519("keyward");
          onChange({ privateKey: k.privateKey, publicKey: k.publicKey, keyFingerprint: k.fingerprint });
        } catch (e) {
          toast(`Key generation failed: ${(e as Error).message}`, { tone: "error" });
        } finally {
          setBusy(false);
        }
      }}>Generate Ed25519 key</Button>
    </>
  );
}

export const IDENTITY_LABELS: Record<string, string> = {
  title: "Title", firstName: "First name", middleName: "Middle name", lastName: "Last name", address1: "Address 1", address2: "Address 2",
  address3: "Address 3", city: "City / town", state: "State / province", postalCode: "Postal code", country: "Country", company: "Company",
  email: "Email", phone: "Phone", ssn: "National ID / SSN", username: "Username", passportNumber: "Passport number", licenseNumber: "License number",
};
