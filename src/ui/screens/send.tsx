// Send: share text or a file through a link that carries its own key.
import { useEffect, useState } from "preact/hooks";
import { SendType, sendStatus, type SendDraft, type SendView } from "../../core/send/send.ts";
import { rpc } from "../../platform/messages.ts";
import { Avatar, Badge, Banner, Button, EmptyState, Group, Icon, IconButton, Row, SecretField, Select, Skeleton, Switch, TextField, TopBar, confirm, openMenu, toast } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { copyText } from "../data/clipboard.ts";
import { pop, push, stack, top } from "../data/nav.ts";
import { draftKey, guardFileDialog, saveDraft, takeDraft } from "../data/resume.ts";
import { createFileSend, linkOf, sends, sendsError } from "../data/sends.ts";

const TYPE = {
  [SendType.Text]: { label: "Text", icon: I.textFields },
  [SendType.File]: { label: "File", icon: I.attach },
};

/** Files up to this size (Vaultwarden's default limit is far higher; this keeps uploads sane). */
const MAX_FILE = 100 * 1024 * 1024;

export function newSendMenu(anchor: HTMLElement) {
  openMenu(anchor, [
    { header: true, label: "New Send" },
    { icon: TYPE[SendType.Text].icon, label: "Text", run: () => push({ name: "send-edit", type: SendType.Text }) },
    { icon: TYPE[SendType.File].icon, label: "File", run: () => push({ name: "send-edit", type: SendType.File }) },
  ]);
}

const copyLink = (s: SendView) => copyText(linkOf(s), "Link", false);

async function removePassword(s: SendView) {
  if (!(await confirm("Remove the password?", "Anyone with the link can then open this Send.", "Remove"))) return;
  try {
    await rpc("send.removePassword", { id: s.id });
    toast("Password removed", { tone: "ok" });
  } catch (e) {
    toast((e as Error).message, { tone: "error" });
  }
}

async function deleteSend(s: SendView): Promise<boolean> {
  if (!(await confirm(`Delete “${s.name}”?`, "The link stops working for everyone.", "Delete", true))) return false;
  try {
    await rpc("send.delete", { id: s.id });
    toast("Send deleted");
    return true;
  } catch (e) {
    toast((e as Error).message, { tone: "error" });
    return false;
  }
}

function sendMenu(anchor: HTMLElement | MouseEvent, s: SendView, onDeleted?: () => void) {
  openMenu(anchor, [
    { icon: I.link, label: "Copy link", run: () => void copyLink(s) },
    { icon: I.edit, label: "Edit", run: () => push({ name: "send-edit", id: s.id }) },
    ...(s.hasPassword ? [{ icon: I.lockOpen, label: "Remove password", run: () => void removePassword(s) }] : []),
    { icon: I.del, label: "Delete", danger: true, run: () => void deleteSend(s).then((done) => done && onDeleted?.()) },
  ]);
}

function SendRow({ s }: { s: SendView }) {
  const st = sendStatus(s);
  return (
    <Row
      class={`send-row ${st.open ? "" : "closed"}`}
      leading={<Avatar seed={s.id} name={s.name} icon={TYPE[s.type].icon} badges={s.hasPassword ? [I.lockFill] : undefined} />}
      title={s.name}
      sub={s.type === SendType.File ? `${s.file?.fileName ?? "File"}${s.file?.sizeName ? ` · ${s.file.sizeName}` : ""}` : s.text?.hidden ? "Hidden text" : s.text?.text.split("\n")[0]}
      below={
        <>
          <Badge tone={st.open ? "outline" : "warn"} icon={st.open ? I.schedule : s.disabled ? I.block : I.timer}>{st.label}</Badge>
          {s.maxAccessCount != null || s.accessCount > 0 ? <Badge tone="outline" icon={I.eye}>{s.maxAccessCount != null ? `${s.accessCount} / ${s.maxAccessCount}` : s.accessCount}</Badge> : null}
        </>
      }
      trailing={<IconButton icon={I.link} label="Copy link" onClick={(e) => { e.stopPropagation(); void copyLink(s); }} />}
      onClick={() => push({ name: "send-edit", id: s.id })}
      onContextMenu={(e) => { e.preventDefault(); sendMenu(e, s); }}
    />
  );
}

export function SendList() {
  const list = sends.value;
  return (
    <div class="send-list">
      <TopBar title="Send" />
      {sendsError.value && <div class="pad"><Banner tone="error">Couldn't read Sends: {sendsError.value}</Banner></div>}
      {!list ? <Skeleton rows={3} /> : list.length ? (
        <Group>{list.map((s) => <SendRow key={s.id} s={s} />)}</Group>
      ) : (
        <EmptyState text="Share text or a file through a link. Only people with the link can open it, and the server never sees what's inside." />
      )}
      <div style={{ height: "88px" }} />
    </div>
  );
}

// ---------------------------------------------------------------- editor
// Values are hours from now (the server allows deletion up to 31 days out).
const DELETION: [string, string][] = [["1", "In 1 hour"], ["24", "In 1 day"], ["48", "In 2 days"], ["72", "In 3 days"], ["168", "In 7 days"], ["336", "In 14 days"], ["720", "In 30 days"]];
const inHours = (h: number) => new Date(Date.now() + h * 3_600_000).toISOString();
const EXPIRATION: [string, string][] = [["", "Never"], ...DELETION];

function dateLabel(iso: string): string {
  return new Date(iso).toLocaleString([], { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}

function Section({ label, children }: { label?: string; children: any }) {
  return (
    <>
      {label && <div class="section-label">{label}</div>}
      <div class="col" style={{ gap: "10px", margin: "0 16px" }}>{children}</div>
    </>
  );
}

function Toggle({ title, sub, checked, onChange }: { title: string; sub?: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div class="group" style={{ margin: 0 }}>
      <Row title={<span class="row-title">{title}</span>} sub={sub} trailing={<Switch checked={checked} onChange={onChange} label={title} />} onClick={() => onChange(!checked)} />
    </div>
  );
}

/** What the Send editor keeps while the popup is closed (data/resume.ts). A chosen file isn't. */
interface SendEditDraft {
  d: SendDraft;
  deletion: string;
  expiration: string;
  password: string;
  start: string;
}

export function SendEdit({ id, type }: { id?: string; type?: number }) {
  const orig = id ? sends.value?.find((s) => s.id === id) ?? null : null;
  if (id && !orig) {
    return (
      <div class="send-edit">
        <TopBar back={pop} small title="Edit Send" />
        {sends.value ? <EmptyState text="This Send no longer exists" /> : <Skeleton rows={3} />}
      </div>
    );
  }
  // Mounted only once the Send is known, so an existing Send never starts out as a new one.
  return <SendEditor orig={orig} type={type} />;
}

function SendEditor({ orig, type }: { orig: SendView | null; type?: number }) {
  const [key] = useState(() => draftKey(top()));
  const [kept] = useState(() => takeDraft<SendEditDraft>(key));
  const [d, setD] = useState<SendDraft>(() =>
    kept?.d ??
    (orig
      ? { id: orig.id, type: orig.type, name: orig.name, notes: orig.notes, text: orig.text, maxAccessCount: orig.maxAccessCount, expirationDate: orig.expirationDate, deletionDate: orig.deletionDate, disabled: orig.disabled, hideEmail: orig.hideEmail }
      : { type: type === SendType.File ? SendType.File : SendType.Text, name: "", notes: null, text: { text: "", hidden: false }, maxAccessCount: null, expirationDate: null, deletionDate: inHours(168), disabled: false, hideEmail: false }),
  );
  // The editor's choices: hours from now, or "keep" for the date an existing Send has.
  const [deletion, setDeletion] = useState(kept?.deletion ?? (orig ? "keep" : "168"));
  const [expiration, setExpiration] = useState(kept?.expiration ?? (orig ? (orig.expirationDate ? "keep" : "") : ""));
  const [password, setPassword] = useState(kept?.password ?? "");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const set = (p: Partial<SendDraft>) => setD((x) => ({ ...x, ...p }));
  // Kept from the first change on, until the route is left (saved or discarded).
  const [start] = useState(() => kept?.start ?? JSON.stringify([d, deletion, expiration, password]));
  const now = JSON.stringify([d, deletion, expiration, password]);
  useEffect(() => {
    if (now !== start) saveDraft(key, { d, deletion, expiration, password, start } satisfies SendEditDraft);
  }, [now]);

  async function save() {
    setErr(null);
    if (!d.name.trim()) return setErr("Give the Send a name");
    if (d.type === SendType.Text && !d.text?.text) return setErr("Write the text to share");
    if (d.type === SendType.File && !orig && !file) return setErr("Choose a file");
    const draft: SendDraft = {
      ...d,
      name: d.name.trim(),
      deletionDate: deletion === "keep" ? d.deletionDate : inHours(Number(deletion)),
      expirationDate: expiration === "keep" ? d.expirationDate : expiration ? inHours(Number(expiration)) : null,
    };
    setBusy(true);
    try {
      let sid: string;
      if (draft.type === SendType.File && !orig) sid = (await createFileSend(draft, password || null, file!)).id;
      else sid = (await rpc("send.save", { draft, password: password || null })).id;
      // The link is what the user came for: copy it right away for a new Send.
      if (!orig) {
        const made = sends.value?.find((s) => s.id === sid);
        if (made) await copyText(linkOf(made), "Send created · link", false);
        else toast("Send created", { tone: "ok" });
      } else toast("Saved", { tone: "ok" });
      if (stack.value[stack.value.length - 1]?.name === "send-edit") pop();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const deletionOptions: [string, string][] = orig ? [["keep", dateLabel(orig.deletionDate)], ...DELETION] : DELETION;
  const expirationOptions: [string, string][] = orig?.expirationDate ? [["keep", dateLabel(orig.expirationDate)], ...EXPIRATION] : EXPIRATION;
  return (
    <div class="send-edit" onKeyDown={(e) => { if ((e.ctrlKey || e.metaKey) && e.key === "s") { e.preventDefault(); void save(); } }}>
      <TopBar
        back={pop}
        small
        title={orig ? "Edit Send" : `New ${TYPE[d.type].label.toLowerCase()} Send`}
        actions={
          <>
            {orig && <IconButton icon={I.more} label="More" onClick={(e) => sendMenu(e.currentTarget as HTMLElement, orig, pop)} />}
            <Button variant="filled" loading={busy} onClick={save} icon={I.check} style={{ marginRight: "8px" }}>Save</Button>
          </>
        }
      />
      {err && <div class="pad"><Banner tone="error">{err}</Banner></div>}
      {orig && (
        <div class="send-link" role="button" tabIndex={0} title="Copy link" onClick={() => void copyLink(orig)} onKeyDown={(e) => e.key === "Enter" && void copyLink(orig)}>
          <Icon d={I.link} />
          <span class="grow mono">{linkOf(orig)}</span>
          <Icon d={I.copy} />
        </div>
      )}

      <Section>
        <TextField label="Name" value={d.name} onInput={(x) => set({ name: x })} autoFocus={!orig} />
        {d.type === SendType.Text ? (
          <>
            <TextField label="Text" value={d.text?.text ?? ""} onInput={(x) => set({ text: { hidden: !!d.text?.hidden, text: x } })} multiline />
            <Toggle title="Hide the text until it's revealed" checked={!!d.text?.hidden} onChange={(v) => set({ text: { text: d.text?.text ?? "", hidden: v } })} />
          </>
        ) : orig ? (
          <div class="group" style={{ margin: 0 }}>
            <Row leading={<Icon d={I.attach} class="lead-icon" />} title={orig.file?.fileName ?? "File"} sub={orig.file?.sizeName} />
          </div>
        ) : (
          <label class={`file-pick ${file ? "chosen" : ""}`}>
            <Icon d={file ? I.attach : I.upload} />
            <span class="grow">{file ? file.name : "Choose a file"}<span class="med">{file ? ` · ${(file.size / 1024).toFixed(file.size < 10240 ? 1 : 0)} KB` : " · up to 100 MB"}</span></span>
            <input type="file" hidden aria-label="File" onClick={guardFileDialog} onChange={(e) => {
              const f = e.currentTarget.files?.[0] ?? null;
              if (f && f.size > MAX_FILE) return toast("Files up to 100 MB", { tone: "error" });
              setFile(f);
              if (f && !d.name) set({ name: f.name });
            }} />
          </label>
        )}
      </Section>

      <Section label="Lifetime">
        <Select label="Deletion" value={deletion} onChange={setDeletion} options={deletionOptions} />
        <Select label="Expiration" value={expiration} onChange={setExpiration} options={expirationOptions} />
        <TextField
          label="Maximum views"
          value={d.maxAccessCount == null ? "" : String(d.maxAccessCount)}
          onInput={(x) => set({ maxAccessCount: /^\d+$/.test(x) ? Number(x) : null })}
          inputMode="numeric"
          hint={orig ? `Opened ${orig.accessCount} ${orig.accessCount === 1 ? "time" : "times"} so far. Empty: no limit.` : "Empty: no limit."}
        />
      </Section>

      <Section label="Protection">
        <SecretField
          label={orig?.hasPassword ? "New password" : "Password"}
          value={password}
          onInput={setPassword}
          autocomplete="new-password"
          hint={orig?.hasPassword ? "Leave empty to keep the current password." : "Recipients need it to open the Send."}
        />
        {orig?.hasPassword && <Button variant="tonal" icon={I.lockOpen} onClick={() => void removePassword(orig)}>Remove password</Button>}
        <Toggle title="Hide my email address" sub="Recipients won't see who sent it" checked={d.hideEmail} onChange={(v) => set({ hideEmail: v })} />
        <Toggle title="Disable this Send" sub="Nobody can open it until you turn this off" checked={d.disabled} onChange={(v) => set({ disabled: v })} />
      </Section>

      <Section label="Notes">
        <TextField label="Private notes" value={d.notes ?? ""} onInput={(x) => set({ notes: x || null })} multiline hint="Only you see these." />
      </Section>
      <div style={{ height: "48px" }} />
    </div>
  );
}
