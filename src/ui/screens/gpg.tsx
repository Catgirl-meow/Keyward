// GPG key items (view and editor sections) and the GPG tools: sign, verify, encrypt, decrypt
// with the vault's keys. OpenPGP.js loads on first use.
import { useEffect, useState } from "preact/hooks";
import type { GpgKeyFields } from "../../core/gpg/fields.ts";
import type { GpgKeyInfo, SignatureCheck, Verified } from "../../core/gpg/pgp.ts";
import { utf8 } from "../../core/util/bytes.ts";
import { Badge, Banner, Button, Chip, Group, Icon, IconButton, Row, SecretField, Select, Spinner, Switch, TextField, TopBar, toast } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { saveBytes } from "../data/attachments.ts";
import { copyText } from "../data/clipboard.ts";
import { ascName, pgp, vaultGpgKeys, type VaultGpgKey } from "../data/gpg.ts";
import { pop } from "../data/nav.ts";
import { guardFileDialog } from "../data/resume.ts";
import { recentlyVerified } from "../data/reprompt.ts";
import { RepromptSheet } from "./item-view.tsx";

const EMPTY: GpgKeyFields = { privateKey: null, publicKey: null, fingerprint: null };
const DAY = 86400e3;

const spaced = (fp: string | null | undefined) => (fp ? fp.replace(/\s/g, "").toUpperCase().replace(/(.{4})(?=.)/g, "$1 ") : "");
const fmtDay = (iso: string) => new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });
const USE_LABEL: Record<string, string> = { certify: "certify", sign: "sign", encrypt: "encrypt", auth: "authenticate" };

/** What the key says about itself, read with OpenPGP.js; null while reading. */
function useKeyInfo(armored: string | null | undefined): { info?: GpgKeyInfo; error?: string } | null {
  const [state, setState] = useState<{ info?: GpgKeyInfo; error?: string } | null>(null);
  useEffect(() => {
    setState(null);
    if (!armored) return setState({ error: "No key" });
    let alive = true;
    (async () => {
      const p = await pgp();
      return p.describeKey(await p.readGpgKey(armored));
    })().then(
      (info) => alive && setState({ info }),
      (e) => alive && setState({ error: (e as Error).message }),
    );
    return () => {
      alive = false;
    };
  }, [armored]);
  return state;
}

function StatusBadges({ info }: { info: Pick<GpgKeyInfo, "expires" | "revoked"> }) {
  if (info.revoked) return <Badge tone="error" icon={I.warning}>Revoked</Badge>;
  if (!info.expires) return <Badge tone="outline">Never expires</Badge>;
  const left = Date.parse(info.expires) - Date.now();
  if (left <= 0) return <Badge tone="error" icon={I.warning}>Expired {fmtDay(info.expires)}</Badge>;
  return <Badge tone={left < 30 * DAY ? "warn" : "outline"} icon={I.schedule}>Expires {fmtDay(info.expires)}</Badge>;
}

function KeyRows({ info }: { info: GpgKeyInfo }) {
  return (
    <>
      {info.userIds.map((u) => (
        <Row key={u} leading={<Icon d={I.person} />} title={u} sub="User ID" trailing={<IconButton icon={I.copy} label="Copy user ID" onClick={() => void copyText(u, "User ID", false)} />} />
      ))}
      <Row
        leading={<Icon d={I.fingerprint} />}
        title={<span class="mono" style={{ wordBreak: "break-all", whiteSpace: "normal" }}>{spaced(info.fingerprint)}</span>}
        sub="Fingerprint"
        trailing={<IconButton icon={I.copy} label="Copy fingerprint" onClick={() => void copyText(info.fingerprint, "Fingerprint", false)} />}
      />
      <Row
        leading={<Icon d={I.keyVertical} />}
        title={`${info.algorithm} · ${info.uses.map((u) => USE_LABEL[u]).join(", ") || "no usage flags"}`}
        sub={`Primary key · created ${fmtDay(info.created)}`}
        below={
          <div class="row" style={{ gap: "6px", flexWrap: "wrap" }}>
            <StatusBadges info={info} />
            {info.isPrivate ? <Badge tone="ok" icon={I.lock}>{info.locked ? "Private key, passphrase-protected" : "Private key"}</Badge> : <Badge tone="outline">Public key only</Badge>}
          </div>
        }
      />
      {info.subkeys.map((s) => (
        <Row
          key={s.fingerprint}
          leading={<Icon d={I.vpnKey} />}
          title={`${s.algorithm} · ${s.uses.map((u) => USE_LABEL[u]).join(", ") || "no usage flags"}`}
          sub={`Subkey ${s.keyId} · created ${fmtDay(s.created)}`}
          below={<StatusBadges info={s} />}
        />
      ))}
    </>
  );
}

// ------------------------------------------------------------------ item view
export function GpgKeyView({ name, gkey }: { name: string; gkey: GpgKeyFields }) {
  const st = useKeyInfo(gkey.privateKey || gkey.publicKey);
  const pub = st?.info?.publicKey ?? gkey.publicKey;
  return (
    <>
      <Group label="GPG key">
        {!st && <Row leading={<Spinner size={20} />} title="Reading key…" />}
        {st?.error && <Row leading={<Icon d={I.warning} />} title="This key could not be read" sub={st.error} />}
        {st?.info && <KeyRows info={st.info} />}
        {!st?.info && gkey.fingerprint && <Row leading={<Icon d={I.fingerprint} />} title={<span class="mono">{spaced(gkey.fingerprint)}</span>} sub="Fingerprint" />}
      </Group>
      <Group label="Key files">
        {pub && (
          <Row
            leading={<Icon d={I.key} />}
            title="Public key"
            sub="Share it so others can encrypt to you and check your signatures"
            trailing={
              <>
                <IconButton icon={I.copy} label="Copy public key" onClick={() => void copyText(pub, "Public key", false)} />
                <IconButton icon={I.download} label="Save public key" onClick={() => saveBytes(ascName(name, false), utf8(pub), "application/pgp-keys")} />
              </>
            }
          />
        )}
        {gkey.privateKey && (
          <Row
            leading={<Icon d={I.lock} />}
            title="Private key"
            sub="Keep it secret"
            trailing={
              <>
                <IconButton icon={I.copy} label="Copy private key" onClick={() => void copyText(gkey.privateKey!, "Private key", true)} />
                <IconButton icon={I.download} label="Save private key" onClick={() => saveBytes(ascName(name, true), utf8(gkey.privateKey!), "application/pgp-keys")} />
              </>
            }
          />
        )}
      </Group>
    </>
  );
}

// ------------------------------------------------------------------ item editor
export function GpgKeyEditor({ value, onChange, suggestName }: { value: GpgKeyFields; onChange: (k: GpgKeyFields) => void; suggestName: (n: string) => void }) {
  const [mode, setMode] = useState<"generate" | "import">("generate");
  const has = !!(value.privateKey || value.publicKey);
  const st = useKeyInfo(has ? value.privateKey || value.publicKey : null);
  if (has)
    return (
      <>
        <div class="group" style={{ margin: 0 }}>
          {!st && <Row leading={<Spinner size={20} />} title="Reading key…" />}
          {st?.error && <Row leading={<Icon d={I.warning} />} title="This key could not be read" sub={st.error} />}
          {st?.info && <KeyRows info={st.info} />}
        </div>
        <Button variant="tonal" icon={I.del} onClick={() => onChange(EMPTY)} style={{ alignSelf: "flex-start" }}>Remove key</Button>
      </>
    );
  return (
    <>
      <div class="chips" style={{ padding: 0 }}>
        <Chip selected={mode === "generate"} icon={I.dice} onClick={() => setMode("generate")}>Generate</Chip>
        <Chip selected={mode === "import"} icon={I.upload} onClick={() => setMode("import")}>Import</Chip>
      </div>
      {mode === "generate" ? <GenerateKey onKey={(k, uid) => { onChange(k); suggestName(uid); }} /> : <ImportKey onKey={(k, uid) => { onChange(k); suggestName(uid); }} />}
    </>
  );
}

function GenerateKey({ onKey }: { onKey: (k: GpgKeyFields, uid: string) => void }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [days, setDays] = useState("1825");
  const [type, setType] = useState<"ecc" | "rsa">("ecc");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function go() {
    setBusy(true);
    setErr(null);
    try {
      const k = await (await pgp()).generateGpgKey({ name, email, expiresInDays: Number(days) || null, type });
      onKey(k, [name.trim(), email.trim() && `<${email.trim()}>`].filter(Boolean).join(" "));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <TextField label="Your name" value={name} onInput={setName} autocomplete="off" />
      <TextField label="Email" value={email} onInput={setEmail} type="email" autocomplete="off" error={err} />
      <Select label="Expires" value={days} onChange={setDays} options={[["365", "In 1 year"], ["730", "In 2 years"], ["1825", "In 5 years"], ["0", "Never"]]} />
      <Select label="Algorithm" value={type} onChange={(t) => setType(t as "ecc" | "rsa")} options={[["ecc", "Ed25519 + Cv25519"], ["rsa", "RSA 4096"]]} />
      <Button variant="tonal" icon={I.dice} loading={busy} onClick={go} style={{ alignSelf: "flex-start" }}>Generate key</Button>
    </>
  );
}

function ImportKey({ onKey }: { onKey: (k: GpgKeyFields, uid: string) => void }) {
  const [text, setText] = useState("");
  const [err, setErr] = useState<string | null>(null);
  async function take(data: string | Uint8Array) {
    setErr(null);
    try {
      const p = await pgp();
      const key = await p.readGpgKeyData(data);
      onKey(p.keyFields(key), key.getUserIDs()[0] ?? "");
    } catch (e) {
      setErr((e as Error).message);
    }
  }
  return (
    <>
      <TextField label="Armored key" value={text} onInput={setText} multiline rows={6} mono placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----" error={err} hint="A private key, or a public key to encrypt to and check signatures with" />
      <div class="row" style={{ gap: "8px", flexWrap: "wrap" }}>
        <Button variant="tonal" icon={I.check} disabled={!text.trim()} onClick={() => void take(text)}>Import key</Button>
        <label class="btn text has-icon">
          <Icon d={I.upload} size={18} />
          Choose file
          <input type="file" accept=".asc,.gpg,.pgp,.key,.txt,application/pgp-keys" hidden onClick={guardFileDialog} onChange={async (e) => {
            const f = e.currentTarget.files?.[0];
            if (f) await take(new Uint8Array(await f.arrayBuffer()));
          }} />
        </label>
      </div>
    </>
  );
}

// ------------------------------------------------------------------ GPG tools
type Mode = "sign" | "verify" | "encrypt" | "decrypt";
const MODES: [Mode, string, string][] = [
  ["sign", "Sign", I.signature],
  ["verify", "Verify", I.verified],
  ["encrypt", "Encrypt", I.enhancedEncryption],
  ["decrypt", "Decrypt", I.lockOpen],
];

interface ToolKey extends VaultGpgKey {
  info: GpgKeyInfo | null;
  label: string;
}

export function GpgTools({ keyId, root }: { keyId?: string; root?: boolean }) {
  const [mode, setMode] = useState<Mode>("sign");
  const [keys, setKeys] = useState<ToolKey[] | null>(null);
  useEffect(() => {
    let alive = true;
    (async () => {
      const p = await pgp();
      const all = await vaultGpgKeys();
      const out = await Promise.all(
        all.map(async (k): Promise<ToolKey> => {
          const info = await p.describeKey(await p.readGpgKey((k.key.privateKey || k.key.publicKey)!)).catch(() => null);
          return { ...k, info, label: info?.userIds[0] ? `${k.name} · ${info.userIds[0]}` : k.name };
        }),
      );
      if (alive) setKeys(out.filter((k) => k.info));
    })().catch((e) => toast((e as Error).message, { tone: "error" }));
    return () => {
      alive = false;
    };
  }, []);

  return (
    <div class="gpg-tools">
      <TopBar title="GPG tools" back={root ? undefined : pop} />
      <div class="chips" style={{ padding: "4px 16px 12px" }}>
        {MODES.map(([m, label, icon]) => (
          <Chip key={m} selected={mode === m} icon={icon} onClick={() => setMode(m)}>{label}</Chip>
        ))}
      </div>
      {!keys ? (
        <div style={{ padding: "48px", display: "grid", placeItems: "center" }}><Spinner /></div>
      ) : (
        <div class="col" style={{ gap: "10px", margin: "0 16px" }}>
          {mode === "sign" && <SignTool keys={keys} keyId={keyId} />}
          {mode === "verify" && <VerifyTool keys={keys} />}
          {mode === "encrypt" && <EncryptTool keys={keys} keyId={keyId} />}
          {mode === "decrypt" && <DecryptTool keys={keys} />}
        </div>
      )}
      <div style={{ height: "48px" }} />
    </div>
  );
}

/**
 * Private keys ready to use: asks for the master password (re-prompt items) and for a key's own
 * passphrase when it has one, then the caller runs the action again.
 */
function useUnlock() {
  const [reprompt, setReprompt] = useState<((ok: boolean) => void) | null>(null);
  const [ask, setAsk] = useState<{ fingerprint: string; wrong: boolean } | null>(null);
  const [pass, setPass] = useState("");
  const [passes] = useState(() => new Map<string, string>());
  async function unlock(k: ToolKey) {
    if (!k.key.privateKey) throw new Error(`${k.name} has no private key`);
    if (k.reprompt && !recentlyVerified()) {
      const ok = await new Promise<boolean>((resolve) => setReprompt(() => resolve));
      setReprompt(null);
      if (!ok) throw new Error("Not confirmed");
    }
    const p = await pgp();
    const fp = k.info?.fingerprint ?? "";
    try {
      const key = await p.unlockKey(k.key.privateKey, passes.get(fp));
      setAsk(null);
      return key;
    } catch (e) {
      if (e instanceof p.PassphraseNeeded) {
        if (ask?.fingerprint !== e.fingerprint) setPass("");
        setAsk({ fingerprint: e.fingerprint, wrong: e.wrong });
      }
      throw e;
    }
  }
  const ui = (
    <>
      {ask && (
        <SecretField
          label="Key passphrase"
          value={pass}
          onInput={(x) => {
            setPass(x);
            passes.set(ask.fingerprint, x);
          }}
          error={ask.wrong ? "Wrong passphrase" : null}
          hint="This private key has its own passphrase"
          autoFocus
        />
      )}
      {reprompt && <RepromptSheet onDone={() => reprompt(true)} onCancel={() => reprompt(false)} />}
    </>
  );
  return { unlock, ui };
}

function useAction() {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setErr(null);
    try {
      await fn();
    } catch (e) {
      const m = (e as Error).message;
      if (!/passphrase|Not confirmed/i.test(m)) setErr(m);
    } finally {
      setBusy(false);
    }
  }
  return { busy, err, run };
}

function Output({ value, label, file }: { value: string; label: string; file?: string }) {
  if (!value) return null;
  return (
    <>
      <TextField label={label} value={value} readOnly multiline rows={8} mono />
      <div class="row" style={{ gap: "8px" }}>
        <Button variant="tonal" icon={I.copy} onClick={() => void copyText(value, label, false)}>Copy</Button>
        {file && <Button variant="text" icon={I.download} onClick={() => saveBytes(file, utf8(value), "application/pgp-signature")}>Save</Button>}
      </div>
    </>
  );
}

function SignatureResults({ signatures }: { signatures: SignatureCheck[] }) {
  if (!signatures.length) return <Banner tone="info" icon={I.info}>Not signed</Banner>;
  return (
    <>
      {signatures.map((s, i) =>
        s.valid ? (
          <Banner key={i} tone="info" icon={I.verified}>
            Good signature from {s.signer?.userId || "an unnamed key"} · {spaced(s.signer?.fingerprint)}
            {s.created ? ` · signed ${new Date(s.created).toLocaleString()}` : ""}
          </Banner>
        ) : (
          <Banner key={i} tone="error" icon={I.warning}>
            {s.signer ? `Bad signature from ${s.signer.userId || s.keyId}: ${s.error ?? "it doesn't match"}` : `Signed by key ${s.keyId}, which isn't in your vault`}
          </Banner>
        ),
      )}
    </>
  );
}

const keyOptions = (keys: ToolKey[]) => keys.map((k) => [k.id, k.label] as [string, string]);
const pubKeys = async (keys: ToolKey[]) => {
  const p = await pgp();
  return Promise.all(keys.map((k) => p.readGpgKey((k.key.publicKey || k.key.privateKey)!)));
};
const NoKeys = ({ what }: { what: string }) => <Banner tone="info" icon={I.keyVertical}>{what} Add one with New item → GPG key.</Banner>;

function SignTool({ keys, keyId }: { keys: ToolKey[]; keyId?: string }) {
  const signers = keys.filter((k) => k.key.privateKey);
  const [id, setId] = useState(signers.find((k) => k.id === keyId)?.id ?? signers[0]?.id ?? "");
  const [kind, setKind] = useState("clear");
  const [text, setText] = useState("");
  const [out, setOut] = useState("");
  const { unlock, ui } = useUnlock();
  const { busy, err, run } = useAction();
  if (!signers.length) return <NoKeys what="Signing needs a GPG key with its private key." />;
  return (
    <>
      <Select label="Sign with" value={id} onChange={setId} options={keyOptions(signers)} />
      <Select label="Signature" value={kind} onChange={setKind} options={[["clear", "Text with the signature in it"], ["detached", "Detached signature"]]} />
      <TextField label="Text to sign" value={text} onInput={(x) => { setText(x); setOut(""); }} multiline rows={6} error={err} />
      {ui}
      <Button icon={I.signature} loading={busy} disabled={!text} onClick={() => run(async () => {
        const key = await unlock(signers.find((k) => k.id === id)!);
        setOut(await (await pgp()).signText(text, key, kind === "detached"));
      })} style={{ alignSelf: "flex-start" }}>Sign</Button>
      <Output value={out} label={kind === "detached" ? "Signature" : "Signed text"} file={kind === "detached" ? "signature.asc" : "signed.asc"} />
    </>
  );
}

function VerifyTool({ keys }: { keys: ToolKey[] }) {
  const [signed, setSigned] = useState("");
  const [text, setText] = useState("");
  const [res, setRes] = useState<Verified | null>(null);
  const { busy, err, run } = useAction();
  const detached = /^\s*-----BEGIN PGP SIGNATURE-----/.test(signed);
  return (
    <>
      <TextField label="Signed text or signature" value={signed} onInput={(x) => { setSigned(x); setRes(null); }} multiline rows={6} mono placeholder="-----BEGIN PGP SIGNED MESSAGE-----" error={err} />
      {detached && <TextField label="The text that was signed" value={text} onInput={(x) => { setText(x); setRes(null); }} multiline rows={4} />}
      <Button icon={I.verified} loading={busy} disabled={!signed.trim()} onClick={() => run(async () => {
        setRes(await (await pgp()).verifyText(signed, await pubKeys(keys), detached ? text : undefined));
      })} style={{ alignSelf: "flex-start" }}>Verify</Button>
      {res && <SignatureResults signatures={res.signatures} />}
      {res && !detached && <Output value={res.text} label="Text" />}
    </>
  );
}

function EncryptTool({ keys, keyId }: { keys: ToolKey[]; keyId?: string }) {
  const [to, setTo] = useState<string[]>(keyId ? [keyId] : []);
  const [other, setOther] = useState("");
  const [signer, setSigner] = useState("");
  const [text, setText] = useState("");
  const [out, setOut] = useState("");
  const { unlock, ui } = useUnlock();
  const { busy, err, run } = useAction();
  const signers = keys.filter((k) => k.key.privateKey);
  const encryptable = keys.filter((k) => k.info?.subkeys.some((s) => s.uses.includes("encrypt")) || k.info?.uses.includes("encrypt"));
  return (
    <>
      <div class="section-label" style={{ padding: "4px 0 0" }}>Recipients</div>
      {encryptable.length ? (
        <div class="group" style={{ margin: 0 }}>
          {encryptable.map((k) => {
            const on = to.includes(k.id);
            const flip = () => { setTo(on ? to.filter((x) => x !== k.id) : [...to, k.id]); setOut(""); };
            return <Row key={k.id} leading={<Icon d={I.keyVertical} />} title={k.name} sub={k.info?.userIds[0]} onClick={flip} trailing={<Switch checked={on} label={k.name} onChange={flip} />} />;
          })}
        </div>
      ) : (
        <NoKeys what="No GPG keys in your vault yet." />
      )}
      <TextField label="Another recipient's public key" value={other} onInput={(x) => { setOther(x); setOut(""); }} multiline rows={3} mono placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----" hint="Optional" />
      <Select label="Sign with" value={signer} onChange={setSigner} options={[["", "Don't sign"], ...keyOptions(signers)]} />
      <TextField label="Text to encrypt" value={text} onInput={(x) => { setText(x); setOut(""); }} multiline rows={6} error={err} />
      {ui}
      <Button icon={I.enhancedEncryption} loading={busy} disabled={!text || (!to.length && !other.trim())} onClick={() => run(async () => {
        const p = await pgp();
        const recipients = await pubKeys(keys.filter((k) => to.includes(k.id)));
        if (other.trim()) recipients.push(await p.readGpgKey(other));
        const sign = signer ? await unlock(signers.find((k) => k.id === signer)!) : undefined;
        setOut(await p.encryptText(text, recipients, sign));
      })} style={{ alignSelf: "flex-start" }}>Encrypt</Button>
      <Output value={out} label="Encrypted message" file="message.asc" />
    </>
  );
}

function DecryptTool({ keys }: { keys: ToolKey[] }) {
  const [msg, setMsg] = useState("");
  const [res, setRes] = useState<Verified | null>(null);
  const { unlock, ui } = useUnlock();
  const { busy, err, run } = useAction();
  const own = keys.filter((k) => k.key.privateKey);
  if (!own.length) return <NoKeys what="Decrypting needs a GPG key with its private key." />;
  return (
    <>
      <TextField label="Encrypted message" value={msg} onInput={(x) => { setMsg(x); setRes(null); }} multiline rows={6} mono placeholder="-----BEGIN PGP MESSAGE-----" error={err} />
      {ui}
      <Button icon={I.lockOpen} loading={busy} disabled={!msg.trim()} onClick={() => run(async () => {
        const p = await pgp();
        const ids = await p.recipientsOf(msg);
        // Only the keys it was encrypted to (all of them for a hidden recipient), so a re-prompt
        // or passphrase is asked for only where it matters.
        const subkeyIds = (k: ToolKey) => [k.info!.keyId, ...k.info!.subkeys.map((s) => s.keyId)];
        const mine = own.filter((k) => ids.some((id) => p.isWildcardId(id) || subkeyIds(k).includes(id)));
        if (!mine.length) throw new Error("None of your GPG keys can open this message");
        const unlocked = [];
        for (const k of mine) unlocked.push(await unlock(k));
        setRes(await p.decryptText(msg, unlocked, await pubKeys(keys)));
      })} style={{ alignSelf: "flex-start" }}>Decrypt</Button>
      {res && <SignatureResults signatures={res.signatures} />}
      {res && <Output value={res.text} label="Decrypted text" />}
    </>
  );
}
