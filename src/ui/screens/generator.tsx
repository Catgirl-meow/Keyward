import { useEffect, useState } from "preact/hooks";
import { decryptString, encryptString } from "../../core/crypto/encstring.ts";
import {
  DEFAULT_PASSPHRASE, DEFAULT_PASSWORD, generatePassphrase, generatePassword, generateUsername, passphraseEntropy, passwordEntropy,
  type PassphraseOpts, type PasswordOpts, type UsernameKind,
} from "../../core/generator/password.ts";
import { checkServerUrl, createAlias, FORWARDERS, type ForwarderConfig, type ForwarderId } from "../../core/generator/forwarders.ts";
import { local } from "../../platform/storage.ts";
import { loadGeneratorPrefs, type GeneratorPrefs } from "../../platform/generator.ts";
export { loadGeneratorPrefs, type GeneratorPrefs };
import { Badge, Button, Chip, ColoredPassword, Group, Icon, IconButton, Row, SecretField, Sheet, Switch, TextField, TopBar, toast } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { account, currentRing } from "../data/app.ts";
import { copyText } from "../data/clipboard.ts";

// Forwarder tokens and the generated history are secrets: stored encrypted with the user key.
async function loadSecret<T>(name: string, fallback: T): Promise<T> {
  const ring = currentRing();
  const a = account.value;
  if (!ring || !a) return fallback;
  const enc = await local.get<string>(`${name}:${a.id}`);
  if (!enc) return fallback;
  try {
    return JSON.parse(await decryptString(enc, ring.user));
  } catch {
    return fallback;
  }
}
async function saveSecret(name: string, v: unknown) {
  const ring = currentRing();
  const a = account.value;
  if (!ring || !a) return;
  await local.set(`${name}:${a.id}`, await encryptString(JSON.stringify(v), ring.user));
}

export async function addToHistory(value: string) {
  const h = await loadSecret<{ v: string; t: number }[]>("genHistory", []);
  if (h[0]?.v === value) return;
  await saveSecret("genHistory", [{ v: value, t: Date.now() }, ...h].slice(0, 50));
}

function Slider({ label, value, min, max, onChange }: { label: string; value: number; min: number; max: number; onChange: (v: number) => void }) {
  return (
    <div class="item" style={{ flexDirection: "column", alignItems: "stretch", gap: "4px" }}>
      <div class="row"><span class="grow t-body-l">{label}</span><span class="mono t-title-m">{value}</span></div>
      <input type="range" min={min} max={max} value={value} onInput={(e) => onChange(Number(e.currentTarget.value))} class="slider" aria-label={label} />
    </div>
  );
}

function Toggle({ label, checked, onChange, sub }: { label: string; checked: boolean; onChange: (v: boolean) => void; sub?: string }) {
  return <Row title={<span style={{ fontWeight: 400 }}>{label}</span>} sub={sub} trailing={<Switch checked={checked} onChange={onChange} label={label} />} onClick={() => onChange(!checked)} />;
}

/** A forwarder's API key, alias domain and (self-hosted) server URL; null removes them. */
function ForwarderSheet({ id, cfg, onSave, onClose }: { id: ForwarderId; cfg?: ForwarderConfig; onSave: (c: ForwarderConfig | null) => void; onClose: () => void }) {
  const f = FORWARDERS[id];
  const [token, setToken] = useState(cfg?.token ?? "");
  const [domain, setDomain] = useState(cfg?.domain ?? "");
  const [baseUrl, setBaseUrl] = useState(cfg?.baseUrl ?? "");
  const [err, setErr] = useState<string | null>(null);
  function save() {
    if (!token.trim()) return setErr("Enter the API key");
    if (f.needsDomain && !domain.trim()) return setErr("Enter the domain for new aliases");
    const url = baseUrl.trim() ? checkServerUrl(baseUrl) : undefined;
    if (url === null) return setErr("The server URL must start with https://");
    onSave({ token: token.trim(), domain: f.needsDomain ? domain.trim() : undefined, baseUrl: url });
  }
  return (
    <Sheet onClose={onClose}>
      <div class="section-label" style={{ paddingTop: 0 }}>{f.name}</div>
      <div class="col" style={{ gap: "10px", margin: "0 16px" }} onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLElement).tagName === "INPUT" && save()}>
        <SecretField label="API key" value={token} onInput={setToken} hint={f.help} autoFocus mono />
        {f.needsDomain && <TextField label="Alias domain" value={domain} onInput={setDomain} hint={id === "addy" ? "Your username subdomain or a domain you added to addy.io" : "A domain you added to Forward Email"} />}
        {f.selfHost && <TextField label="Server URL" value={baseUrl} onInput={setBaseUrl} type="url" placeholder={f.selfHost} hint="Only if you host it yourself" />}
        {err && <div class="field-hint error">{err}</div>}
        <div class="row" style={{ gap: "8px", justifyContent: "flex-end" }}>
          {cfg?.token && <Button variant="text" icon={I.del} onClick={() => onSave(null)}>Remove</Button>}
          <span class="grow" />
          <Button variant="text" onClick={onClose}>Cancel</Button>
          <Button onClick={save}>Save</Button>
        </div>
      </div>
    </Sheet>
  );
}

export function GeneratorScreen({ onUse, site }: { onUse?: (v: string) => void; site?: string }) {
  const [p, setP] = useState<GeneratorPrefs | null>(null);
  const [value, setValue] = useState("");
  const [fwd, setFwd] = useState<Record<string, ForwarderConfig>>({});
  const [history, setHistory] = useState<{ v: string; t: number }[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<ForwarderId | null>(null);

  useEffect(() => {
    loadGeneratorPrefs().then(setP);
    loadSecret<Record<string, ForwarderConfig>>("forwarders", {}).then(setFwd);
  }, []);

  async function regen(prefs = p!) {
    try {
      if (prefs.mode === "password") setValue(generatePassword(prefs.password));
      else if (prefs.mode === "passphrase") setValue(await generatePassphrase(prefs.passphrase));
      else if (prefs.username.kind === "forwarded") setValue("");
      // Nothing to build on yet: the field below says what's needed, no error for it.
      else if ((prefs.username.kind === "plus" && !prefs.username.email.includes("@")) || (prefs.username.kind === "catchall" && !prefs.username.domain.trim())) setValue("");
      else setValue(await generateUsername(prefs.username.kind, { ...prefs.username, site }));
    } catch (e) {
      setValue("");
      toast((e as Error).message, { tone: "error" });
    }
  }

  useEffect(() => {
    if (p) void regen(p);
  }, [p && JSON.stringify(p)]);

  if (!p) return null;
  const update = (patch: Partial<GeneratorPrefs>) => {
    const next = { ...p, ...patch };
    setP(next);
    void local.set("generator", next);
  };
  const bits = p.mode === "password" ? passwordEntropy(p.password) : p.mode === "passphrase" ? passphraseEntropy(p.passphrase) : null;

  async function copyAndRemember() {
    if (!value) return;
    await copyText(value, p!.mode === "username" ? "Username" : "Password", p!.mode !== "username");
    if (p!.mode !== "username") void addToHistory(value);
  }

  async function forward() {
    const id = p!.username.forwarder;
    const cfg = fwd[id];
    if (!cfg?.token) return toast(`Add your ${FORWARDERS[id].name} API key first`, { tone: "error" });
    setBusy(true);
    try {
      setValue(await createAlias(id, cfg, site ?? ""));
    } catch (e) {
      toast(`${FORWARDERS[id].name}: ${(e as Error).message}`, { tone: "error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="generator">
      {!onUse && <TopBar title="Generator" actions={<IconButton icon={I.history} label="History" onClick={async () => setHistory(await loadSecret("genHistory", []))} />} />}
      <div class="chips" style={{ padding: "4px 16px 12px" }}>
        {(["password", "passphrase", "username"] as const).map((m) => (
          <Chip key={m} selected={p.mode === m} onClick={() => update({ mode: m })}>{m[0].toUpperCase() + m.slice(1)}</Chip>
        ))}
      </div>

      <div class="gen-output" onClick={copyAndRemember} title="Click to copy">
        <div class="gen-value">{value ? (p.mode === "username" ? value : <ColoredPassword value={value} />) : <span class="med">—</span>}</div>
        <div class="row" style={{ gap: "8px", marginTop: "12px" }}>
          {bits != null && <Badge tone={bits < 50 ? "error" : bits < 70 ? "warn" : "ok"} icon={I.verified}>{bits} bits</Badge>}
          <span class="grow" />
          <IconButton icon={I.refresh} label="Regenerate" onClick={(e) => { e.stopPropagation(); void regen(); }} />
          <IconButton icon={I.copy} label="Copy" onClick={(e) => { e.stopPropagation(); void copyAndRemember(); }} />
        </div>
      </div>
      {onUse && <div style={{ margin: "0 16px 8px" }}><Button full icon={I.check} disabled={!value} onClick={() => { void addToHistory(value); onUse(value); }}>Use this {p.mode === "username" ? "username" : "password"}</Button></div>}

      {p.mode === "password" && (
        <Group>
          <Slider label="Length" value={p.password.length} min={5} max={128} onChange={(length) => update({ password: { ...p.password, length } })} />
          <Toggle label="A–Z" checked={p.password.upper} onChange={(upper) => update({ password: { ...p.password, upper } })} />
          <Toggle label="a–z" checked={p.password.lower} onChange={(lower) => update({ password: { ...p.password, lower } })} />
          <Toggle label="0–9" checked={p.password.digits} onChange={(digits) => update({ password: { ...p.password, digits } })} />
          <Toggle label="!@#$%^&*" checked={p.password.symbols} onChange={(symbols) => update({ password: { ...p.password, symbols } })} />
          <Toggle label="Avoid ambiguous characters" sub="No I, l, O, 0, 1" checked={p.password.avoidAmbiguous} onChange={(avoidAmbiguous) => update({ password: { ...p.password, avoidAmbiguous } })} />
          <Slider label="Minimum numbers" value={p.password.minDigits} min={0} max={9} onChange={(minDigits) => update({ password: { ...p.password, minDigits } })} />
          <Slider label="Minimum special" value={p.password.minSymbols} min={0} max={9} onChange={(minSymbols) => update({ password: { ...p.password, minSymbols } })} />
        </Group>
      )}
      {p.mode === "passphrase" && (
        <Group>
          <Slider label="Words" value={p.passphrase.words} min={3} max={20} onChange={(words) => update({ passphrase: { ...p.passphrase, words } })} />
          <div class="item"><TextField label="Separator" value={p.passphrase.separator} onInput={(separator) => update({ passphrase: { ...p.passphrase, separator } })} maxLength={3} /></div>
          <Toggle label="Capitalize" checked={p.passphrase.capitalize} onChange={(capitalize) => update({ passphrase: { ...p.passphrase, capitalize } })} />
          <Toggle label="Include number" checked={p.passphrase.includeNumber} onChange={(includeNumber) => update({ passphrase: { ...p.passphrase, includeNumber } })} />
        </Group>
      )}
      {p.mode === "username" && (
        <>
          <div class="chips" style={{ padding: "0 16px 8px", flexWrap: "wrap" }}>
            {([["word", "Random word"], ["plus", "Plus-addressed email"], ["catchall", "Catch-all email"], ["forwarded", "Forwarded alias"]] as const).map(([k, l]) => (
              <Chip key={k} selected={p.username.kind === k} onClick={() => update({ username: { ...p.username, kind: k } })}>{l}</Chip>
            ))}
          </div>
          <Group>
            {p.username.kind === "word" && (
              <>
                <Toggle label="Capitalize" checked={p.username.capitalize} onChange={(capitalize) => update({ username: { ...p.username, capitalize } })} />
                <Toggle label="Include number" checked={p.username.number} onChange={(number) => update({ username: { ...p.username, number } })} />
              </>
            )}
            {p.username.kind === "plus" && <div class="item"><div class="grow"><TextField label="Your email" value={p.username.email} type="email" onInput={(email) => update({ username: { ...p.username, email } })} /></div></div>}
            {p.username.kind === "catchall" && <div class="item"><div class="grow"><TextField label="Catch-all domain" value={p.username.domain} onInput={(domain) => update({ username: { ...p.username, domain } })} /></div></div>}
            {p.username.kind === "forwarded" && (
              <>
                {(Object.keys(FORWARDERS) as ForwarderId[]).map((id) => (
                  <Row key={id} title={FORWARDERS[id].name} sub={fwd[id]?.token ? `API key saved${fwd[id]?.baseUrl ? ` · ${new URL(fwd[id]!.baseUrl!).host}` : ""}` : FORWARDERS[id].help}
                    selected={p.username.forwarder === id}
                    onClick={() => update({ username: { ...p.username, forwarder: id } })}
                    trailing={<IconButton icon={I.key} label={`${FORWARDERS[id].name} settings`} onClick={(e) => { e.stopPropagation(); setEditing(id); }} />} />
                ))}
                <div class="item"><Button full loading={busy} icon={I.mail} onClick={forward}>Create alias with {FORWARDERS[p.username.forwarder].name}</Button></div>
              </>
            )}
          </Group>
        </>
      )}
      <div style={{ height: "24px" }} />

      {editing && (
        <ForwarderSheet
          id={editing}
          cfg={fwd[editing]}
          onClose={() => setEditing(null)}
          onSave={async (cfg) => {
            const next = { ...fwd };
            if (cfg) next[editing] = cfg;
            else delete next[editing];
            setFwd(next);
            await saveSecret("forwarders", next);
            setEditing(null);
          }}
        />
      )}
      {history && (
        <Sheet onClose={() => setHistory(null)}>
          <div class="section-label" style={{ paddingTop: 0 }}>Generated passwords</div>
          {history.length ? (
            <div class="group">
              {history.map((h) => (
                <Row key={h.t} title={<span class="mono" style={{ fontWeight: 400 }}>{h.v}</span>} sub={new Date(h.t).toLocaleString()}
                  trailing={<IconButton icon={I.copy} label="Copy" onClick={() => copyText(h.v, "Password")} />} />
              ))}
            </div>
          ) : <div class="t-body-m med" style={{ padding: "16px 32px" }}>Nothing yet.</div>}
          <div style={{ padding: "12px 16px 0" }}>
            {history.length > 0 && <Button variant="text" icon={I.del} onClick={async () => { await saveSecret("genHistory", []); setHistory([]); }}>Clear history</Button>}
          </div>
        </Sheet>
      )}
      <Icon d={I.dice} size={0} />
    </div>
  );
}
