// Settings → Export vault / Import items.
import { useState } from "preact/hooks";
import { csvSkipped, exportable, exportAccountEncrypted, exportCsv, exportFileName, exportJson, exportPasswordProtected, type ExportFormat } from "../../core/export/export.ts";
import { detectFormat, FORMAT_LABEL, ImportError, parseImport, type ImportFormat, type ImportResult } from "../../core/export/import.ts";
import { utf8 } from "../../core/util/bytes.ts";
import { CipherType } from "../../core/vault/types.ts";
import { lazyArgon2 } from "../../platform/login.ts";
import { rpc } from "../../platform/messages.ts";
import { Banner, Button, Icon, Row, SecretField, Select, toast } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { account, aux, currentRing, folderNames, items, openItem, rawCiphers, rawFolders } from "../data/app.ts";
import { saveBytes } from "../data/attachments.ts";
import { verifyMasterPassword } from "../data/master-password.ts";
import { home } from "../data/nav.ts";
import { TYPE_META } from "./vault-list.tsx";

const FORMATS: [ExportFormat, string][] = [
  ["json", "JSON"],
  ["password_json", "JSON, protected by a password"],
  ["encrypted_json", "JSON, encrypted for this account"],
  ["csv", "CSV (logins and notes only)"],
];

const ABOUT: Record<ExportFormat, { tone: "warn" | "info"; text: string }> = {
  json: { tone: "warn", text: "Anyone who opens this file can read every password in it. Delete it once you've imported it." },
  csv: { tone: "warn", text: "Anyone who opens this file can read every password in it. Cards, identities and SSH keys don't fit the format and are left out." },
  password_json: { tone: "info", text: "Opens only with the password you set here. Bitwarden, Keyguard and Keyward can all import it." },
  encrypted_json: { tone: "info", text: "Only this account can import it, in Keyward, Bitwarden or Keyguard. A backup that can't be read anywhere else." },
};

export function ExportPage() {
  const [format, setFormat] = useState<ExportFormat>("json");
  const [filePw, setFilePw] = useState("");
  const [filePw2, setFilePw2] = useState("");
  const [master, setMaster] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const all = [...items.value.values()];
  const count = all.filter((s) => exportable({ organizationId: s.org, deletedDate: s.del }) && (format !== "csv" || s.type === CipherType.Login || s.type === CipherType.SecureNote)).length;
  const orgCount = all.filter((s) => s.org && !s.del).length;

  async function run() {
    setErr(null);
    if (format === "password_json") {
      if (!filePw) return setErr("Set a password for the file");
      if (filePw !== filePw2) return setErr("The two passwords don't match");
    }
    setBusy(true);
    try {
      if (!(await verifyMasterPassword(master))) return setErr("Wrong master password");
      const a = account.value!;
      let text: string;
      if (format === "encrypted_json") {
        text = await exportAccountEncrypted(await rawCiphers(), await rawFolders(), currentRing()!.user);
      } else {
        const views = (await Promise.all([...items.value.keys()].map((id) => openItem(id).catch(() => null)))).flatMap((r) => (r ? [r.view] : []));
        if (format === "csv") text = exportCsv(views, folderNames.value);
        else {
          text = exportJson(views, aux.value.folders);
          if (format === "password_json") text = await exportPasswordProtected(text, filePw, a.kdf, lazyArgon2);
        }
        if (format === "csv" && csvSkipped(views)) toast(`${csvSkipped(views)} items don't fit CSV and were left out`);
      }
      saveBytes(exportFileName(format), utf8(text), format === "csv" ? "text/csv" : "application/json");
      toast(`Exported ${count} ${count === 1 ? "item" : "items"}`, { tone: "ok" });
      setMaster("");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="col transfer" style={{ gap: "12px", margin: "0 16px" }}>
      <Select label="File format" value={format} onChange={(v) => setFormat(v as ExportFormat)} options={FORMATS} />
      <Banner tone={ABOUT[format].tone}>{ABOUT[format].text}</Banner>
      {format === "password_json" && (
        <>
          <SecretField label="File password" value={filePw} onInput={setFilePw} autocomplete="new-password" />
          <SecretField label="File password again" value={filePw2} onInput={setFilePw2} autocomplete="new-password" />
        </>
      )}
      <SecretField label="Master password" value={master} onInput={setMaster} autocomplete="current-password" hint="Confirm it's you before your vault leaves Keyward." onKeyDown={(e) => e.key === "Enter" && void run()} />
      {err && <Banner tone="error">{err}</Banner>}
      <Button variant="filled" icon={I.download} loading={busy} onClick={run} disabled={!master}>Export {count} {count === 1 ? "item" : "items"}</Button>
      <p class="t-body-s med">
        Your personal vault, without items in the trash or attachments{orgCount ? ` and without the ${orgCount} items that belong to organizations` : ""}.
      </p>
    </div>
  );
}

export function ImportPage() {
  const [file, setFile] = useState<{ name: string; text: string; format: ImportFormat } | null>(null);
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function open(f: { text: string; format: ImportFormat }, pw?: string) {
    setErr(null);
    setResult(null);
    setBusy(true);
    try {
      setResult(await parseImport(f.text, { userKey: currentRing()?.user, password: pw, argon2: lazyArgon2 }));
    } catch (e) {
      if (!(e instanceof ImportError && e.code === "password" && !pw)) setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function pick(f: File | null | undefined) {
    if (!f) return;
    setErr(null);
    setResult(null);
    setPassword("");
    if (f.size > 50 * 1024 * 1024) return setErr("That file is too big to be an export");
    const text = await f.text();
    const format = detectFormat(text);
    if (!format) {
      setFile(null);
      return setErr("Not a file Keyward can import. Use a Bitwarden JSON or CSV export, or a browser's password CSV.");
    }
    const next = { name: f.name, text, format };
    setFile(next);
    if (format !== "bitwarden_password_json") void open(next);
  }

  async function run() {
    if (!result) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await rpc("vault.import", { items: result.items, folders: result.folders, relations: result.relations });
      toast(`Imported ${r.imported} ${r.imported === 1 ? "item" : "items"}`, { tone: "ok" });
      setFile(null);
      setResult(null);
      home("vault");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const byType = result ? Object.entries(result.items.reduce<Record<number, number>>((m, v) => ((m[v.type] = (m[v.type] ?? 0) + 1), m), {})) : [];
  return (
    <div class="col transfer" style={{ gap: "12px", margin: "0 16px" }}>
      <p class="t-body-m med" style={{ margin: 0 }}>
        From a Bitwarden or Keyguard export (JSON or CSV, encrypted or not), or the password CSV that Chrome, Firefox or Safari exports. Items go into your personal vault.
      </p>
      <label class={`file-pick ${file ? "chosen" : ""}`}>
        <Icon d={file ? I.note : I.upload} />
        <span class="grow">{file ? file.name : "Choose a file"}{file && <span class="med"> · {FORMAT_LABEL[file.format]}</span>}</span>
        <input type="file" hidden aria-label="Import file" accept=".json,.csv,application/json,text/csv" onChange={(e) => { void pick(e.currentTarget.files?.[0]); e.currentTarget.value = ""; }} />
      </label>
      {file?.format === "bitwarden_password_json" && !result && (
        <>
          <SecretField label="File password" value={password} onInput={setPassword} autoFocus onKeyDown={(e) => e.key === "Enter" && password && void open(file, password)} />
          <Button variant="tonal" icon={I.lockOpen} loading={busy} disabled={!password} onClick={() => void open(file, password)}>Open file</Button>
        </>
      )}
      {err && <Banner tone="error">{err}</Banner>}
      {result && (
        <>
          <div class="group" style={{ margin: 0 }}>
            {byType.map(([t, n]) => (
              <Row key={t} leading={<Icon d={TYPE_META[Number(t)]?.icon ?? I.note} class="lead-icon" />} title={TYPE_META[Number(t)]?.plural ?? "Items"} trailing={<span class="t-title-s">{n}</span>} />
            ))}
            {result.folders.length > 0 && <Row leading={<Icon d={I.folder} class="lead-icon" />} title="Folders" sub={result.folders.join(", ")} trailing={<span class="t-title-s">{result.folders.length}</span>} />}
          </div>
          <Button variant="filled" icon={I.upload} loading={busy} onClick={run}>Import {result.items.length} {result.items.length === 1 ? "item" : "items"}</Button>
        </>
      )}
    </div>
  );
}
