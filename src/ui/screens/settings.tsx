import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import { clearPin, hasPinConfigured, setPin } from "../../platform/pin.ts";
import { lazyArgon2 } from "../../platform/login.ts";
import { rpc } from "../../platform/messages.ts";
import { LockTimeout, type Settings } from "../../platform/settings.ts";
import { Avatar, Banner, Button, Group, Icon, IconButton, Row, SecretField, Select, Sheet, Switch, TextField, TopBar, confirm, openMenu, toast } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { account, accounts, addingAccount, aux, currentRing, lockNow, refreshPhase, settings, switchAccount, syncNow, syncStatus, updateSettings } from "../data/app.ts";
import { home, pop, push } from "../data/nav.ts";
import { accents } from "../theme/theme.ts";
import { useSignal } from "@preact/signals";
import { ago } from "./account-menu.tsx";
import { filter } from "./vault-list.tsx";
import { ExportPage, ImportPage } from "./transfer.tsx";

const LOCK_OPTIONS: [string, string][] = [
  [String(LockTimeout.Immediately), "When the popup closes"],
  ["1", "After 1 minute"],
  ["5", "After 5 minutes"],
  ["15", "After 15 minutes"],
  ["30", "After 30 minutes"],
  ["60", "After 1 hour"],
  ["240", "After 4 hours"],
  [String(LockTimeout.OnRestart), "On browser restart"],
  [String(LockTimeout.Never), "Never"],
];

function lockLabel(v: number): string {
  return LOCK_OPTIONS.find(([k]) => Number(k) === v)?.[1] ?? `After ${v} minutes`;
}

function Toggle({ title, sub, checked, onChange, icon }: { title: string; sub?: ComponentChildren; checked: boolean; onChange: (v: boolean) => void; icon?: string }) {
  return (
    <Row
      leading={icon ? <Icon d={icon} class="lead-icon" /> : undefined}
      title={<span class="row-title">{title}</span>}
      sub={sub}
      trailing={<Switch checked={checked} onChange={onChange} label={title} />}
      onClick={() => onChange(!checked)}
    />
  );
}

function Nav({ icon, title, sub, page, onClick }: { icon: string; title: string; sub?: string; page?: string; onClick?: () => void }) {
  return (
    <Row
      leading={<div class="settings-ico"><Icon d={icon} /></div>}
      title={title}
      sub={sub}
      trailing={<Icon d={I.chevron} class="med" />}
      onClick={onClick ?? (() => push({ name: "settings-page", page: page! }))}
    />
  );
}

const set = (patch: Partial<Settings>) => void updateSettings(patch);

// ---------------------------------------------------------------- root list
const ACCENT_LABELS: Record<string, string> = {
  red: "Red", pink: "Pink", purple: "Purple", "deep-purple": "Deep purple", indigo: "Indigo", blue: "Blue", cyan: "Cyan", teal: "Teal",
  green: "Green", "light-green": "Light green", lime: "Lime", yellow: "Yellow", amber: "Amber", orange: "Orange", "deep-orange": "Deep orange",
  brown: "Brown", gray: "Gray", default: "Default",
};

export function SettingsScreen() {
  const s = settings.value;
  const a = account.value;
  return (
    <div class="settings">
      <TopBar title="Settings" />
      <Group>
        {a && <Row leading={<Avatar seed={a.id} name={a.name || a.email} sat={0.7} />} title={a.name || a.email} sub={a.name ? a.email : hostOf(a.server)} trailing={<Icon d={I.chevron} class="med" />} onClick={() => push({ name: "settings-page", page: "accounts" })} />}
      </Group>
      <div style={{ height: "12px" }} />
      <Group>
        <Nav icon={I.lock} title="Security" sub={`Lock ${lockLabel(s.lockTimeout).toLowerCase()}`} page="security" />
        <Nav icon={I.keyboard} title="Autofill" sub={s.autofill.inlineMenu ? "Inline menu, save prompts" : "Popup and shortcut only"} page="autofill" />
        <Nav icon={I.passkey} title="Passkeys" sub={s.passkeys.enabled ? "Keyward saves and uses passkeys" : "Off — the browser handles passkeys"} page="passkeys" />
        <Nav icon={I.palette} title="Appearance" sub={`${cap(s.theme)} theme · ${ACCENT_LABELS[s.accent] ?? "Custom"}`} page="appearance" />
      </Group>
      <div style={{ height: "12px" }} />
      <Group>
        <Nav icon={I.sync} title="Sync" sub={syncStatus.value?.at ? `Last synced ${ago(syncStatus.value.at)}` : "Not synced yet"} page="sync" />
        <Nav icon={I.folder} title="Folders" sub={`${aux.value.folders.length} folder${aux.value.folders.length === 1 ? "" : "s"}`} page="folders" />
        <Nav icon={I.archive} title="Archive" sub="Items kept out of the list and autofill" onClick={() => { filter.value = { archive: true }; home("vault"); }} />
        <Nav icon={I.del} title="Trash" sub="Restore or delete forever" onClick={() => { filter.value = { trash: true }; home("vault"); }} />
      </Group>
      <div style={{ height: "12px" }} />
      <Group>
        <Nav icon={I.upload} title="Import items" sub="From Bitwarden, Keyguard or a browser" page="import" />
        <Nav icon={I.download} title="Export vault" sub="JSON or CSV, encrypted or not" page="export" />
      </Group>
      <div style={{ height: "12px" }} />
      <Group>
        <Nav icon={I.info} title="About Keyward" sub={`Version ${__VERSION__}`} page="about" />
      </Group>
      <div style={{ height: "24px" }} />
    </div>
  );
}

export function SettingsPage({ page }: { page: string }) {
  const P = PAGES[page];
  if (!P) return null;
  return (
    <div class="settings">
      <TopBar title={P.title} back={pop} />
      <P.C />
      <div style={{ height: "24px" }} />
    </div>
  );
}

const PAGES: Record<string, { title: string; C: () => any }> = {
  accounts: { title: "Accounts", C: AccountsPage },
  security: { title: "Security", C: SecurityPage },
  autofill: { title: "Autofill", C: AutofillPage },
  passkeys: { title: "Passkeys", C: PasskeysPage },
  appearance: { title: "Appearance", C: AppearancePage },
  sync: { title: "Sync", C: SyncPage },
  folders: { title: "Folders", C: FoldersPage },
  about: { title: "About", C: AboutPage },
  import: { title: "Import items", C: ImportPage },
  export: { title: "Export vault", C: ExportPage },
  "autofill-excluded": { title: "Excluded sites", C: () => <SiteList path="autofill" /> },
  "autofill-never-save": {
    title: "Sites never saved",
    C: () => (
      <SiteList path="autofill" field="neverSave" canAdd={false} intro="Keyward doesn't offer to save or update logins on these sites. Filling still works." empty="No sites. Pick “Never for this site” on the save bar to add one." />
    ),
  },
  "passkeys-excluded": { title: "Passkey exceptions", C: () => <SiteList path="passkeys" /> },
};

// ---------------------------------------------------------------- pages
function AccountsPage() {
  const a = account.value;
  return (
    <>
      <Group>
        {accounts.value.list.map((x) => (
          <Row
            key={x.id}
            leading={<Avatar seed={x.id} name={x.name || x.email} sat={0.7} />}
            title={x.email}
            sub={hostOf(x.server)}
            selected={x.id === a?.id}
            trailing={x.id === a?.id ? <Icon d={I.checkCircle} class="primary" /> : undefined}
            onClick={() => x.id !== a?.id && switchAccount(x.id)}
          />
        ))}
        <Row leading={<div class="settings-ico"><Icon d={I.add} /></div>} title="Add account" onClick={() => (addingAccount.value = true)} />
      </Group>
      {a && (
        <>
          <div class="section-label">{a.email}</div>
          <Group>
            <Row leading={<div class="settings-ico"><Icon d={I.lock} /></div>} title="Lock now" onClick={() => lockNow()} />
            <Row
              leading={<div class="settings-ico"><Icon d={I.logout} /></div>}
              title={<span class="error-text">Log out</span>}
              sub="Removes this account and its offline copy from the browser"
              onClick={async () => {
                if (!(await confirm("Log out?", `Removes ${a.email} and its offline copy from this browser.`, "Log out", true))) return;
                await rpc("session.logout", { accountId: a.id });
                await refreshPhase();
              }}
            />
          </Group>
        </>
      )}
    </>
  );
}

function SecurityPage() {
  const s = settings.value;
  const a = account.value;
  const [pin, setPinOn] = useState<boolean | null>(null);
  const [pinSheet, setPinSheet] = useState(false);
  useEffect(() => {
    if (a) hasPinConfigured(a.id).then(setPinOn);
  }, [a?.id, pinSheet]);

  return (
    <>
      <div class="section-label">Vault timeout</div>
      <div class="pad col" style={{ gap: "10px" }}>
        <Select label="Lock the vault" value={String(s.lockTimeout)} options={LOCK_OPTIONS} onChange={(v) => set({ lockTimeout: Number(v) })} />
        <Select label="When the timeout runs out" value={s.timeoutAction} options={[["lock", "Lock"], ["logout", "Log out"]]} onChange={(v) => set({ timeoutAction: v as "lock" | "logout" })} />
      </div>
      {s.lockTimeout === LockTimeout.Never && (
        <div class="pad" style={{ marginTop: "10px" }}>
          <Banner tone="warn">The vault key is kept on disk, so anyone who can use this browser profile can open your vault.</Banner>
        </div>
      )}
      <div style={{ height: "12px" }} />
      <Group>
        <Toggle icon={I.lockReset} title="Lock when the computer locks" checked={s.lockOnSystemLock} onChange={(v) => set({ lockOnSystemLock: v })} />
      </Group>

      <div class="section-label">Unlock</div>
      <Group>
        <Toggle
          icon={I.dialpad}
          title="Unlock with PIN"
          sub={pin ? (s.pinSurvivesRestart ? "Works after a browser restart" : "Until the browser restarts, then the master password") : "Use a short PIN instead of the master password"}
          checked={!!pin}
          onChange={async (v) => {
            if (!a) return;
            if (v) setPinSheet(true);
            else {
              await clearPin(a.id);
              setPinOn(false);
              toast("PIN unlock turned off");
            }
          }}
        />
        {pin && (
          <Row leading={<div class="settings-ico"><Icon d={I.edit} /></div>} title="Change PIN" sub={s.pinSurvivesRestart ? "Survives restart" : "Session only"} onClick={() => setPinSheet(true)} />
        )}
      </Group>

      <div class="section-label">Clipboard</div>
      <div class="pad">
        <Select
          label="Clear copied secrets"
          value={String(s.clipboardClearSec)}
          options={[["0", "Never"], ["10", "After 10 seconds"], ["20", "After 20 seconds"], ["45", "After 45 seconds"], ["60", "After 1 minute"], ["120", "After 2 minutes"], ["300", "After 5 minutes"]]}
          onChange={(v) => set({ clipboardClearSec: Number(v) })}
        />
      </div>
      {pinSheet && a && <PinSheet onClose={() => setPinSheet(false)} />}
    </>
  );
}

function PinSheet({ onClose }: { onClose: () => void }) {
  const a = account.value!;
  const [p1, setP1] = useState("");
  const [p2, setP2] = useState("");
  const [survive, setSurvive] = useState(settings.value.pinSurvivesRestart);
  const [busy, setBusy] = useState(false);
  const err = p1 && p1.length < 4 ? "At least 4 characters" : p2 && p1 !== p2 ? "PINs don't match" : null;

  async function save(e: Event) {
    e.preventDefault();
    const ring = currentRing();
    if (!ring || err || !p1 || p1 !== p2) return;
    setBusy(true);
    try {
      await setPin(a.id, p1, ring.user, a.kdf, survive, lazyArgon2);
      await updateSettings({ pinSurvivesRestart: survive });
      toast("PIN set", { tone: "ok" });
      onClose();
    } catch (e) {
      toast((e as Error).message, { tone: "error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Sheet onClose={onClose}>
      <form class="col pad" style={{ gap: "12px" }} onSubmit={save}>
        <h2 class="t-title-l" style={{ margin: "0 0 4px" }}>Set a PIN</h2>
        <SecretField label="PIN" value={p1} onInput={setP1} autoFocus inputMode="numeric" error={p1.length > 0 && p1.length < 4 ? "At least 4 characters" : null} />
        <SecretField label="Repeat PIN" value={p2} onInput={setP2} inputMode="numeric" error={p2 && p1 !== p2 ? "PINs don't match" : null} />
        <div class="group" style={{ margin: 0 }}>
          <Toggle title="Keep PIN unlock after a browser restart" sub="Without it, the first unlock after a restart needs the master password" checked={survive} onChange={setSurvive} />
        </div>
        {survive && <Banner tone="warn">A short PIN can be guessed offline by anyone who copies this browser profile. Use 6+ digits or letters.</Banner>}
        <div class="row" style={{ justifyContent: "flex-end", gap: "8px" }}>
          <Button variant="text" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={busy} disabled={!!err || !p1 || p1 !== p2}>Save</Button>
        </div>
      </form>
    </Sheet>
  );
}

function AutofillPage() {
  const s = settings.value;
  const af = s.autofill;
  const setAf = (patch: Partial<Settings["autofill"]>) => set({ autofill: { ...af, ...patch } });
  return (
    <>
      <Group>
        <Toggle icon={I.keyboard} title="Inline menu in fields" sub="A Keyward button in login, card and identity fields" checked={af.inlineMenu} onChange={(v) => setAf({ inlineMenu: v })} />
        {af.inlineMenu && (
          <Toggle icon={I.adsClick} title="Open the menu when a field is focused" sub="Otherwise click the Keyward button in the field or press ↓" checked={af.menuOnFocus} onChange={(v) => setAf({ menuOnFocus: v })} />
        )}
        <Toggle icon={I.bolt} title="Fill on page load" sub="Only when exactly one login matches the page" checked={af.onPageLoad} onChange={(v) => setAf({ onPageLoad: v })} />
        <Toggle icon={I.steps} title="Fill the next login step" sub="After a fill, the password page and the verification code page that follow fill themselves" checked={af.continueSteps} onChange={(v) => setAf({ continueSteps: v })} />
        <Toggle icon={I.schedule} title="Copy the TOTP code after filling" sub="When the page has no code field yet" checked={af.copyTotp} onChange={(v) => setAf({ copyTotp: v })} />
      </Group>
      <div class="section-label">Prompts</div>
      <Group>
        <Toggle icon={I.add} title="Ask to save new logins" checked={af.savePrompt} onChange={(v) => setAf({ savePrompt: v })} />
        <Toggle icon={I.refresh} title="Ask to update changed passwords" checked={af.updatePrompt} onChange={(v) => setAf({ updatePrompt: v })} />
        <Nav icon={I.domainDisabled} title="Sites never saved" sub={af.neverSave.length ? `${af.neverSave.length} site${af.neverSave.length === 1 ? "" : "s"}` : "None"} page="autofill-never-save" />
        <Toggle icon={I.dns} title="Fill HTTP sign-in dialogs" sub="Basic authentication on routers, NAS and similar" checked={af.basicAuth} onChange={(v) => setAf({ basicAuth: v })} />
      </Group>
      <div class="section-label">Matching</div>
      <div class="pad">
        <Select
          label="Default URI match"
          value={String(s.defaultUriMatch)}
          options={[["0", "Base domain"], ["1", "Host"], ["2", "Starts with"], ["3", "Exact"], ["4", "Regular expression"], ["5", "Never"]]}
          onChange={(v) => set({ defaultUriMatch: Number(v) })}
        />
      </div>
      <div style={{ height: "12px" }} />
      <Group>
        <Nav icon={I.block} title="Excluded sites" sub={af.excluded.length ? `${af.excluded.length} site${af.excluded.length === 1 ? "" : "s"}` : "None"} page="autofill-excluded" />
      </Group>
      <div class="section-label">Shortcuts</div>
      <Group>
        <Row leading={<div class="settings-ico"><Icon d={I.keyboard} /></div>} title="Ctrl+Shift+L" sub="Fill the next matching login" />
        <Row leading={<div class="settings-ico"><Icon d={I.dice} /></div>} title="Ctrl+Shift+9" sub="Generate a password and copy it" />
        <Row
          leading={<div class="settings-ico"><Icon d={I.tune} /></div>}
          title="Change shortcuts"
          sub="In the browser's extension shortcut settings"
          trailing={<Icon d={I.openInNew} class="med" />}
          onClick={() => chrome.tabs.create({ url: __FIREFOX__ ? "about:addons" : "chrome://extensions/shortcuts" })}
        />
      </Group>
    </>
  );
}

function PasskeysPage() {
  const p = settings.value.passkeys;
  return (
    <>
      <Group>
        <Toggle icon={I.passkey} title="Use Keyward for passkeys" sub="Save and sign in with passkeys stored in your vault. You can always pick the browser or a security key instead." checked={p.enabled} onChange={(v) => set({ passkeys: { ...p, enabled: v } })} />
      </Group>
      <div style={{ height: "12px" }} />
      <Group>
        <Nav icon={I.block} title="Sites that always use the browser" sub={p.excluded.length ? `${p.excluded.length} site${p.excluded.length === 1 ? "" : "s"}` : "None"} page="passkeys-excluded" />
      </Group>
    </>
  );
}

type SiteListProps =
  | { path: "autofill"; field?: "excluded" | "neverSave"; canAdd?: boolean; intro?: string; empty?: string }
  | { path: "passkeys"; field?: "excluded"; canAdd?: boolean; intro?: string; empty?: string };

function SiteList({ path, field = "excluded", canAdd = true, intro, empty = "No sites yet. Keyward behaves normally everywhere." }: SiteListProps) {
  const section: Record<string, unknown> = settings.value[path];
  const list = (section[field] as string[] | undefined) ?? [];
  const [v, setV] = useState("");
  const save = (next: string[]) => set({ [path]: { ...settings.value[path], [field]: next } } as Partial<Settings>);
  function add(e: Event) {
    e.preventDefault();
    let host = v.trim().toLowerCase();
    try {
      host = new URL(host.includes("://") ? host : `https://${host}`).hostname;
    } catch {
      return toast("Not a valid site", { tone: "error" });
    }
    if (!host || list.includes(host)) return setV("");
    save([...list, host].sort());
    setV("");
  }
  return (
    <>
      {intro && <div class="pad t-body-s med" style={{ marginBottom: "12px" }}>{intro}</div>}
      {canAdd && (
        <>
          <form class="pad row" style={{ gap: "8px" }} onSubmit={add}>
            <div class="grow"><TextField label="Site, e.g. example.com" value={v} onInput={setV} /></div>
            <IconButton icon={I.add} label="Add site" type="submit" />
          </form>
          <div style={{ height: "12px" }} />
        </>
      )}
      {list.length ? (
        <Group>
          {list.map((h) => (
            <Row key={h} leading={<div class="settings-ico"><Icon d={I.globe} /></div>} title={h} trailing={<IconButton icon={I.close} label={`Remove ${h}`} onClick={() => save(list.filter((x) => x !== h))} />} />
          ))}
        </Group>
      ) : (
        <div class="pad t-body-m med">{empty}</div>
      )}
    </>
  );
}

function AppearancePage() {
  const s = settings.value;
  const list = useSignal<{ id: string; label: string; seed: string }[]>([]);
  useEffect(() => {
    accents().then((a) => (list.value = a));
  }, []);
  return (
    <>
      <div class="pad col" style={{ gap: "10px" }}>
        <Select label="Theme" value={s.theme} options={[["system", "Follow system"], ["light", "Light"], ["dark", "Dark"]]} onChange={(v) => set({ theme: v as Settings["theme"] })} />
        <Select label="Font" value={s.font} options={[["roboto", "Roboto"], ["system", "System font"]]} onChange={(v) => set({ font: v as Settings["font"] })} />
      </div>
      <div style={{ height: "12px" }} />
      <Group>
        <Toggle icon={I.palette} title="Black dark theme" sub="Pure black for OLED screens" checked={s.amoled} onChange={(v) => set({ amoled: v })} />
        <Toggle icon={I.globe} title="Show website icons" sub="Fetched through your server" checked={s.showFavicons} onChange={(v) => set({ showFavicons: v })} />
        <Toggle icon={I.numbers} title="Count logins on the toolbar icon" checked={s.badgeCount} onChange={(v) => set({ badgeCount: v })} />
      </Group>
      <div class="section-label">Accent color</div>
      <div class="accents pad">
        {list.value.map((x) => (
          <button
            key={x.id}
            type="button"
            class="accent"
            title={x.label}
            aria-label={x.label}
            aria-pressed={s.accent === x.id}
            style={{ background: x.id === "default" ? "conic-gradient(#F44336, #FFEB3B, #4CAF50, #2196F3, #9C27B0, #F44336)" : x.seed }}
            onClick={() => set({ accent: x.id })}
          >
            {s.accent === x.id && <Icon d={I.check} size={20} />}
          </button>
        ))}
      </div>
    </>
  );
}

function SyncPage() {
  const s = settings.value;
  const st = syncStatus.value;
  const [busy, setBusy] = useState(false);
  return (
    <>
      <Group>
        <Row
          leading={<div class="settings-ico"><Icon d={st && !st.ok ? I.cloudOff : I.cloudDone} /></div>}
          title={st ? (st.ok ? "Up to date" : st.offline ? "Offline" : "Sync failed") : "Not synced yet"}
          sub={st ? `${ago(st.at)}${st.total != null ? ` · ${st.total} items` : ""}${st.error ? ` · ${st.error}` : ""}` : undefined}
          trailing={<Button variant="tonal" loading={busy} onClick={async () => { setBusy(true); await syncNow(true).finally(() => setBusy(false)); }}>Sync now</Button>}
        />
      </Group>
      <div style={{ height: "12px" }} />
      <Group>
        <Toggle icon={I.bolt} title="Live updates" sub="Keep a connection to the server for instant changes. Otherwise Keyward checks when you open it and every 5 minutes." checked={s.websocketSync} onChange={(v) => set({ websocketSync: v })} />
      </Group>
    </>
  );
}

function FoldersPage() {
  const folders = [...aux.value.folders].sort((a, b) => a.name.localeCompare(b.name));
  const [name, setName] = useState("");
  async function add(e: Event) {
    e.preventDefault();
    if (!name.trim()) return;
    try {
      await rpc("folder.save", { name: name.trim() });
      setName("");
    } catch (err) {
      toast((err as Error).message, { tone: "error" });
    }
  }
  return (
    <>
      <form class="pad row" style={{ gap: "8px" }} onSubmit={add}>
        <div class="grow"><TextField label="New folder" value={name} onInput={setName} /></div>
        <IconButton icon={I.add} label="Add folder" type="submit" />
      </form>
      <div style={{ height: "12px" }} />
      {folders.length ? (
        <Group>
          {folders.map((f) => (
            <Row
              key={f.id}
              leading={<div class="settings-ico"><Icon d={I.folder} /></div>}
              title={f.name}
              onClick={() => { filter.value = { folder: f.id }; home("vault"); }}
              trailing={
                <IconButton
                  icon={I.more}
                  label="Folder options"
                  onClick={(e) => {
                    e.stopPropagation();
                    openMenu(e.currentTarget as HTMLElement, [
                      {
                        icon: I.edit,
                        label: "Rename",
                        run: async () => {
                          const n = prompt("Folder name", f.name)?.trim();
                          if (n && n !== f.name) await rpc("folder.save", { id: f.id, name: n }).catch((err) => toast(err.message, { tone: "error" }));
                        },
                      },
                      {
                        icon: I.del,
                        label: "Delete",
                        danger: true,
                        run: async () => {
                          if (await confirm(`Delete “${f.name}”?`, "Items in it are kept and move to “No folder”.", "Delete", true))
                            await rpc("folder.delete", { id: f.id }).catch((err) => toast(err.message, { tone: "error" }));
                        },
                      },
                    ]);
                  }}
                />
              }
            />
          ))}
        </Group>
      ) : (
        <div class="pad t-body-m med">No folders yet.</div>
      )}
    </>
  );
}

function AboutPage() {
  const a = account.value;
  return (
    <>
      <div class="about-head">
        <img src="/icons/128.png" width={72} height={72} alt="" />
        <div class="t-title-l" style={{ marginTop: "12px" }}>Keyward</div>
        <div class="t-body-m med">Version {__VERSION__} · {__FIREFOX__ ? "LibreWolf / Firefox" : "Chromium"}</div>
      </div>
      <Group>
        {a && (
          <Row
            leading={<div class="settings-ico"><Icon d={I.dns} /></div>}
            title="Open web vault"
            sub={hostOf(a.server)}
            trailing={<Icon d={I.openInNew} class="med" />}
            onClick={() => chrome.tabs.create({ url: a.server })}
          />
        )}
        <Row leading={<div class="settings-ico"><Icon d={I.info} /></div>} title="Design" sub="Inspired by Keyguard by Artem Chepurnyi" />
      </Group>
    </>
  );
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function cap(s: string) {
  return s[0].toUpperCase() + s.slice(1);
}

