import { useEffect, useState } from "preact/hooks";
import { startLogin, submitLogin, sendEmailCode, preferredProvider, TWO_FACTOR_NAMES, TwoFactorProvider, type LoginOutcome } from "../../core/auth/login.ts";
import { ApiError, OfflineError, serverUrls } from "../../core/api/client.ts";
import { deriveMasterKey, masterPasswordHash } from "../../core/crypto/kdf.ts";
import { decryptUserKey } from "../../core/crypto/keys.ts";
import { DEFAULT_SERVER, removeAccount } from "../../platform/accounts.ts";
import { apiForServer, attemptOf, clearPending, finishLogin, lazyArgon2, loadPending, rememberToken, savePending, submitTwoFactor, type PendingLogin } from "../../platform/login.ts";
import { rpc } from "../../platform/messages.ts";
import { pinAvailable, restorePinSession, unlockWithPin, PinError } from "../../platform/pin.ts";
import { Avatar, Banner, Button, Chip, Icon, IconButton, SecretField, Switch, TextField, openMenu, toast, confirm } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { account, accounts, addingAccount, needsLogin, refreshPhase, switchAccount, syncing } from "../data/app.ts";

function errText(e: unknown): string {
  if (e instanceof OfflineError) return "Can't reach the server. Check the URL and your connection.";
  if (e instanceof ApiError) return e.message;
  return (e as Error)?.message ?? String(e);
}

function Logo({ size = 56 }: { size?: number }) {
  return <img src="/icons/128.png" width={size} height={size} alt="" style={{ borderRadius: size * 0.27 + "px", display: "block" }} />;
}

export function AuthFrame({ title, subtitle, children, onBack }: { title: string; subtitle?: string; children: any; onBack?: () => void }) {
  return (
    <div class="auth page-enter">
      {onBack && (
        <div style={{ padding: "8px 4px 0" }}>
          <IconButton icon={I.back} label="Back" onClick={onBack} />
        </div>
      )}
      <div class="auth-head">
        <Logo />
        <h1 class="t-headline" style={{ margin: "16px 0 4px" }}>{title}</h1>
        {subtitle && <p class="t-body-m med" style={{ margin: 0 }}>{subtitle}</p>}
      </div>
      <div class="auth-body">{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------- login
export function LoginScreen({ onCancel, prefillEmail }: { onCancel?: () => void; prefillEmail?: string }) {
  const [server, setServer] = useState(account.value?.server ?? DEFAULT_SERVER);
  const [editServer, setEditServer] = useState(false);
  const [email, setEmail] = useState(prefillEmail ?? "");
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingLogin | null>(null);

  useEffect(() => {
    // Resume a two-step login that was interrupted (Firefox closes the popup when you switch windows to read the code).
    loadPending().then((p) => p && setPending(p));
  }, []);

  if (pending) return <TwoFactorScreen pending={pending} onCancel={async () => { await clearPending(); setPending(null); }} />;

  async function submit(e: Event) {
    e.preventDefault();
    if (!email.trim() || !pw) return;
    setBusy(true);
    setErr(null);
    try {
      const api = await apiForServer(server);
      const attempt = await startLogin(api, email, pw, lazyArgon2);
      const out = await submitLogin(api, attempt, { rememberToken: await rememberToken(server, attempt.email) });
      await handleOutcome(server, out, setPending);
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  }

  const host = (() => {
    try {
      return new URL(serverUrls(server).base).host;
    } catch {
      return server;
    }
  })();

  return (
    <AuthFrame title="Log in" subtitle="Bitwarden-compatible account (Vaultwarden)" onBack={onCancel}>
      <form onSubmit={submit} class="col" style={{ gap: "12px" }}>
        {editServer ? (
          <TextField label="Server URL" value={server} onInput={setServer} type="url" hint="Your self-hosted Vaultwarden, e.g. https://pass.example.com" />
        ) : (
          <button type="button" class="item click" style={{ borderRadius: "16px" }} onClick={() => setEditServer(true)}>
            <Icon d={I.dns} />
            <div class="text">
              <div class="title" style={{ fontSize: "14px" }}>Server</div>
              <div class="sub">{host}</div>
            </div>
            <Icon d={I.edit} size={20} />
          </button>
        )}
        <TextField label="Email" value={email} onInput={setEmail} type="email" autocomplete="username" autoFocus={!email} name="email" />
        <SecretField label="Master password" value={pw} onInput={setPw} autocomplete="current-password" autoFocus={!!email} name="password" />
        {err && <Banner tone="error">{err}</Banner>}
        <Button type="submit" full loading={busy} disabled={!email.trim() || !pw} icon={I.lockOpen}>
          {busy ? "Logging in…" : "Log in"}
        </Button>
        <p class="t-body-s med" style={{ textAlign: "center", margin: "4px 0 0" }}>
          Your master password never leaves this device.
        </p>
      </form>
    </AuthFrame>
  );
}

async function handleOutcome(server: string, out: LoginOutcome, setPending: (p: PendingLogin) => void) {
  if (out.kind === "twoFactor") {
    await savePending(server, out);
    setPending((await loadPending())!);
    return;
  }
  const { accountId, userKey } = await finishLogin(server, out);
  await completeLogin(accountId, userKey);
}

/** Every login path ends here: hand the key to the background, leave "add account" mode, show the vault. */
async function completeLogin(accountId: string, userKey: string) {
  syncing.value = true;
  const r = await rpc("session.loginComplete", { accountId, userKey });
  if (!r.synced && r.error) toast(`Sync failed: ${r.error}`, { tone: "error" });
  addingAccount.value = false;
  await refreshPhase();
}

// ---------------------------------------------------------------- two-step
function TwoFactorScreen({ pending, onCancel }: { pending: PendingLogin; onCancel: () => void }) {
  const providers = Object.keys(pending.providers).map(Number).filter((p) => p in TWO_FACTOR_NAMES && p !== TwoFactorProvider.Duo && p !== TwoFactorProvider.OrganizationDuo);
  const [provider, setProvider] = useState<number>(preferredProvider(pending.providers));
  const [code, setCode] = useState("");
  const [remember, setRemember] = useState(true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  async function sendEmail() {
    setErr(null);
    try {
      await sendEmailCode(await apiForServer(pending.server), attemptOf(pending));
      setSent(true);
      toast("Code sent");
    } catch (e) {
      setErr(errText(e));
    }
  }

  useEffect(() => {
    setCode("");
    setErr(null);
    if (provider === TwoFactorProvider.Email && !sent) void sendEmail();
  }, [provider]);

  async function submit(token: string) {
    if (!token.trim()) return;
    setBusy(true);
    setErr(null);
    try {
      const out = await submitTwoFactor(pending, { provider, token, remember });
      if (out.kind === "twoFactor") throw new Error("The server asked for another code. Try again.");
      const { accountId, userKey } = await finishLogin(pending.server, out);
      await completeLogin(accountId, userKey);
    } catch (e) {
      setErr(errText(e));
      setBusy(false);
    }
  }

  async function webauthn() {
    setBusy(true);
    setErr(null);
    try {
      // Runs in the background: the assertion needs a tab on the server's origin, and the popup
      // closes as soon as that tab takes focus. The background finishes the login on its own.
      const r = await rpc("auth.webauthn2fa", { remember });
      if (!r.ok) throw new Error(r.error ?? "Security key sign-in failed");
      addingAccount.value = false;
      await refreshPhase();
    } catch (e) {
      setErr(errText(e));
      setBusy(false);
    }
  }

  const hint =
    provider === TwoFactorProvider.Authenticator
      ? "Enter the code from your authenticator app."
      : provider === TwoFactorProvider.Email
        ? `Enter the code sent to ${pending.providers[1]?.email ?? "your email"}.`
        : provider === TwoFactorProvider.WebAuthn
          ? "Use your passkey or security key. A tab on your server opens for the browser's prompt."
          : provider === TwoFactorProvider.Yubikey
            ? "Touch your YubiKey to type its code."
            : "Enter your recovery code.";

  return (
    <AuthFrame title="Two-step login" subtitle={pending.email} onBack={onCancel}>
      <div class="col" style={{ gap: "12px" }}>
        {providers.length > 1 && (
          <div class="chips" style={{ padding: 0, flexWrap: "wrap" }}>
            {providers.map((p) => (
              <Chip key={p} selected={p === provider} onClick={() => setProvider(p)}>
                {TWO_FACTOR_NAMES[p]}
              </Chip>
            ))}
          </div>
        )}
        <p class="t-body-m med" style={{ margin: 0 }}>{hint}</p>
        {provider === TwoFactorProvider.WebAuthn ? (
          <Button full icon={I.passkey} loading={busy} onClick={webauthn}>Use passkey / security key</Button>
        ) : (
          <form onSubmit={(e) => { e.preventDefault(); void submit(code); }} class="col" style={{ gap: "12px" }}>
            <TextField
              label={provider === TwoFactorProvider.RecoveryCode ? "Recovery code" : "Code"}
              value={code}
              onInput={(v) => {
                setCode(v);
                const digits = v.replace(/\s/g, "");
                if ((provider === 0 || provider === 1) && /^\d{6}$/.test(digits) && !busy) void submit(digits);
              }}
              autoFocus
              mono
              inputMode={provider <= 1 ? "numeric" : undefined}
              autocomplete="one-time-code"
              trailing={provider === TwoFactorProvider.Email ? <Button variant="text" onClick={sendEmail}>Resend</Button> : undefined}
            />
            <Button type="submit" full loading={busy} disabled={!code.trim()}>Continue</Button>
          </form>
        )}
        <label class="row" style={{ gap: "12px", padding: "4px 4px" }}>
          <span class="grow t-body-m">Remember this device</span>
          <Switch checked={remember} onChange={setRemember} label="Remember this device" />
        </label>
        {err && <Banner tone="error">{err}</Banner>}
      </div>
    </AuthFrame>
  );
}

// ---------------------------------------------------------------- unlock
export function UnlockScreen() {
  const a = account.value!;
  const [mode, setMode] = useState<"password" | "pin" | null>(null);
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [relogin, setRelogin] = useState(false);

  // No state reset here: the shell remounts this screen per account (key), and a reset after the
  // first paint would drop a password typed or filled in before it ran.
  useEffect(() => {
    pinAvailable(a.id).then((ok) => setMode(ok && !needsLogin.value ? "pin" : "password"));
  }, [a.id]);

  if (relogin) return <LoginScreen prefillEmail={a.email} onCancel={() => setRelogin(false)} />;

  async function submit(e: Event) {
    e.preventDefault();
    if (!pw) return;
    setBusy(true);
    setErr(null);
    try {
      let userKeyB64: string;
      if (mode === "pin") {
        userKeyB64 = (await unlockWithPin(a.id, pw, lazyArgon2)).toB64();
      } else {
        const mk = await deriveMasterKey(pw, a.email, a.kdf, lazyArgon2);
        if (a.localHash && (await masterPasswordHash(mk, pw, 2)) !== a.localHash) throw new Error("Invalid master password");
        const uk = await decryptUserKey(a.protectedUserKey, mk).catch(() => {
          throw new Error("Invalid master password");
        });
        await restorePinSession(a.id, uk, lazyArgon2);
        userKeyB64 = uk.toB64();
      }
      await rpc("session.unlocked", { accountId: a.id, userKey: userKeyB64, via: mode ?? "password" });
      await refreshPhase();
    } catch (e) {
      setErr(e instanceof PinError ? e.message : errText(e));
      if (e instanceof PinError && e.remaining === 0) setMode("password");
      setPw("");
    } finally {
      setBusy(false);
    }
  }

  const others = accounts.value.list.filter((x) => x.id !== a.id);
  let host = a.server;
  try {
    host = new URL(a.server).host;
  } catch {}

  return (
    <AuthFrame title={needsLogin.value ? "Session expired" : "Vault is locked"} subtitle={needsLogin.value ? "Log in again to continue" : undefined}>
      <div class="col" style={{ gap: "12px" }}>
        <div class="item" style={{ borderRadius: "16px" }}>
          <Avatar seed={a.id} name={a.name || a.email} sat={0.7} />
          <div class="text">
            <div class="title">{a.email}</div>
            <div class="sub">{host}</div>
          </div>
          <IconButton
            icon={I.more}
            label="Account options"
            onClick={(e) =>
              openMenu(e.currentTarget as HTMLElement, [
                ...others.map((o) => ({ icon: I.account, label: `Switch to ${o.email}`, run: () => switchAccount(o.id) })),
                { icon: I.add, label: "Add account", run: () => (addingAccount.value = true) },
                { divider: true, label: "" },
                {
                  icon: I.logout,
                  label: "Log out",
                  danger: true,
                  run: async () => {
                    if (await confirm("Log out?", `Removes ${a.email} and its offline data from this browser.`, "Log out", true)) {
                      await rpc("session.logout", { accountId: a.id }).catch(() => removeAccount(a.id));
                      await refreshPhase();
                    }
                  },
                },
              ])
            }
          />
        </div>
        {needsLogin.value ? (
          <Button full icon={I.lockOpen} onClick={() => setRelogin(true)}>Log in</Button>
        ) : (
          <form onSubmit={submit} class="col" style={{ gap: "12px" }}>
            {mode === "pin" ? (
              <SecretField label="PIN" value={pw} onInput={setPw} autoFocus inputMode="numeric" autocomplete="off" />
            ) : (
              <SecretField label="Master password" value={pw} onInput={setPw} autoFocus autocomplete="current-password" />
            )}
            {err && <Banner tone="error">{err}</Banner>}
            <Button type="submit" full loading={busy} disabled={!pw} icon={I.lockOpen}>Unlock</Button>
            {mode === "pin" ? (
              <Button variant="text" onClick={() => { setMode("password"); setPw(""); setErr(null); }}>Use master password</Button>
            ) : null}
          </form>
        )}
      </div>
    </AuthFrame>
  );
}
