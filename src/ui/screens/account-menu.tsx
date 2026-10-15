import { rpc } from "../../platform/messages.ts";
import { Avatar, confirm, openMenu, toast } from "../components/kit.tsx";
import * as I from "../icons/index.ts";
import { account, accounts, addingAccount, lockNow, refreshPhase, switchAccount, syncNow, syncStatus } from "../data/app.ts";
import { home } from "../data/nav.ts";

export function isPopup(): boolean {
  return location.pathname.endsWith("popup.html");
}

export function AccountButton() {
  const a = account.value;
  if (!a) return null;
  const last = syncStatus.value?.at;
  return (
    <button
      type="button"
      class="icon-btn"
      aria-label="Account and vault menu"
      title={a.email}
      onClick={(e) =>
        openMenu(e.currentTarget as HTMLElement, [
          { header: true, label: a.email },
          {
            icon: I.sync,
            label: last ? `Sync now · ${ago(last)}` : "Sync now",
            run: async () => {
              await syncNow(true);
              const st = syncStatus.value;
              toast(st?.ok ? "Vault synced" : `Sync failed: ${st?.error}`, { tone: st?.ok ? "ok" : "error" });
            },
          },
          { icon: I.lock, label: "Lock", run: () => lockNow() },
          ...(isPopup() ? [{ icon: I.openFull, label: "Open vault in a tab", run: () => { void rpc("ui.openVault"); window.close(); } }] : []),
          { icon: I.settings, label: "Settings", run: () => home("settings") },
          { divider: true, label: "" },
          ...accounts.value.list.filter((x) => x.id !== a.id).map((x) => ({ icon: I.account, label: x.email, run: () => switchAccount(x.id) })),
          { icon: I.add, label: "Add account", run: () => (addingAccount.value = true) },
          {
            icon: I.logout,
            label: "Log out",
            danger: true,
            run: async () => {
              if (!(await confirm("Log out?", `Removes ${a.email} and its offline copy from this browser.`, "Log out", true))) return;
              await rpc("session.logout", { accountId: a.id });
              await refreshPhase();
            },
          },
        ])
      }
    >
      <Avatar seed={a.id} name={a.name || a.email} sat={0.7} />
    </button>
  );
}

export function ago(t: number): string {
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(t).toLocaleDateString();
}

