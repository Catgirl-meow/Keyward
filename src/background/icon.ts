import { loadAccounts } from "../platform/accounts.ts";
import { isUnlocked } from "../platform/session.ts";

let last: boolean | null = null;

export async function refreshIcon(): Promise<void> {
  const s = await loadAccounts();
  const unlocked = !!s.active && (await isUnlocked(s.active));
  if (unlocked === last) return;
  last = unlocked;
  const p = unlocked ? "icons/" : "icons/locked-";
  await chrome.action.setIcon({ path: { 16: `${p}16.png`, 32: `${p}32.png` } }).catch(() => {});
  await chrome.action.setTitle({ title: unlocked ? "Keyward" : s.list.length ? "Keyward — locked" : "Keyward — log in" }).catch(() => {});
}
