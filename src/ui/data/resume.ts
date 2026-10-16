// The popup closes whenever it loses focus: switching to a terminal to copy something, or (on
// Linux, and always in Firefox) opening a file dialog. So the popup keeps what is on screen and
// any unsaved form in storage.session ("ui:<account>"), and a reopened popup puts the user back
// there. storage.session is memory only and closed to content scripts, the same place as the
// unlocked keys; locking clears it (platform/session.ts, clearUnlocked).
//
// Choosing a file can't happen in the popup at all, so there the screen and its draft are handed
// to the full-tab vault ("vault.html#resume"), which takes them over.
import { effect } from "@preact/signals";
import { session } from "../../platform/storage.ts";
import { direction, stack, tab, type Route, type Tab } from "./nav.ts";

interface Saved {
  tab: Tab;
  stack: Route[];
  /** Unsaved forms, by the route that shows them (draftKey). */
  drafts: Record<string, unknown>;
  at: number;
}

/** A screen without unsaved changes comes back if the popup was closed less than this ago. */
const KEEP_SCREEN_MS = 5 * 60_000;
const TABS: Tab[] = ["vault", "generator", "send", "watchtower", "gpg", "settings"];

/** "popup": save and restore; "handoff": a full tab taking over the popup's screen; null: neither. */
let mode: "popup" | "handoff" | null = null;
let owner: string | null = null;
let drafts: Record<string, unknown> = {};
let pending = false;

export const uiKey = (accountId: string) => `ui:${accountId}`;
export const draftKey = (r: Route) => JSON.stringify(r);

export function setResumeMode(m: typeof mode) {
  mode = m;
}

/**
 * Called when an account is found unlocked, before its vault renders: puts the saved screen
 * back, once per page and account. `saved` is what storage.session holds under uiKey(accountId).
 */
export function restoreUi(accountId: string, saved: unknown) {
  if (owner === accountId) return;
  owner = accountId;
  drafts = {};
  if (!mode) return;
  const m = mode;
  if (m === "handoff") {
    mode = null; // only the first account's screen is the popup's, and this tab saves nothing
    void session.remove(uiKey(accountId));
  }
  const s = saved as Saved | undefined;
  const ok = !!s && TABS.includes(s.tab) && Array.isArray(s.stack) && s.stack[0]?.name === "home" && s.stack.every((r) => r && typeof r.name === "string");
  if (!ok) return;
  const hasDrafts = Object.keys(s.drafts ?? {}).length > 0;
  if (m === "popup" && !hasDrafts && Date.now() - s.at > KEEP_SCREEN_MS) return;
  drafts = { ...(s.drafts ?? {}) };
  direction.value = "forward";
  tab.value = s.tab;
  stack.value = s.stack;
}

/** The vault locked (or the account left): forms kept in this page go too. */
export function forgetUi() {
  owner = null;
  drafts = {};
}

/** The unsaved form for this route, if one was kept. */
export function takeDraft<T>(key: string): T | undefined {
  return drafts[key] as T | undefined;
}

/** Keeps a form's state while its route is on screen (dropped once the route is left). */
export function saveDraft(key: string, value: unknown) {
  if (!stack.value.some((r) => draftKey(r) === key)) return;
  drafts[key] = value;
  schedule();
}

/** Throws away a form's kept state (the form was saved or discarded). */
export function dropDraft(key: string) {
  if (!(key in drafts)) return;
  delete drafts[key];
  schedule();
}

function snapshot(): Saved {
  const live = new Set(stack.value.map(draftKey));
  for (const k of Object.keys(drafts)) if (!live.has(k)) delete drafts[k];
  return { tab: tab.value, stack: stack.value, drafts, at: Date.now() };
}

/** One write per burst of changes; storage.session is in memory, so this is cheap. */
function schedule() {
  if (mode !== "popup" || !owner || pending) return;
  pending = true;
  queueMicrotask(() => {
    pending = false;
    if (owner) void session.set(uiKey(owner), snapshot()).catch(() => {});
  });
}

effect(() => {
  void stack.value;
  void tab.value;
  schedule();
});

/** Opening a file dialog closes the popup in Firefox and on Linux (as Bitwarden notes too). */
export function fileDialogClosesPopup(): boolean {
  if (mode !== "popup") return false;
  return __FIREFOX__ || /Linux|CrOS/.test(navigator.userAgent);
}

/**
 * For a file input's onClick: in a popup that a file dialog would close, the dialog is not
 * opened; the screen and its draft move to the full tab instead, where the user picks the file.
 */
export function guardFileDialog(e: Event) {
  if (!fileDialogClosesPopup()) return;
  e.preventDefault();
  void handOff();
}

export async function handOff(): Promise<void> {
  if (owner) await session.set(uiKey(owner), snapshot());
  await chrome.tabs.create({ url: chrome.runtime.getURL("vault.html#resume") });
  window.close();
}
