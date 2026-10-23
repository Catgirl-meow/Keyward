import { policedTimeout, type EffectivePolicy } from "../core/vault/policy.ts";
import { loadPolicy } from "./policy.ts";
import { local } from "./storage.ts";

export const LockTimeout = {
  OnRestart: -1,
  Never: -2,
  Immediately: 0,
} as const;

export interface Settings {
  theme: "system" | "light" | "dark";
  amoled: boolean;
  accent: string; // swatch id, see ui/theme/palettes
  font: "roboto" | "atkinson" | "system";
  /** minutes; -1 = on browser restart (default), -2 = never, 0 = when the popup closes */
  lockTimeout: number;
  lockOnSystemLock: boolean;
  timeoutAction: "lock" | "logout";
  pinSurvivesRestart: boolean;
  clipboardClearSec: number; // 0 = never
  showFavicons: boolean;
  badgeCount: boolean;
  websocketSync: boolean;
  defaultUriMatch: number; // 0 domain
  autofill: {
    inlineMenu: boolean;
    /** open the inline menu when an empty login field gets focus (else: icon click / ↓) */
    menuOnFocus: boolean;
    /** fill the password and code steps of a login that started with a fill in this tab */
    continueSteps: boolean;
    onPageLoad: boolean;
    copyTotp: boolean;
    savePrompt: boolean;
    updatePrompt: boolean;
    basicAuth: boolean;
    excluded: string[]; // hostnames where nothing is injected / prompted
    neverSave: string[]; // hostnames where "Never" was chosen in the save prompt
  };
  passkeys: { enabled: boolean; excluded: string[] };
  generator: Record<string, unknown>;
  /** the active account's organization policies (computed, never saved); lockTimeout and
   * timeoutAction above already follow them */
  policy?: EffectivePolicy;
}

export const DEFAULT_SETTINGS: Settings = {
  theme: "system",
  amoled: false,
  accent: "indigo",
  font: "roboto",
  lockTimeout: LockTimeout.OnRestart,
  lockOnSystemLock: false,
  timeoutAction: "lock",
  pinSurvivesRestart: false,
  clipboardClearSec: 45,
  showFavicons: true,
  badgeCount: true,
  websocketSync: false,
  defaultUriMatch: 0,
  autofill: {
    inlineMenu: true,
    menuOnFocus: true,
    continueSteps: true,
    onPageLoad: false,
    copyTotp: true,
    savePrompt: true,
    updatePrompt: true,
    basicAuth: true,
    excluded: [],
    neverSave: [],
  },
  passkeys: { enabled: true, excluded: [] },
  generator: {},
};

function merge<T>(base: T, over: any): T {
  if (!over || typeof over !== "object" || Array.isArray(base)) return (over ?? base) as T;
  const out: any = { ...base };
  for (const k of Object.keys(over)) {
    const b = (base as any)[k];
    out[k] = b && typeof b === "object" && !Array.isArray(b) ? merge(b, over[k]) : over[k];
  }
  return out;
}

export async function loadSettings(): Promise<Settings> {
  const [s, policy] = await Promise.all([local.get("settings"), loadPolicy()]);
  const out = merge(DEFAULT_SETTINGS, s);
  if (!policy) return out;
  const t = policedTimeout(out.lockTimeout, out.timeoutAction, policy);
  return { ...out, lockTimeout: t.minutes, timeoutAction: t.action, policy };
}

export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const next = merge(merge(DEFAULT_SETTINGS, await local.get("settings")), patch);
  delete next.policy;
  await local.set("settings", next);
  return loadSettings();
}
