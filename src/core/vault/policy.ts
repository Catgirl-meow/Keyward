// Organization policies (Bitwarden's PolicyType), reduced to what this account must follow.
// A policy counts when it is enabled, its organization is enabled, uses policies and has
// confirmed the user. Owners and admins are exempt, as in Bitwarden, except where noted.
import type { PassphraseOpts, PasswordOpts } from "../generator/password.ts";

export const PolicyType = {
  PasswordGenerator: 2,
  PersonalOwnership: 5,
  DisableSend: 6,
  SendOptions: 7,
  MaximumVaultTimeout: 9,
  DisablePersonalVaultExport: 10,
  RemoveUnlockWithPin: 14,
} as const;

export interface RawPolicy {
  organizationId: string;
  type: number;
  enabled: boolean;
  data?: Record<string, any> | string | null;
}

interface RawOrgMembership {
  id: string;
  name?: string;
  type?: number; // 0 owner, 1 admin, 2 user, 3 manager, 4 custom
  status?: number; // 2 confirmed
  enabled?: boolean;
  usePolicies?: boolean;
}

export interface EffectivePolicy {
  /** organization names, for "set by …" notes */
  by: Record<string, string>;
  generator?: {
    type?: "password" | "passphrase";
    minLength: number;
    upper: boolean;
    lower: boolean;
    digits: boolean;
    symbols: boolean;
    minDigits: number;
    minSymbols: number;
    minWords: number;
    capitalize: boolean;
    includeNumber: boolean;
  };
  /** new items must belong to an organization */
  personalOwnership?: boolean;
  disableSend?: boolean;
  /** Sends can't hide the sender's email */
  sendShowEmail?: boolean;
  /** longest lock timeout, in minutes; what happens when it runs out */
  maxTimeout?: { minutes: number; action: "lock" | "logout" | null };
  disableExport?: boolean;
  removePin?: boolean;
}

const OWNER = 0;
const ADMIN = 1;
/** Policies that also bind admins (owners too, unless listed in OWNER_EXEMPT). */
const BINDS_ADMINS = new Set<number>([PolicyType.PasswordGenerator, PolicyType.MaximumVaultTimeout, PolicyType.RemoveUnlockWithPin]);
const OWNER_EXEMPT = new Set<number>([PolicyType.MaximumVaultTimeout]);

const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : Number(v) || 0);

export function effectivePolicy(policies: RawPolicy[], orgs: RawOrgMembership[]): EffectivePolicy {
  const eff: EffectivePolicy = { by: {} };
  for (const p of policies ?? []) {
    if (!p?.enabled) continue;
    const org = orgs.find((o) => o.id === p.organizationId);
    if (!org || org.enabled === false || org.usePolicies === false || (org.status ?? 2) !== 2) continue;
    const role = org.type ?? 2;
    if ((role === OWNER || role === ADMIN) && !BINDS_ADMINS.has(p.type)) continue;
    if (role === OWNER && OWNER_EXEMPT.has(p.type)) continue;
    let d: Record<string, any> = {};
    try {
      d = (typeof p.data === "string" ? JSON.parse(p.data) : p.data) ?? {};
    } catch {}
    const note = () => (eff.by[p.type] = org.name ?? "your organization");
    switch (p.type) {
      case PolicyType.PasswordGenerator: {
        const g = (eff.generator ??= { minLength: 0, upper: false, lower: false, digits: false, symbols: false, minDigits: 0, minSymbols: 0, minWords: 0, capitalize: false, includeNumber: false });
        const type = d.overridePasswordType ?? d.defaultType;
        if (type === "password" || type === "passphrase") g.type ??= type;
        g.minLength = Math.max(g.minLength, num(d.minLength));
        g.upper ||= !!d.useUpper;
        g.lower ||= !!d.useLower;
        g.digits ||= !!d.useNumbers;
        g.symbols ||= !!d.useSpecial;
        g.minDigits = Math.max(g.minDigits, num(d.minNumbers));
        g.minSymbols = Math.max(g.minSymbols, num(d.minSpecial));
        g.minWords = Math.max(g.minWords, num(d.minNumberWords));
        g.capitalize ||= !!d.capitalize;
        g.includeNumber ||= !!d.includeNumber;
        note();
        break;
      }
      case PolicyType.PersonalOwnership:
        eff.personalOwnership = true;
        note();
        break;
      case PolicyType.DisableSend:
        eff.disableSend = true;
        note();
        break;
      case PolicyType.SendOptions:
        if (d.disableHideEmail) (eff.sendShowEmail = true), note();
        break;
      case PolicyType.MaximumVaultTimeout: {
        const minutes = num(d.minutes);
        if (minutes <= 0) break;
        const action = d.action === "logOut" ? "logout" : d.action === "lock" ? "lock" : null;
        if (!eff.maxTimeout || minutes < eff.maxTimeout.minutes) eff.maxTimeout = { minutes, action: action ?? eff.maxTimeout?.action ?? null };
        else if (action === "logout") eff.maxTimeout.action = "logout";
        note();
        break;
      }
      case PolicyType.DisablePersonalVaultExport:
        eff.disableExport = true;
        note();
        break;
      case PolicyType.RemoveUnlockWithPin:
        eff.removePin = true;
        note();
        break;
    }
  }
  return eff;
}

export function policedPassword(o: PasswordOpts, eff: EffectivePolicy | undefined): PasswordOpts {
  const g = eff?.generator;
  if (!g) return o;
  const digits = o.digits || g.digits || g.minDigits > 0;
  const symbols = o.symbols || g.symbols || g.minSymbols > 0;
  return {
    ...o,
    length: Math.max(o.length, g.minLength),
    upper: o.upper || g.upper,
    lower: o.lower || g.lower,
    digits,
    symbols,
    minDigits: digits ? Math.max(o.minDigits, g.minDigits) : o.minDigits,
    minSymbols: symbols ? Math.max(o.minSymbols, g.minSymbols) : o.minSymbols,
  };
}

export function policedPassphrase(o: PassphraseOpts, eff: EffectivePolicy | undefined): PassphraseOpts {
  const g = eff?.generator;
  if (!g) return o;
  return { ...o, words: Math.max(o.words, g.minWords), capitalize: o.capitalize || g.capitalize, includeNumber: o.includeNumber || g.includeNumber };
}

/** The lock timeout in effect: a policy caps it (minutes; -1 "on restart" and -2 "never" count
 * as unlimited), and may say what happens when it runs out. */
export function policedTimeout(minutes: number, action: "lock" | "logout", eff: EffectivePolicy | undefined): { minutes: number; action: "lock" | "logout" } {
  const m = eff?.maxTimeout;
  if (!m) return { minutes, action };
  return { minutes: minutes < 0 || minutes > m.minutes ? m.minutes : minutes, action: m.action ?? action };
}
