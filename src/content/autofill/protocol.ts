// Messages between the autofill content script and the background. Types only.
import type { Purpose, ScopeType } from "./classify.ts";
import type { FillPlan, FillResult } from "./fill.ts";

export type FillVia = "popup" | "menu" | "hotkey" | "context" | "flow" | "pageload";
export type FillPurpose = "login" | "card" | "identity" | "generate" | "totp";

export interface ScopeInfo {
  type: ScopeType;
  hasUser: boolean;
  hasPw: boolean;
  hasNewPw: boolean;
  hasOtp: boolean;
  emptyPw: boolean;
  emptyOtp: boolean;
  card: boolean;
  identity: boolean;
}

export interface ScanResult {
  url: string;
  top: boolean;
  focused: (ScopeInfo & { purpose: Purpose }) | null;
  scopes: ScopeInfo[];
}

export interface SubmitData {
  url: string;
  type: "login" | "signup" | "change";
  username: string;
  password: string;
  newPassword: string;
}

/** content → background */
export type CsMessage =
  | { kw: "cs"; t: "focus"; type: string; ac: string }
  | ({ kw: "cs"; t: "field"; purpose: Purpose; empty: boolean; webauthn?: boolean } & ScopeInfo)
  | { kw: "cs"; t: "menu"; purpose: Purpose; scope: ScopeType; token: string; webauthn?: boolean }
  | ({ kw: "cs"; t: "step" } & ScopeInfo)
  | { kw: "cs"; t: "submit"; data: SubmitData }
  | { kw: "cs"; t: "submitDone" }
  | { kw: "cs"; t: "pageload" };

export interface FieldReply {
  icon: boolean;
  open: boolean;
}

/** background → content */
export type AfMessage =
  | { kw: "af"; t: "scan" }
  | { kw: "af"; t: "fill"; plan: FillPlan; via: FillVia; purpose: FillPurpose }
  | { kw: "af"; t: "menuClose" }
  /** a passkey autofill request arrived: ask again about the focused field */
  | { kw: "af"; t: "refocus" }
  /** is the inline menu still ours to act on (not hidden, covered or restyled by the page)? */
  | { kw: "af"; t: "menuTrusted" }
  | { kw: "af"; t: "watch"; ms: number }
  | { kw: "af"; t: "savebar"; token: string }
  | { kw: "af"; t: "savebarClose" };

export type AfFillResult = FillResult & { error?: string };
