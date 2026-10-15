// Filling. Values are set through the element's native setter from the content-script world
// (page-side value trackers such as React's never see the write), followed by the events the
// frameworks listen to: keydown, input, keyup, change.
import type { Analysis, CardKind, Fillable, IdKind } from "./classify.ts";

export interface CardValues {
  cardholderName: string | null;
  brand: string | null;
  number: string | null;
  expMonth: string | null;
  expYear: string | null;
  code: string | null;
}
export type IdentityValues = Record<string, string | null>;

export interface FillPlan {
  username?: string | null;
  password?: string | null;
  /** a generated password for new-password fields */
  newPassword?: string | null;
  totp?: string | null;
  card?: CardValues | null;
  identity?: IdentityValues | null;
  /** custom text fields of the item, matched by name */
  fields?: { name: string; value: string }[];
  /** only fill fields that are empty (multi-step continuation) */
  onlyEmpty?: boolean;
}

export interface FillResult {
  filled: string[];
  otpField: boolean;
}

const fire = (el: Element, e: Event) => el.dispatchEvent(e);
const key = (type: string) => new KeyboardEvent(type, { bubbles: true, cancelable: true, composed: true, key: "Unidentified" });

function flash(el: Element) {
  try {
    el.animate([{ boxShadow: "0 0 0 2px rgba(124,77,255,.9)" }, { boxShadow: "0 0 0 2px rgba(124,77,255,0)" }], { duration: 700, easing: "ease-out" });
  } catch {}
}

/** Values Keyward put into fields, so a submit of exactly those doesn't ask to save them. */
export const filledByUs = new WeakMap<Element, string>();

export function setInput(el: HTMLInputElement, value: string, remember = true): boolean {
  el.focus({ preventScroll: true });
  if (el.readOnly || el.disabled) return false; // some sites drop readonly on focus; checked after it
  fire(el, key("keydown"));
  fire(el, key("keypress"));
  el.value = value;
  fire(el, new InputEvent("input", { bubbles: true, composed: true, inputType: "insertReplacementText", data: value }));
  fire(el, key("keyup"));
  fire(el, new Event("change", { bubbles: true }));
  flash(el);
  if (remember) filledByUs.set(el, el.value);
  return el.value === value || (el.maxLength > 0 && el.value === value.slice(0, el.maxLength));
}

const normOpt = (s: string) => s.trim().toLowerCase().replace(/[\s.]+/g, " ");

export function setSelect(el: HTMLSelectElement, candidates: string[]): boolean {
  const want = candidates.filter(Boolean).map(normOpt);
  const opts = Array.from(el.options);
  let hit = opts.find((o) => want.includes(normOpt(o.value)) || want.includes(normOpt(o.text)));
  hit ??= opts.find((o) => want.some((w) => w.length > 2 && (normOpt(o.text).startsWith(w) || normOpt(o.value).startsWith(w))));
  if (!hit) return false;
  el.focus({ preventScroll: true });
  el.value = hit.value;
  fire(el, new Event("input", { bubbles: true, composed: true }));
  fire(el, new Event("change", { bubbles: true }));
  flash(el);
  return true;
}

function set(el: Fillable, value: string | null | undefined, onlyEmpty?: boolean, alts?: string[]): boolean {
  if (value == null || value === "") return false;
  if (el instanceof HTMLSelectElement) return setSelect(el, [value, ...(alts ?? [])]);
  if (onlyEmpty && el.value) return false;
  return setInput(el, value);
}

/** Fill a code into one field or split one-digit boxes. */
function fillOtp(boxes: HTMLInputElement[], code: string): boolean {
  if (boxes.length === 1) return setInput(boxes[0], code);
  let ok = true;
  boxes.forEach((b, i) => (ok = setInput(b, code[i] ?? "") && ok));
  return ok;
}

// ---------------------------------------------------------------- cards
const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];

function expParts(c: CardValues) {
  const m = Number(c.expMonth) || 0;
  let y = (c.expYear ?? "").trim();
  if (/^\d{2}$/.test(y)) y = "20" + y;
  return { m, mm: m ? String(m).padStart(2, "0") : "", yyyy: y, yy: y.slice(-2) };
}

function fillCard(a: Analysis, c: CardValues, filled: string[], onlyEmpty?: boolean) {
  const e = expParts(c);
  const one = (k: CardKind) => a.card[k]?.[0];
  const num = a.card["cc-number"];
  if (num?.length && c.number) {
    const digits = c.number.replace(/\D/g, "");
    if (num.length > 1) {
      // Split card number (four boxes of four).
      let pos = 0;
      for (const el of num) {
        const len = (el as HTMLInputElement).maxLength > 0 ? (el as HTMLInputElement).maxLength : 4;
        set(el, digits.slice(pos, pos + len), onlyEmpty);
        pos += len;
      }
      filled.push("cc-number");
    } else if (set(num[0], digits, onlyEmpty)) filled.push("cc-number");
  }
  const name = one("cc-name");
  if (name && set(name, c.cardholderName, onlyEmpty)) filled.push("cc-name");
  const month = one("cc-exp-month");
  if (month && e.m) {
    const asText = month instanceof HTMLInputElement && (month.maxLength === 1 || /^m$/i.test(month.placeholder)) ? String(e.m) : e.mm;
    if (set(month, asText, onlyEmpty, [String(e.m), e.mm, MONTHS[e.m - 1], MONTHS[e.m - 1].slice(0, 3), `${e.mm} - ${MONTHS[e.m - 1]}`])) filled.push("cc-exp-month");
  }
  const year = one("cc-exp-year");
  if (year && e.yyyy) {
    const two = year instanceof HTMLInputElement && (year.maxLength === 2 || /^yy$/i.test(year.placeholder.trim()));
    if (set(year, two ? e.yy : e.yyyy, onlyEmpty, [e.yyyy, e.yy])) filled.push("cc-exp-year");
  }
  const exp = one("cc-exp");
  if (exp && e.mm && e.yyyy && exp instanceof HTMLInputElement) {
    const ph = (exp.placeholder || exp.getAttribute("aria-label") || "").toLowerCase();
    const m = /mm\s*([^a-z0-9]*)\s*y/.exec(ph);
    const sep = m ? m[1].trim() : exp.maxLength === 4 ? "" : "/";
    const long = /yyyy/.test(ph) || (!/yy/.test(ph) && exp.maxLength >= 7);
    if (set(exp, `${e.mm}${sep}${long ? e.yyyy : e.yy}`, onlyEmpty)) filled.push("cc-exp");
  }
  const csc = one("cc-csc");
  if (csc && set(csc, c.code, onlyEmpty)) filled.push("cc-csc");
  const type = one("cc-type");
  if (type && c.brand) set(type, c.brand, onlyEmpty, [c.brand === "Amex" ? "American Express" : c.brand, c.brand === "Mastercard" ? "MasterCard" : c.brand]);
}

// ---------------------------------------------------------------- identities
let regionNames: Intl.DisplayNames | null = null;
function countryAlts(v: string): string[] {
  if (!/^[A-Za-z]{2}$/.test(v)) return [v];
  try {
    regionNames ??= new Intl.DisplayNames(["en"], { type: "region" });
    return [v, v.toUpperCase(), regionNames.of(v.toUpperCase()) ?? v];
  } catch {
    return [v];
  }
}

function fillIdentity(a: Analysis, id: IdentityValues, filled: string[], onlyEmpty?: boolean) {
  const full = [id.firstName, id.middleName, id.lastName].filter(Boolean).join(" ");
  const map: [IdKind, string | null | undefined, string[]?][] = [
    ["id-title", id.title],
    ["id-first", id.firstName],
    ["id-middle", id.middleName],
    ["id-last", id.lastName],
    ["id-full", full],
    ["id-address1", id.address1],
    ["id-address2", id.address2],
    ["id-address3", id.address3],
    ["id-city", id.city],
    ["id-state", id.state],
    ["id-postal", id.postalCode],
    ["id-country", id.country, id.country ? countryAlts(id.country) : []],
    ["id-company", id.company],
    ["id-phone", id.phone],
    ["id-email", id.email],
    ["id-username", id.username],
  ];
  for (const [k, v, alts] of map) {
    const el = a.identity[k];
    if (el && set(el, v, onlyEmpty, alts)) filled.push(k);
  }
}

// ---------------------------------------------------------------- custom fields
function fillCustom(a: Analysis, fields: { name: string; value: string }[], filled: string[]) {
  const used = new Set<Element>([a.username, a.password, ...a.newPasswords, ...a.otp].filter(Boolean) as Element[]);
  for (const f of fields) {
    const n = f.name.trim().toLowerCase();
    if (!n) continue;
    const el = a.fields.find(
      (x) =>
        !used.has(x.el) &&
        [x.el.getAttribute("name"), x.el.id, x.el.getAttribute("aria-label"), x.el.getAttribute("placeholder"), ...Array.from(x.el.labels ?? []).map((l) => l.textContent)]
          .some((s) => (s ?? "").trim().toLowerCase() === n),
    );
    if (el && set(el.el, f.value)) {
      used.add(el.el);
      filled.push(`field:${f.name}`);
    }
  }
}

export function fillScope(a: Analysis, plan: FillPlan, focusAfter?: Element | null): FillResult {
  const filled: string[] = [];
  const oe = plan.onlyEmpty;
  if (plan.username != null && a.username && set(a.username, plan.username, oe)) filled.push("username");
  if (plan.password != null) {
    if (a.password) {
      if (set(a.password, plan.password, oe)) filled.push("password");
    } else if (a.type === "signup" && !plan.newPassword) {
      // Explicit fill into a two-password form: both get the item's password.
      for (const el of a.newPasswords) if (set(el, plan.password, oe)) filled.push("password");
    }
  }
  if (plan.newPassword && a.newPasswords.length) {
    // Not remembered as "ours": submitting a generated password should offer to save it.
    for (const el of a.newPasswords) setInput(el, plan.newPassword, false);
    filled.push("newPassword");
  }
  if (plan.totp && a.otp.length && (!oe || a.otp.every((b) => !b.value)) && fillOtp(a.otp, plan.totp)) filled.push("otp");
  if (plan.card && Object.keys(a.card).length) fillCard(a, plan.card, filled, oe);
  if (plan.identity && Object.keys(a.identity).length) fillIdentity(a, plan.identity, filled, oe);
  if (plan.fields?.length) fillCustom(a, plan.fields, filled);
  // Leave the caret where the user would type next.
  const last = filled.includes("otp") ? a.otp[a.otp.length - 1] : filled.includes("password") ? a.password ?? a.newPasswords[0] : (focusAfter as HTMLElement | null);
  try {
    (last as HTMLElement | null)?.focus({ preventScroll: true });
  } catch {}
  return { filled, otpField: a.otp.length > 0 };
}
