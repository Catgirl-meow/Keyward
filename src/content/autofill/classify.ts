// Field classification. Looks only at one scope (the focused field's form, or a small ancestor),
// never the whole page, unless an explicit fill asks for every scope in the frame.
// Signal order: autocomplete token > input type > words from name/id/placeholder/aria/label/
// nearby text (English + Russian) > structure (the field before the password is the username,
// new/confirm pairs, split one-digit OTP boxes).

export type CardKind = "cc-name" | "cc-number" | "cc-exp" | "cc-exp-month" | "cc-exp-year" | "cc-csc" | "cc-type";
export type IdKind =
  | "id-title" | "id-first" | "id-middle" | "id-last" | "id-full" | "id-address1" | "id-address2" | "id-address3"
  | "id-city" | "id-state" | "id-postal" | "id-country" | "id-company" | "id-phone" | "id-email" | "id-username";
export type Kind =
  | "username" | "email" | "phone" | "password" | "password-current" | "password-new" | "otp"
  | CardKind | IdKind | "search" | "skip" | "text";

export type Fillable = HTMLInputElement | HTMLSelectElement;

export interface Field {
  el: Fillable;
  kind: Kind;
  hint: string;
  /** the kind came from an autocomplete token (a strong signal) */
  ac?: boolean;
}

export type ScopeType = "login" | "signup" | "change" | "username" | "otp" | "card" | "identity" | "none";

export interface Analysis {
  root: Node;
  fields: Field[];
  type: ScopeType;
  username: HTMLInputElement | null;
  /** the existing-password field of a login or change form */
  password: HTMLInputElement | null;
  /** new password and its confirmation(s) */
  newPasswords: HTMLInputElement[];
  /** one field, or the boxes of a split code in order */
  otp: HTMLInputElement[];
  card: Partial<Record<CardKind, Fillable[]>>;
  identity: Partial<Record<IdKind, Fillable>>;
}

const SKIP_TYPES = /^(hidden|submit|button|reset|image|file|checkbox|radio|range|color|date|datetime-local|time|week)$/;

// ---------------------------------------------------------------- shadow roots
const shadowOf = (el: Element): ShadowRoot | null => {
  if (el.shadowRoot) return el.shadowRoot;
  if (!el.localName.includes("-")) return null; // closed roots in the wild sit on custom elements
  try {
    return __CHROMIUM__ ? chrome.dom.openOrClosedShadowRoot(el as HTMLElement) ?? null : ((el as any).openOrClosedShadowRoot as ShadowRoot | null) ?? null;
  } catch {
    return null;
  }
};

/** The real focused element, through (open or closed) shadow roots. */
export function deepActive(doc: Document = document): Element | null {
  let a: Element | null = doc.activeElement;
  for (let i = 0; a && i < 20; i++) {
    const r = shadowOf(a);
    if (!r?.activeElement) break;
    a = r.activeElement;
  }
  return a;
}

/** Parent across shadow boundaries. */
const up = (n: Node): Element | null => {
  const p = n.parentNode;
  if (!p) return null;
  if (p instanceof ShadowRoot) return p.host;
  return p instanceof Element ? p : null;
};

/** All inputs/selects under `root`, descending into shadow roots. */
export function collectInputs(root: ParentNode, out: Fillable[] = [], limit = 4000): Fillable[] {
  const all = root.querySelectorAll("*");
  if (all.length > 6000) {
    // Huge documents: light DOM only (shadow roots are found through the focused element instead).
    for (const el of Array.from(root.querySelectorAll("input,select")).slice(0, limit)) out.push(el as Fillable);
    return out;
  }
  for (let i = 0; i < all.length && out.length < limit; i++) {
    const el = all[i];
    if (el instanceof HTMLInputElement || el instanceof HTMLSelectElement) out.push(el);
    const sr = shadowOf(el);
    if (sr) collectInputs(sr, out, limit);
  }
  return out;
}

export function isFillable(el: unknown): el is Fillable {
  if (el instanceof HTMLSelectElement) return !el.disabled;
  return el instanceof HTMLInputElement && !SKIP_TYPES.test(el.type) && !el.disabled;
}

export function isVisible(el: Element): boolean {
  if (!(el as HTMLElement).isConnected) return false;
  const r = el.getBoundingClientRect();
  if (r.width < 2 || r.height < 2) return false;
  // Honeypots are often pushed far off-screen rather than hidden.
  if (r.right < -500 || r.bottom < -500 || r.left > 20000) return false;
  const cv = (el as any).checkVisibility;
  return cv ? cv.call(el, { visibilityProperty: true, contentVisibilityAuto: true }) : getComputedStyle(el).visibility !== "hidden";
}

// ---------------------------------------------------------------- hints
const norm = (s: string) =>
  s
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .replace(/[_\-.:\[\]()*#/\\|"'«»,]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();

const textOf = (n: Node | null | undefined, max = 80) => {
  const t = (n?.textContent ?? "").replace(/\s+/g, " ").trim();
  return t.length <= max ? t : "";
};

function labelText(el: Fillable): string {
  const parts: string[] = [];
  for (const l of Array.from(el.labels ?? [])) parts.push(textOf(l, 120));
  const by = el.getAttribute("aria-labelledby");
  if (by) {
    const root = el.getRootNode() as Document | ShadowRoot;
    for (const id of by.split(/\s+/)) parts.push(textOf(root.getElementById?.(id)));
  }
  if (!parts.join("").trim()) {
    // Unlinked labels: <div>Email</div><input>, or text right before the field.
    let prev = el.previousElementSibling;
    for (let i = 0; prev && i < 2; i++, prev = prev.previousElementSibling) {
      if (prev instanceof HTMLInputElement || prev instanceof HTMLSelectElement) break;
      const t = textOf(prev, 60);
      if (t) {
        parts.push(t);
        break;
      }
    }
    if (!parts.join("").trim()) {
      const p = el.parentElement;
      if (p && p.querySelectorAll("input,select").length === 1) parts.push(textOf(p, 60));
    }
  }
  return parts.join(" ");
}

export function hintOf(el: Fillable): string {
  const a = (n: string) => el.getAttribute(n) ?? "";
  return norm(
    [a("name"), el.id, a("placeholder"), a("aria-label"), a("title"), a("data-testid"), a("data-test"), a("data-qa"), labelText(el)]
      .filter(Boolean)
      .join(" "),
  );
}

// ---------------------------------------------------------------- word lists
const RX = {
  search: /\b(search|query|keywords?|lookup|find|filter)\b|^(q|s)$|поиск|найти|искать/,
  captcha: /captcha|капч/,
  // Recovery / backup codes are one-off secrets the vault doesn't hold: never put a TOTP there.
  recoveryCode: /\b(recovery|backup|scratch|rescue|emergency)[\s_-]?(code|key|token)|резервн[а-яё]* код|код[а-яё]* восстановлен/,
  newsletter: /newsletter|subscri|рассылк|подписк/,
  notOtp: /\b(postal|zip|post ?code|postcode|promo|coupon|voucher|discount|gift|country|area|referral|invite|invitation|captcha|cvv|cvc|csc|card)\b|индекс|промо|купон|карт/,
  /** Words that make a code box a code box even when it says "password" ("one-time password"). */
  otpStrong: /\b(otp|totp|hotp|one ?time|onetime|2fa|mfa|tfa|2 ?step|two ?(step|factor)|second ?factor|sms)\b|одноразов/,
  otp: /\b(otp|totp|hotp|2fa|mfa|tfa|one ?time|onetime|passcode|verification|verify|verif|authenticat\w*|auth ?code|security ?code|2 ?step|two ?(step|factor)|second ?factor|sms ?code|token|pin ?code|confirmation ?code|code|digits?)\b|код|одноразов/,
  password: /\b(pass(word|wd|phrase)?|pwd|pw)\b|password|пароль/,
  pwNew: /\b(new|create|choose|set|confirm|confirmation|repeat|retype|re ?type|re ?enter|again|verify|second|password ?2|pass ?2|pwd ?2)\b|нов|повтор|ещё раз|еще раз|подтвер|придума/,
  pwCurrent: /\b(current|old|existing|previous)\b|текущ|стар|прежн/,
  email: /\be ?mail|почт|e-?mail/,
  phone: /\b(phone|tel|telephone|mobile|cell|msisdn)\b|телефон/,
  username: /\b(user|login|logon|log ?in|sign ?in|signin|account|acct|member|nick|handle|uid|identifier|e ?mail|mail|phone|mobile)|логин|пользоват|почт|телефон|учетн|учётн/,
  ccNumber: /\b(card ?(number|no|num|nr)|cc ?(num|number|no)|ccnum|cardnum|cardnumber|credit ?card|debit ?card|pan)\b|номер (банковской )?карт/,
  ccName: /\b(name ?on ?card|card ?holder|cardholder|holder ?name|cc ?name|ccname|card ?name|nameoncard)\b|владел|имя на карт|держател/,
  ccExpMonth: /\b(exp\w* ?(month|mo|mm)|cc ?exp ?month|ccmonth|card ?month|month|mm)\b|месяц/,
  ccExpYear: /\b(exp\w* ?(year|yr|yy|yyyy)|cc ?exp ?year|ccyear|card ?year|year|yy|yyyy)\b|(^|\s)год/,
  ccExp: /\b(exp|expiry|expiration|expires|exp ?date|valid ?(thru|through|until|to)|mm ?yy|mm ?yyyy|cc ?exp)\b|срок/,
  ccCsc: /\b(cvv|cvc|csc|cvn|cid|cvv2|cvc2|security ?code|card ?code|card ?verification|verification ?(value|number))\b|код безопасности/,
  ccType: /\b(card ?type|cc ?type|card ?brand)\b/,
  idTitle: /\b(salutation|honorific|prefix|title)\b|обращен/,
  idFirst: /\b(first ?name|given ?name|fname|forename|first)\b|(^|\s)имя(\s|$)/,
  idMiddle: /\b(middle ?name|mname|middle|patronymic)\b|отчеств/,
  idLast: /\b(last ?name|family ?name|surname|lname|last)\b|фамил/,
  idFull: /\b(full ?name|fullname|your ?name|name)\b|фио/,
  idAddress3: /\b(address ?(line)? ?3|addr ?3|address3)\b/,
  idAddress2: /\b(address ?(line)? ?2|addr ?2|address2|apt|apartment|suite|unit|flat)\b|кварт|корпус/,
  idAddress1: /\b(address ?(line)? ?1|addr ?1|address1|street|address|addr)\b|улиц|адрес/,
  idCity: /\b(city|town|locality|suburb|municipality)\b|город|населен/,
  idState: /\b(state|province|region|county|prefecture)\b|област|регион|край/,
  idPostal: /\b(zip|zipcode|postal|post ?code|postcode)\b|индекс/,
  idCountry: /\b(country|nation)\b|стран/,
  idCompany: /\b(company|organi[sz]ation|business|employer|firm)\b|организац|компани/,
  submitNext: /\b(next|continue|sign ?in|log ?in|login|proceed|submit|verify|confirm)\b|далее|войти|продолж|вход|подтверд/,
};

const AC: Record<string, Kind> = {
  username: "username",
  email: "email",
  "current-password": "password-current",
  "new-password": "password-new",
  "one-time-code": "otp",
  "cc-name": "cc-name",
  "cc-given-name": "cc-name",
  "cc-number": "cc-number",
  "cc-exp": "cc-exp",
  "cc-exp-month": "cc-exp-month",
  "cc-exp-year": "cc-exp-year",
  "cc-csc": "cc-csc",
  "cc-type": "cc-type",
  name: "id-full",
  "honorific-prefix": "id-title",
  "given-name": "id-first",
  "additional-name": "id-middle",
  "family-name": "id-last",
  organization: "id-company",
  "street-address": "id-address1",
  "address-line1": "id-address1",
  "address-line2": "id-address2",
  "address-line3": "id-address3",
  "address-level2": "id-city",
  "address-level1": "id-state",
  "postal-code": "id-postal",
  country: "id-country",
  "country-name": "id-country",
  tel: "phone",
  "tel-national": "phone",
};

const isCard = (k: Kind): k is CardKind => k.startsWith("cc-");
const isId = (k: Kind): k is IdKind => k.startsWith("id-");

/** Per-field kind from its own attributes only. Structure is applied in analyze(). */
export function fieldKind(el: Fillable, hint = hintOf(el)): Kind {
  const ac = (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/);
  for (const t of ac) if (AC[t]) return AC[t];
  if (el instanceof HTMLSelectElement) return selectKind(el, hint);
  const type = el.type;
  const max = el.maxLength > 0 ? el.maxLength : 0;
  const otpish = !RX.notOtp.test(hint) && (max === 0 || max <= 12) && RX.otp.test(hint);
  if (type === "password") {
    // A code box drawn as a password field is still a code box (never put the password there).
    if (otpish && (!RX.password.test(hint) || RX.otpStrong.test(hint))) return "otp";
    // An unlabeled short numeric box is a code even when drawn as a password field.
    if (max >= 4 && max <= 8 && (el.inputMode === "numeric" || /\d/.test(el.pattern)) && !RX.password.test(hint) && !RX.pwCurrent.test(hint)) return "otp";
    if (RX.pwCurrent.test(hint)) return "password-current";
    if (RX.pwNew.test(hint)) return "password-new";
    return "password";
  }
  if (type === "search" || el.getAttribute("role") === "searchbox" || RX.search.test(hint)) return "search";
  if (RX.captcha.test(hint) || RX.recoveryCode.test(hint)) return "skip";
  if (type === "email") return RX.newsletter.test(hint) ? "skip" : "email";
  if (RX.password.test(hint) && !otpish && !RX.email.test(hint)) return "password"; // "show password" toggled to text
  if (RX.ccNumber.test(hint)) return "cc-number";
  if (RX.ccCsc.test(hint)) return "cc-csc";
  if (RX.ccName.test(hint)) return "cc-name";
  if (otpish) return "otp";
  // An unlabeled short numeric box (4–8 digits) is a code, not a username.
  if (max >= 4 && max <= 8 && (el.inputMode === "numeric" || /\d/.test(el.pattern) || type === "number") && !RX.username.test(hint) && !RX.idPostal.test(hint)) return "otp";
  if (RX.ccExpMonth.test(hint) && /exp|card|cc/.test(hint)) return "cc-exp-month";
  if (RX.ccExpYear.test(hint) && /exp|card|cc/.test(hint)) return "cc-exp-year";
  if (RX.ccExp.test(hint)) return "cc-exp";
  if (RX.email.test(hint)) return RX.newsletter.test(hint) ? "skip" : "email";
  if (type === "tel" || RX.phone.test(hint)) return "phone";
  if (RX.username.test(hint)) return RX.newsletter.test(hint) ? "skip" : "username";
  if (RX.idAddress3.test(hint)) return "id-address3";
  if (RX.idAddress2.test(hint)) return "id-address2";
  if (RX.idAddress1.test(hint)) return "id-address1";
  if (RX.idPostal.test(hint)) return "id-postal";
  if (RX.idCity.test(hint)) return "id-city";
  if (RX.idState.test(hint)) return "id-state";
  if (RX.idCountry.test(hint)) return "id-country";
  if (RX.idCompany.test(hint)) return "id-company";
  if (RX.idFirst.test(hint)) return "id-first";
  if (RX.idMiddle.test(hint)) return "id-middle";
  if (RX.idLast.test(hint)) return "id-last";
  if (RX.idTitle.test(hint)) return "id-title";
  if (RX.idFull.test(hint)) return "id-full";
  return "text";
}

function selectKind(el: HTMLSelectElement, hint: string): Kind {
  const opts = Array.from(el.options).map((o) => (o.value || o.text).trim().toLowerCase());
  const nums = opts.map(Number).filter((n) => Number.isFinite(n) && n > 0);
  const y = new Date().getFullYear();
  if (RX.ccExpMonth.test(hint) || (nums.length >= 12 && nums.every((n) => n <= 12))) return /exp|card|cc|month/.test(hint) ? "cc-exp-month" : "text";
  if (RX.ccExpYear.test(hint) || (nums.length >= 5 && nums.every((n) => (n >= y && n <= y + 30) || (n >= y % 100 && n <= (y % 100) + 30))))
    return /exp|card|cc|year/.test(hint) ? "cc-exp-year" : "text";
  if (RX.ccType.test(hint)) return "cc-type";
  if (RX.idCountry.test(hint)) return "id-country";
  if (RX.idState.test(hint)) return "id-state";
  if (RX.idTitle.test(hint)) return "id-title";
  return "skip";
}

// ---------------------------------------------------------------- scopes
const BUTTONISH = 'button,input[type=submit],input[type=button],[role=button]';

/** The form of a field, or the smallest ancestor that also holds a button (≤6 levels, ≤300 elements). */
export function scopeOf(el: Element): Node {
  const f = (el as HTMLInputElement).form;
  if (f) return f;
  let cur: Element = el;
  for (let i = 0; i < 6; i++) {
    const p = up(cur);
    if (!p || p === document.documentElement || p === document.body) break;
    if (p.getElementsByTagName("*").length > 300) break;
    cur = p;
    if (p.querySelector(BUTTONISH)) {
      // One more level when the password sits just outside (username and password in sibling boxes).
      const pp = up(p);
      if (!p.querySelector("input[type=password]") && pp && pp !== document.body && pp.getElementsByTagName("*").length <= 300 && pp.querySelector("input[type=password]")) cur = pp;
      break;
    }
  }
  return cur === el ? up(el) ?? el : cur;
}

function fieldsIn(root: Node): Fillable[] {
  const els = collectInputs(root as ParentNode).filter(isFillable);
  if (root instanceof HTMLFormElement) {
    // Fields outside the form that join it with form="id".
    for (const x of Array.from(root.elements)) if (isFillable(x) && !els.includes(x)) els.push(x);
  }
  return els;
}

const empty = (): Analysis => ({ root: document, fields: [], type: "none", username: null, password: null, newPasswords: [], otp: [], card: {}, identity: {} });

export function analyze(root: Node, opts: { visibleOnly?: boolean } = {}): Analysis {
  const a = empty();
  a.root = root;
  const active = deepActive();
  const els = fieldsIn(root).filter((e) => !opts.visibleOnly || e === active || isVisible(e));
  a.fields = els.map((el) => {
    const hint = hintOf(el);
    const ac = (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/).some((t) => t in AC);
    return { el, hint, kind: fieldKind(el, hint), ac };
  });
  const F = a.fields;
  const inputs = F.filter((f) => f.el instanceof HTMLInputElement) as (Field & { el: HTMLInputElement })[];

  // Split one-digit OTP boxes: 4–8 consecutive maxlength=1 inputs.
  const boxes = inputs.filter((f) => f.el.maxLength === 1 && f.kind !== "password-new");
  if (boxes.length >= 4 && boxes.length <= 8) {
    for (const b of boxes) b.kind = "otp";
  }

  // Passwords and their roles.
  const pws = inputs.filter((f) => f.kind === "password" || f.kind === "password-current" || f.kind === "password-new");
  if (pws.length) {
    const cur = pws.filter((f) => f.kind === "password-current");
    const neu = pws.filter((f) => f.kind === "password-new");
    const plain = pws.filter((f) => f.kind === "password");
    if (pws.length === 1) {
      if (neu.length) a.newPasswords = [neu[0].el];
      else a.password = pws[0].el;
    } else if (cur.length) {
      a.password = cur[0].el;
      a.newPasswords = pws.filter((f) => f !== cur[0]).map((f) => f.el);
    } else if (pws.length >= 3) {
      a.password = pws[0].el;
      a.newPasswords = pws.slice(1).map((f) => f.el);
    } else if (neu.length || plain.length === 2) {
      // Two passwords with no "current" hint: new + confirm (sign-up).
      a.newPasswords = pws.map((f) => f.el);
    }
    for (const f of pws) f.kind = f.el === a.password ? (cur.length || a.newPasswords.length ? "password-current" : "password") : "password-new";
    // Username: the nearest login-looking field before the first password, else the nearest
    // plain text field right before it.
    const first = F.indexOf(pws[0]);
    let loose: Field | null = null;
    for (let i = first - 1; i >= 0 && i >= first - 6; i--) {
      const f = F[i];
      if (!(f.el instanceof HTMLInputElement)) continue;
      if (f.kind === "username" || f.kind === "email" || f.kind === "phone" || f.kind === "id-username") {
        a.username = f.el;
        f.kind = "username";
        break;
      }
      if (f.kind === "search" || f.kind === "otp" || f.kind === "skip" || isCard(f.kind)) continue;
      if (!loose && i >= first - 2) loose = f;
    }
    if (!a.username && loose) {
      a.username = loose.el as HTMLInputElement;
      loose.kind = "username";
    }
    // A username-hinted field after the password (rare layouts).
    if (!a.username) {
      const u = F.find((f) => f.kind === "username" && f.el instanceof HTMLInputElement);
      if (u) a.username = u.el as HTMLInputElement;
    }
  }

  a.otp = inputs.filter((f) => f.kind === "otp").map((f) => f.el);

  // Cards: only when there is a card number, or two other strong card fields.
  const cardFields = F.filter((f) => isCard(f.kind));
  // (Payment iframes hold one field each, marked with autocomplete="cc-…".)
  if (cardFields.some((f) => f.kind === "cc-number" || f.ac) || cardFields.filter((f) => f.kind !== "cc-name").length >= 2) {
    for (const f of cardFields) (a.card[f.kind as CardKind] ??= []).push(f.el);
    // A bare "security code" next to a card number is the CSC, not an OTP.
    if (a.card["cc-number"] && a.otp.length === 1 && /security|code/.test(F.find((f) => f.el === a.otp[0])!.hint)) {
      (a.card["cc-csc"] ??= []).push(a.otp[0]);
      a.otp = [];
    }
  }

  // Identity: only with two or more identity-ish fields and no password.
  if (!pws.length) {
    const idFields = F.filter((f) => isId(f.kind) || ((f.kind === "email" || f.kind === "phone" || f.kind === "username") && !a.otp.includes(f.el as HTMLInputElement)));
    if (idFields.filter((f) => isId(f.kind)).length >= 2) {
      for (const f of idFields) {
        const k: IdKind = f.kind === "email" ? "id-email" : f.kind === "phone" ? "id-phone" : f.kind === "username" ? "id-username" : (f.kind as IdKind);
        a.identity[k] ??= f.el;
      }
    }
  }

  // Scope type.
  if (a.password && a.newPasswords.length) a.type = "change";
  else if (a.newPasswords.length) a.type = "signup";
  else if (a.password) a.type = "login";
  else if (a.otp.length) a.type = "otp";
  else if (Object.keys(a.card).length) a.type = "card";
  else if (Object.keys(a.identity).length) a.type = "identity";
  else {
    // A username-only first step: one or two text fields, with a login hint or a "Next" button.
    const text = inputs.filter((f) => f.kind === "username" || f.kind === "email" || f.kind === "phone" || f.kind === "text");
    const strong = text.find((f) => f.kind === "username" || f.kind === "email");
    if (text.length && text.length <= 2) {
      const btn = root instanceof Element || root instanceof Document ? buttonText(root as ParentNode) : "";
      if (RX.newsletter.test(btn + " " + text.map((t) => t.hint).join(" "))) return a;
      const pick = strong ?? (RX.submitNext.test(btn) && text.length === 1 ? text[0] : undefined);
      if (pick && (strong || RX.submitNext.test(btn))) {
        a.username = pick.el;
        pick.kind = "username";
        a.type = "username";
      }
    }
  }
  return a;
}

function buttonText(root: ParentNode): string {
  const b = root.querySelectorAll(BUTTONISH);
  let s = "";
  for (let i = 0; i < b.length && i < 6; i++) s += " " + ((b[i] as HTMLInputElement).value || b[i].textContent || b[i].getAttribute("aria-label") || "");
  return norm(s);
}

/** Every scope in the frame (explicit fills). Forms first, then loose fields grouped by ancestor. */
export function allScopes(): Analysis[] {
  const inputs = collectInputs(document).filter((e) => isFillable(e) && isVisible(e));
  const roots: Node[] = [];
  for (const el of inputs) {
    const s = scopeOf(el);
    if (!roots.includes(s)) roots.push(s);
  }
  return roots.map((r) => analyze(r, { visibleOnly: true })).filter((a) => a.type !== "none" || a.fields.some((f) => f.kind !== "search" && f.kind !== "skip"));
}

/** Kind of one field in the context of its scope. */
export function kindInScope(el: Fillable, a: Analysis): Kind {
  if (el === a.username) return "username";
  if (el === a.password) return "password";
  if (a.newPasswords.includes(el as HTMLInputElement)) return "password-new";
  if (a.otp.includes(el as HTMLInputElement)) return "otp";
  for (const [k, v] of Object.entries(a.card)) if (v?.includes(el)) return k as CardKind;
  for (const [k, v] of Object.entries(a.identity)) if (v === el) return k as IdKind;
  return a.fields.find((f) => f.el === el)?.kind ?? "text";
}

/** What a field is for, for the menu and the background. */
export type Purpose = "login" | "newPassword" | "otp" | "card" | "identity" | null;
export function purposeOf(k: Kind): Purpose {
  if (k === "username" || k === "password" || k === "password-current") return "login";
  if (k === "password-new") return "newPassword";
  if (k === "otp") return "otp";
  if (isCard(k)) return "card";
  if (isId(k)) return "identity";
  return null;
}
