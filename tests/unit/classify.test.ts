// @vitest-environment happy-dom
// Field classifier against the fixture pages (tests/fixtures/forms) and a few inline forms.
// Layout isn't available here, so scopes are analyzed with visibleOnly: false.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, test } from "vitest";
import { analyze, fieldKind, scopeOf, type Analysis } from "../../src/content/autofill/classify.ts";

const dir = join(process.cwd(), "tests/fixtures/forms/"); // import.meta.url isn't a file URL under happy-dom

beforeAll(() => {
  (globalThis as any).chrome = { dom: { openOrClosedShadowRoot: (e: HTMLElement) => e.shadowRoot } };
});

/** Loads a fixture's markup (scripts dropped) into the document. */
function load(html: string) {
  document.body.innerHTML = html.replace(/<script[\s\S]*?<\/script>/g, "").replace(/^[\s\S]*?<body[^>]*>|<\/body>[\s\S]*$/g, "");
}
const page = (name: string) => load(readFileSync(dir + name, "utf8"));
const $ = <T extends Element = HTMLInputElement>(s: string) => document.querySelector(s) as T;
const scope = (s: string): Analysis => analyze(scopeOf($(s)), { visibleOnly: false });

describe("mailfence (markup of the real pages, saved 2026-10-15)", () => {
  test("login: UserID + Password", () => {
    page("mailfence/login.html");
    const a = scope("#UserID");
    expect(a.type).toBe("login");
    expect(a.username).toBe($("#UserID"));
    expect(a.password).toBe($("#Password"));
  });

  test("2FA: six unnamed one-digit boxes are one code, in order", () => {
    page("mailfence/2fa.html");
    const boxes = Array.from(document.querySelectorAll("#totp-inputs .code-input"));
    const a = scope("#totp-inputs .code-input");
    expect(a.type).toBe("otp");
    expect(a.otp).toEqual(boxes);
    expect(a.username).toBeNull();
    expect(a.password).toBeNull();
  });

  test("2FA: the recovery-code alternative is never a code field", () => {
    page("mailfence/2fa.html");
    expect(fieldKind($("#backup-code"))).toBe("skip");
    expect(scope("#backup-code").otp).not.toContain($("#backup-code"));
  });
});

describe("fixture corpus", () => {
  test("plain login; the search box is not the username", () => {
    page("plain.html");
    const a = scope("#u");
    expect(a.type).toBe("login");
    expect([a.username, a.password]).toEqual([$("#u"), $("#p")]);
    expect(fieldKind($("#search"))).toBe("search");
  });

  test("no attributes, no form: structure finds the pair", () => {
    page("noattrs.html");
    const a = scope("input[name=j_username]");
    expect(a.username).toBe($("input[name=j_username]"));
    expect(a.password).toBe($("input[name=j_password]"));
  });

  test("search, newsletter and coupon fields are not login or code fields", () => {
    page("negatives.html");
    expect(fieldKind($("#search"))).toBe("search");
    expect(fieldKind($("#nl"))).toBe("skip");
    expect(["username", "otp", "password", "email"]).not.toContain(fieldKind($("#cp")));
    expect(scope("#cp").type).not.toBe("login");
    expect(scope("#u").type).toBe("login");
  });

  test("sign-up: password + confirmation are both new passwords", () => {
    page("signup.html");
    const a = scope("#p");
    expect(a.type).toBe("signup");
    expect(a.username).toBe($("#u"));
    expect(a.newPasswords).toEqual([$("#p"), $("#r")]);
  });

  test("change password: current, new, confirm", () => {
    page("change.html");
    const a = scope("#n");
    expect(a.type).toBe("change");
    expect(a.password).toBe($("#c"));
    expect(a.newPasswords).toEqual([$("#n"), $("#r")]);
  });

  test("split code boxes and a lone code field", () => {
    page("split-otp.html");
    expect(scope(".boxes input").otp).toHaveLength(6);
    page("otp-only.html");
    expect(scope("#c").type).toBe("otp");
  });

  test("card and identity forms", () => {
    page("card.html");
    const c = scope("#cn");
    expect(c.type).toBe("card");
    expect(c.card["cc-number"]).toEqual([$("#cn")]);
    expect(c.card["cc-csc"]).toEqual([$("#cv")]);
    page("identity.html");
    const i = scope("#fn");
    expect(i.type).toBe("identity");
    expect(i.password).toBeNull();
  });
});

describe("Russian labels", () => {
  test("Логин / Пароль", () => {
    load(`<form><label>Логин <input id="u"></label><label>Пароль <input id="p" type="password"></label><button>Войти</button></form>`);
    const a = scope("#u");
    expect([a.type, a.username, a.password]).toEqual(["login", $("#u"), $("#p")]);
  });

  test("an SMS code is a code; a recovery code is not", () => {
    load(`<form><input id="c" placeholder="Код из SMS" maxlength="6"><input id="r" placeholder="Код восстановления"></form>`);
    expect(fieldKind($("#c"))).toBe("otp");
    expect(fieldKind($("#r"))).toBe("skip");
  });
});
