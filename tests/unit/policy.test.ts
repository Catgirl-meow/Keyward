import { describe, expect, test } from "vitest";
import { effectivePolicy, policedPassphrase, policedPassword, policedTimeout, PolicyType as T } from "../../src/core/vault/policy.ts";
import { DEFAULT_PASSPHRASE, DEFAULT_PASSWORD } from "../../src/core/generator/password.ts";

const org = (id: string, type = 2, extra = {}) => ({ id, name: `Org ${id}`, type, status: 2, enabled: true, usePolicies: true, ...extra });
const pol = (organizationId: string, type: number, data: unknown = null, enabled = true) => ({ organizationId, type, enabled, data: data as any });

describe("effectivePolicy", () => {
  test("a member follows every enabled policy; data may come as a JSON string", () => {
    const e = effectivePolicy(
      [pol("a", T.PersonalOwnership), pol("a", T.DisableSend), pol("a", T.SendOptions, '{"disableHideEmail":true}'), pol("a", T.DisablePersonalVaultExport), pol("a", T.RemoveUnlockWithPin), pol("a", T.MaximumVaultTimeout, { minutes: 30, action: "logOut" })],
      [org("a")],
    );
    expect(e).toMatchObject({ personalOwnership: true, disableSend: true, sendShowEmail: true, disableExport: true, removePin: true, maxTimeout: { minutes: 30, action: "logout" } });
    expect(e.by[T.DisableSend]).toBe("Org a");
  });

  test("disabled policies, unconfirmed memberships, orgs without policies: nothing", () => {
    expect(effectivePolicy([pol("a", T.DisableSend, null, false)], [org("a")])).toEqual({ by: {} });
    expect(effectivePolicy([pol("a", T.DisableSend)], [org("a", 2, { status: 1 })])).toEqual({ by: {} });
    expect(effectivePolicy([pol("a", T.DisableSend)], [org("a", 2, { usePolicies: false })])).toEqual({ by: {} });
    expect(effectivePolicy([pol("x", T.DisableSend)], [org("a")])).toEqual({ by: {} });
  });

  test("owners and admins are exempt, except from the generator, PIN and (admins) timeout policies", () => {
    const all = [pol("a", T.DisableSend), pol("a", T.PasswordGenerator, { minLength: 30 }), pol("a", T.RemoveUnlockWithPin), pol("a", T.MaximumVaultTimeout, { minutes: 15 })];
    const owner = effectivePolicy(all, [org("a", 0)]);
    expect(owner.disableSend).toBeUndefined();
    expect(owner.generator?.minLength).toBe(30);
    expect(owner.removePin).toBe(true);
    expect(owner.maxTimeout).toBeUndefined();
    expect(effectivePolicy(all, [org("a", 1)]).maxTimeout?.minutes).toBe(15);
  });

  test("several organizations: the strictest wins", () => {
    const e = effectivePolicy(
      [pol("a", T.MaximumVaultTimeout, { minutes: 60, action: "lock" }), pol("b", T.MaximumVaultTimeout, { minutes: 10 }), pol("a", T.PasswordGenerator, { minLength: 12, useSpecial: true }), pol("b", T.PasswordGenerator, { minLength: 24, minNumbers: 3 })],
      [org("a"), org("b")],
    );
    expect(e.maxTimeout).toEqual({ minutes: 10, action: "lock" });
    expect(e.generator).toMatchObject({ minLength: 24, symbols: true, minDigits: 3 });
  });
});

describe("applying policies", () => {
  test("generator options are raised, never lowered", () => {
    const e = effectivePolicy([pol("a", T.PasswordGenerator, { minLength: 32, useSpecial: true, minNumbers: 4, minNumberWords: 7, capitalize: true })], [org("a")]);
    const p = policedPassword({ ...DEFAULT_PASSWORD, length: 14, symbols: false, minDigits: 1 }, e);
    expect(p).toMatchObject({ length: 32, symbols: true, digits: true, minDigits: 4 });
    expect(policedPassword({ ...DEFAULT_PASSWORD, length: 64 }, e).length).toBe(64);
    expect(policedPassphrase({ ...DEFAULT_PASSPHRASE, words: 4, capitalize: false }, e)).toMatchObject({ words: 7, capitalize: true });
  });

  test("lock timeout: capped; 'on restart' and 'never' count as unlimited", () => {
    const e = effectivePolicy([pol("a", T.MaximumVaultTimeout, { minutes: 15, action: "logOut" })], [org("a")]);
    expect(policedTimeout(5, "lock", e)).toEqual({ minutes: 5, action: "logout" });
    expect(policedTimeout(240, "lock", e).minutes).toBe(15);
    expect(policedTimeout(-1, "lock", e).minutes).toBe(15);
    expect(policedTimeout(-2, "lock", e).minutes).toBe(15);
    expect(policedTimeout(0, "lock", e).minutes).toBe(0);
    expect(policedTimeout(-2, "lock", undefined)).toEqual({ minutes: -2, action: "lock" });
  });
});
