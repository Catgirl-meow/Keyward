import { describe, expect, it } from "vitest";
import { base32Decode, formatCode, hotp, otpCode, parseOtp } from "../../src/core/totp/totp.ts";

const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"

describe("otp", () => {
  it("RFC 4226 HOTP vectors", async () => {
    const spec = parseOtp(RFC_SECRET_B32)!;
    const want = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
    for (let i = 0; i < 10; i++) expect(await hotp(spec, i)).toBe(want[i]);
  });

  it("RFC 6238 TOTP (SHA1, 8 digits)", async () => {
    const spec = parseOtp(`otpauth://totp/Example:alice@x.com?secret=${RFC_SECRET_B32}&digits=8&issuer=Example`)!;
    expect(spec.issuer).toBe("Example");
    expect(spec.account).toBe("alice@x.com");
    expect((await otpCode(spec, 59_000)).code).toBe("94287082");
    expect((await otpCode(spec, 1111111109_000)).code).toBe("07081804");
    expect((await otpCode(spec, 59_000)).remaining).toBe(1);
  });

  it("SHA256/SHA512 TOTP vectors", async () => {
    const s256 = parseOtp(`otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8`)!;
    expect((await otpCode(s256, 59_000)).code).toBe("46119246");
    const s512 = parseOtp(
      `otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA&algorithm=SHA512&digits=8`,
    )!;
    expect((await otpCode(s512, 59_000)).code).toBe("90693936");
  });

  it("steam and formatting", async () => {
    const s = parseOtp("steam://" + RFC_SECRET_B32)!;
    expect(s.kind).toBe("steam");
    expect((await otpCode(s, 59_000)).code).toMatch(/^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
    expect(formatCode("123456")).toBe("123 456");
    expect(base32Decode("MZXW6===").length).toBe(3);
    expect(parseOtp("not base32 !!")).toBeNull();
  });
});
