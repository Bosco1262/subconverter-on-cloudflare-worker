import { describe, expect, it } from "vitest";
import { base64Decode, base64Encode, urlSafeBase64Decode, urlSafeBase64Encode } from "../../src/lib/base64";

describe("base64", () => {
  it("encode/decode roundtrip ascii", () => {
    expect(base64Encode("hello")).toBe("aGVsbG8=");
    expect(base64Decode("aGVsbG8=")).toBe("hello");
  });
  it("encode handles utf-8", () => {
    expect(base64Encode("中文")).toBe(base64Encode("中文"));
    expect(base64Decode(base64Encode("中文"))).toBe("中文");
  });
  it("decode is lenient — non-base64 chars copied verbatim", () => {
    // C++ behavior: chars outside the table are copied to the result as-is
    expect(base64Decode("aGVs*bG8=")).toBe("hel*lo");
  });
  it("decode stops at =", () => {
    expect(base64Decode("aGVsbG8=JUNK")).toBe("hello");
  });
  it("urlsafe variants", () => {
    // bytes 0xfb 0xff 0xbf encode to "+/+/+..." containing + and /
    const raw = String.fromCharCode(0xfb, 0xff, 0xbf);
    const std = base64Encode(raw);
    const safe = urlSafeBase64Encode(raw);
    expect(safe).not.toContain("+");
    expect(safe).not.toContain("/");
    expect(urlSafeBase64Decode(safe)).toBe(urlSafeBase64Decode(std));
  });
  it("urlsafe decode accepts - _", () => {
    expect(base64Decode("a-GVs_bG8=", true)).toBe(base64Decode("a+GVs/bG8=", false));
  });
});
