import { describe, expect, it } from "vitest";
import {
  split,
  splitFirst,
  trim,
  trimOf,
  trimWhitespace,
  toInt,
  toNumber,
  getUrlArg,
  replaceAllDistinct,
  parseCommaKeyValue,
  processEscapeChar,
  UTF8ToCodePoint,
  getLineBreak,
  countLeast,
} from "../../src/lib/string";

describe("split (C++ semantics)", () => {
  it("empty input yields no elements", () => {
    expect(split("", ",")).toEqual([]);
  });
  it("keeps empty fields between separators; trailing sep adds none (C++ quirk)", () => {
    expect(split("a,", ",")).toEqual(["a"]);
    expect(split("a,,b", ",")).toEqual(["a", "", "b"]);
    expect(split("a,,", ",")).toEqual(["a", ""]);
  });
  it("no separator returns whole string", () => {
    expect(split("abc", ",")).toEqual(["abc"]);
  });
  it("multi-char separator", () => {
    expect(split("a::b", "::")).toEqual(["a", "b"]);
  });
  it("split_first splits on first occurrence only", () => {
    expect(splitFirst("ss://a=b==", "=")).toEqual(["ss://a", "b=="]);
    expect(splitFirst("nosep", "=")).toEqual(["nosep"]);
  });
});

describe("trim family", () => {
  it("trim spaces both sides", () => {
    expect(trim("  a b  ")).toBe("a b");
  });
  it("trimOf all-target returns unchanged (C++ quirk)", () => {
    expect(trimOf("xxx", "x")).toBe("xxx");
    expect(trimOf("  x  ", " ")).toBe("x");
  });
  it("trimWhitespace default only trims trailing (before=false)", () => {
    expect(trimWhitespace(" \t\n ")).toBe("");
    expect(trimWhitespace("  a\n")).toBe("  a");
    expect(trimWhitespace("  a\n", true, true)).toBe("a");
  });
});

describe("to_int (atoi semantics)", () => {
  it("empty uses default", () => {
    expect(toInt("", 5)).toBe(5);
  });
  it("prefix parse", () => {
    expect(toInt("12ab")).toBe(12);
    expect(toInt("  -7x")).toBe(-7);
  });
  it("no digits yields 0 not default", () => {
    expect(toInt("abc", 5)).toBe(0);
  });
  it("to_number rejects trailing garbage", () => {
    expect(toNumber("12ab", 9)).toBe(9);
    expect(toNumber("12", 9)).toBe(12);
  });
});

describe("getUrlArg", () => {
  it("finds args", () => {
    expect(getUrlArg("target=clash&url=abc", "url")).toBe("abc");
    expect(getUrlArg("?target=clash", "target")).toBe("clash");
  });
  it("finds the last occurrence", () => {
    expect(getUrlArg("url=1&url=2", "url")).toBe("2");
  });
  it("does not match partial names", () => {
    expect(getUrlArg("xxurl=1", "url")).toBe("");
  });
});

describe("misc", () => {
  it("replaceAllDistinct", () => {
    expect(replaceAllDistinct("aaa", "aa", "b")).toBe("ba");
    expect(replaceAllDistinct("a.b.c", ".", "-")).toBe("a-b-c");
  });
  it("parseCommaKeyValue", () => {
    expect(parseCommaKeyValue("a=1,b=2,c=3", ",")).toEqual([
      ["a", "1"],
      ["b", "2"],
      ["c", "3"],
    ]);
    expect(parseCommaKeyValue("flag", ",")).toEqual([["{NONAME}", "flag"]]);
    expect(parseCommaKeyValue("a=1\\,2,b=3", ",")).toEqual([
      ["a", "1,2"],
      ["b", "3"],
    ]);
  });
  it("processEscapeChar only n/r/t", () => {
    expect(processEscapeChar("a\\nb\\tc\\\\d")).toBe("a\nb\tc\\\\d");
  });
  it("UTF8ToCodePoint", () => {
    expect(UTF8ToCodePoint("Aé")).toBe("A\\ue9");
  });
  it("getLineBreak/countLeast", () => {
    expect(getLineBreak("a\nb")).toBe("\n");
    expect(getLineBreak("abc")).toBe("\r");
    expect(countLeast("a,b,c", ",", 2)).toBe(true);
    expect(countLeast("a,b", ",", 2)).toBe(false);
  });
});
