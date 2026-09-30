import { describe, expect, it } from "vitest";
import { regFind, regMatch, regReplace, regGetAllMatch, regGetMatch, regValid, regTrim } from "../../src/lib/regex";

describe("regex adapter (PCRE2 → JS)", () => {
  it("regFind basic + multiline", () => {
    expect(regFind("hello world", "world")).toBe(true);
    expect(regFind("a\nb", "^b")).toBe(true); // m flag
    expect(regFind("abc", "^b")).toBe(false);
  });
  it("regFind (?i) hoisting", () => {
    expect(regFind("HELLO", "(?i)hello")).toBe(true);
    expect(regFind("Clash Meta", "(?i)clash")).toBe(true);
  });
  it("invalid pattern → false", () => {
    expect(regFind("abc", "(unclosed")).toBe(false);
  });
  it("regMatch is whole-subject (ANCHORED|ENDANCHORED)", () => {
    expect(regMatch("12345", "\\d+")).toBe(true);
    expect(regMatch("12345a", "\\d+")).toBe(false);
    expect(regMatch("a12345", "\\d+")).toBe(false);
    expect(regMatch("hello", "(?i)HELLO")).toBe(true);
    // $ before trailing newline must NOT match (ENDANCHORED)
    expect(regMatch("abc\n", "abc$")).toBe(false);
  });
  it("regReplace group refs", () => {
    expect(regReplace("a1b2", "\\d", "[$0]")).toBe("a[1]b[2]");
    expect(regReplace("John Smith", "(\\w+) (\\w+)", "$2, $1")).toBe("Smith, John");
    expect(regReplace("abc", "b", "$1$1")).toBe("ac"); // unset groups → empty
  });
  it("regReplace extended escapes in replacement", () => {
    expect(regReplace("a-b", "-", "\\n")).toBe("a\nb");
    expect(regReplace("ab", "(a)(b)", "$1\\t$2")).toBe("a\tb");
  });
  it("regReplace ${name} and named groups", () => {
    expect(regReplace("2024-01", "(?<y>\\d+)-(?<m>\\d+)", "${m}/${y}")).toBe("01/2024");
  });
  it("regReplace multiline always on", () => {
    expect(regReplace("a\nb", "^", "> ")).toBe("> a\n> b");
  });
  it("regReplace non-global", () => {
    expect(regReplace("aaa", "a", "b", false, true)).toBe("baa");
  });
  it("regReplace invalid → src unchanged", () => {
    expect(regReplace("abc", "(?", "x")).toBe("abc");
  });
  it("regGetAllMatch flat groups", () => {
    expect(regGetAllMatch("a=1,b=2", "(\\w)=(\\d)")).toEqual(["a=1", "a", "1", "b=2", "b", "2"]);
    expect(regGetAllMatch("a=1,b=2", "(\\w)=(\\d)", true)).toEqual(["a", "1", "b", "2"]);
  });
  it("regGetMatch returns null on no match", () => {
    expect(regGetMatch("abc", "(\\d)")).toBeNull();
    expect(regGetMatch("a1", "(\\w)(\\d)")).toEqual(["a1", "a", "1"]);
  });
  it("PCRE \h horizontal whitespace", () => {
    expect(regFind("a b", "a\\hb")).toBe(true);
    expect(regFind("a\tb", "a\\hb")).toBe(true);
    expect(regFind("a\nb", "a\\hb")).toBe(false);
  });
  it("PCRE \\A \\z anchors", () => {
    expect(regFind("hello", "\\Ahello")).toBe(true);
    expect(regFind("xhello", "\\Ahello")).toBe(false);
    expect(regFind("hello", "hello\\z")).toBe(true);
    expect(regFind("hellox", "hello\\z")).toBe(false);
  });
  it("\\x{...} codepoints", () => {
    expect(regFind("a😀b", "a\\x{1F600}b")).toBe(true);
  });
  it("\\Q...\\E quoting", () => {
    expect(regFind("a.b", "\\Qa.b\\E")).toBe(true);
    expect(regFind("axb", "\\Qa.b\\E")).toBe(false);
  });
  it("POSIX classes", () => {
    expect(regMatch("abc123", "[[:alpha:]]+[[:digit:]]+")).toBe(true);
  });
  it("(?i:...) inline group (V8 native)", () => {
    expect(regFind("CLASH", "(?i:clash)")).toBe(true);
  });
  it("regValid", () => {
    expect(regValid("a+")).toBe(true);
    expect(regValid("a(")).toBe(false);
  });
  it("regTrim — greedy group keeps trailing spaces (matches PCRE2 backtracking)", () => {
    expect(regTrim("  x y  ")).toBe("x y  ");
    expect(regTrim("  x y")).toBe("x y");
  });
});
