// Port of src/utils/regexp.cpp — PCRE2 (jpcre2) → JS RegExp adapter.
//
// Upstream semantics:
//  - regFind:  PCRE2_UTF|ALT_BSUX + MULTILINE, search anywhere (true/false)
//  - regMatch: + ANCHORED|ENDANCHORED → whole-subject match
//  - regReplace: always MULTILINE; replacement processed with SUBSTITUTE_EXTENDED
//    (backslash escapes real, $0 = whole match, ${name}, case forcing \U\L\E)
//  - regGetAllMatch: flat [match0_group0, match0_group1, ..., match1_group0, ...]
//  - compile failure → false / src / [] (never throws)

const patternCache = new Map<string, RegExp | null>();

// The cache is keyed by (extraFlags, pattern) and lives as long as the isolate. Upstream builds a
// fresh jpcre2::Regex per call and frees it (regexp.cpp:136-149); on Workers the isolate is long-lived,
// so bound the map and evict oldest-first (Map preserves insertion order).
const MAX_PATTERN_CACHE = 2000;

class PatternError extends Error {}

// PCRE2 turns a pathological match into PCRE2_ERROR_MATCHLIMIT (default match_limit 10,000,000) and
// jpcre2 then reports "no match", so upstream degrades instead of hanging. V8 has no match limit and
// a running RegExp cannot be interrupted, so bound the two things that make a hang possible:
// an absurd pattern length, and a quantifier applied directly to a group that itself ends in an
// unbounded quantifier ("(a+)+", "(a*)*", "(?:x{2,})+") — the classic catastrophic-backtracking shape.
const MAX_PATTERN_LENGTH = 8192;

function hasNestedUnboundedQuantifier(pattern: string): boolean {
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] === "\\") {
      i++;
      continue;
    }
    if (pattern[i] !== "(") continue;
    const end = findGroupEnd(pattern, i);
    if (end === -1) continue;
    const body = pattern.substring(i + 1, end).replace(/^\?[A-Za-z<>=!:-]*/, "");
    if (!/(\*|\+|\{\d+,\})\??$/.test(body)) continue;
    let j = end + 1;
    if (pattern[j] === "?") j++;
    if (pattern[j] === "*" || pattern[j] === "+") return true;
    if (pattern[j] === "{" && /^\{\d+,\}/.test(pattern.substring(j))) return true;
    i = end;
  }
  return false;
}

// --- pattern translation -----------------------------------------------------

const POSIX_CLASSES: Record<string, string> = {
  alpha: "A-Za-z",
  digit: "0-9",
  alnum: "A-Za-z0-9",
  upper: "A-Z",
  lower: "a-z",
  space: "\\t\\n\\v\\f\\r ",
  blank: "\\t ",
  punct: "!-/:-@\\[-`{-~",
  word: "\\w",
  xdigit: "0-9A-Fa-f",
  cntrl: "\\x00-\\x1f\\x7f",
  print: "\\x20-\\x7e",
  graph: "\\x21-\\x7e",
  ascii: "\\x00-\\x7f",
};

// POSIX horizontal whitespace (PCRE2 \h) — includes plain space
const H_SPACE = " \\t\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000";

// Only escape characters that are special to JS RegExp. Escaping everything (as an earlier version
// did) produces identity escapes such as "\ " which are SyntaxErrors once the u flag is set.
// Inside a character class, "-" and "^" additionally need escaping: a literal "-" would build a
// range and a leading "^" would negate the class. "\-" is allowed in u-mode only inside a class,
// which is why that escape is conditional.
const JS_META = /[\\^$.*+?()[\]{}|/]/;
function escapeLiteralChar(ch: string, inClass = false): string {
  if (inClass && (ch === "-" || ch === "^")) return "\\" + ch;
  return JS_META.test(ch) ? "\\" + ch : ch;
}

// translate \Q...\E (literal quoting) into escaped text
function translateQuoteSections(pattern: string): string {
  let out = "";
  let i = 0;
  let inClass = false;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === "\\" && pattern[i + 1] === "Q") {
      let j = i + 2;
      let literal = "";
      while (j < pattern.length && !(pattern[j] === "\\" && pattern[j + 1] === "E")) {
        literal += pattern[j];
        j++;
      }
      for (const ch of literal) out += escapeLiteralChar(ch, inClass);
      i = j + 2;
      continue;
    }
    if (c === "\\") {
      // an escaped bracket must not toggle the class state
      out += c + (pattern[i + 1] ?? "");
      i += 2;
      continue;
    }
    if (c === "[") inClass = true;
    else if (c === "]") inClass = false;
    out += c;
    i++;
  }
  return out;
}

// find the matching ) for a group opened at position `open` (pattern[open] === '(')
function findGroupEnd(pattern: string, open: number): number {
  let depth = 0;
  let i = open;
  let inClass = false;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (inClass) {
      if (c === "]") inClass = false;
    } else if (c === "[") {
      inClass = true;
    } else if (c === "(") {
      depth++;
    } else if (c === ")") {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  return -1;
}

// apply inline (?flags) found in pattern: hoist supported ones to JS flags.
// (?i:...) / (?s:...) group forms are supported natively by modern V8 and kept.
// PCRE2's (?x) has no JS flag — it is reported back so the pattern can be stripped instead
// (previously "x" was hoisted into the flag string, where new RegExp threw and the pattern
// silently never matched anything).
function hoistInlineFlags(pattern: string): { pattern: string; flags: string; extended: boolean } {
  let flags = "";
  let extended = false;
  let out = "";
  let i = 0;
  let inClass = false;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === "\\") {
      out += c + (pattern[i + 1] ?? "");
      i += 2;
      continue;
    }
    if (inClass) {
      if (c === "]") inClass = false;
      out += c;
      i++;
      continue;
    }
    if (c === "[") {
      inClass = true;
      out += c;
      i++;
      continue;
    }
    if (c === "(" && pattern[i + 1] === "?") {
      // candidate (?letters) — only letters until ')'
      let j = i + 2;
      let letters = "";
      while (j < pattern.length && /[a-zA-Z]/.test(pattern[j])) {
        letters += pattern[j];
        j++;
      }
      if (pattern[j] === ")" && letters.length > 0 && /^[imsx]+$/.test(letters)) {
        if (letters.includes("x")) extended = true;
        for (const f of letters) if (f !== "x" && !flags.includes(f)) flags += f;
        i = j + 1;
        continue;
      }
    }
    out += c;
    i++;
  }
  return { pattern: out, flags, extended };
}

// PCRE2 extended mode: unescaped whitespace outside character classes is ignored, and "#" starts a
// comment that runs to the end of the line.
function stripExtendedMode(pattern: string): string {
  let out = "";
  let i = 0;
  let inClass = false;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === "\\") {
      out += c + (pattern[i + 1] ?? "");
      i += 2;
      continue;
    }
    if (inClass) {
      if (c === "]") inClass = false;
      out += c;
      i++;
      continue;
    }
    if (c === "[") {
      inClass = true;
      out += c;
      i++;
      continue;
    }
    if (c === "#") {
      while (i < pattern.length && pattern[i] !== "\n") i++;
      continue;
    }
    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v") {
      i++;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

function translateEscapes(pattern: string): string {
  let out = "";
  let i = 0;
  let inClass = false;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === "\\") {
      const next = pattern[i + 1];
      if (next === undefined) {
        out += "\\\\";
        i++;
        continue;
      }
      switch (next) {
        case "h":
          out += inClass ? H_SPACE : "[" + H_SPACE + "]";
          i += 2;
          continue;
        case "H":
          out += inClass ? "^" + H_SPACE : "[^" + H_SPACE + "]";
          i += 2;
          continue;
        case "N":
          out += "[^\\n]";
          i += 2;
          continue;
        case "R":
          out += "(?:\\r\\n|[\\n\\v\\f\\r\\u0085\\u2028\\u2029])";
          i += 2;
          continue;
        case "P": {
          // (?P<name>) → (?<name>); (?P=name) unsupported
          if (pattern[i + 2] === "<") {
            out += "(?<";
            i += 3;
            continue;
          }
          out += "\\P";
          i += 2;
          continue;
        }
        default:
          out += c + next;
          i += 2;
          continue;
      }
    }
    if (c === "[") inClass = true;
    else if (c === "]") inClass = false;
    out += c;
    i++;
  }
  return out;
}

// \A \z \Z are absolute in PCRE2 and stay absolute even under PCRE2_MULTILINE (which only affects
// ^ and $). JS has no absolute-anchor escapes, so translate them to lookarounds: those keep working
// while the m flag — which upstream always sets — stays in effect. (Translating them to ^/$ and
// dropping m, as an earlier version did, silently made them line anchors in the regReplace /
// regGetAllMatch paths, where extraFlags re-adds m.)
function translateAnchors(pattern: string): string {
  let out = "";
  let i = 0;
  let inClass = false;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === "\\") {
      const next = pattern[i + 1];
      if (!inClass && next === "A") {
        out += "(?<![\\s\\S])";
        i += 2;
        continue;
      }
      if (!inClass && next === "z") {
        out += "(?![\\s\\S])";
        i += 2;
        continue;
      }
      if (!inClass && next === "Z") {
        out += "(?=\\n?(?![\\s\\S]))";
        i += 2;
        continue;
      }
      out += c + (next ?? "");
      i += 2;
      continue;
    }
    if (c === "[") inClass = true;
    else if (c === "]") inClass = false;
    out += c;
    i++;
  }
  return out;
}

// \x{h+} \o{o+} \u{h+} → literal codepoints (avoids needing the u flag)
function translateCodepointEscapes(pattern: string): string {
  return pattern
    .replace(/\\x\{([0-9a-fA-F]{1,6})\}/g, (_, h) => escapeLiteralChar(safeCodepoint(parseInt(h, 16))))
    .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_, h) => escapeLiteralChar(safeCodepoint(parseInt(h, 16))))
    .replace(/\\o\{([0-7]{1,6})\}/g, (_, h) => escapeLiteralChar(safeCodepoint(parseInt(h, 8))));
}

function safeCodepoint(cp: number): string {
  if (!isFinite(cp) || cp < 0 || cp > 0x10ffff) return "";
  if (cp >= 0xd800 && cp <= 0xdfff) return "";
  return String.fromCodePoint(cp);
}

// [[:alpha:]] style POSIX classes. The previous implementation only matched a POSIX class that was
// the ENTIRE character class, so "[[:alpha:]0-9]" was left as literal characters and silently
// matched the wrong things. This walks real character classes and expands members positionally.
function translatePosixClasses(pattern: string): string {
  const expand = (body: string): string =>
    body.replace(/\[:([a-z]+):\]/g, (m, name) => POSIX_CLASSES[name] ?? m);

  let out = "";
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === "\\") {
      out += c + (pattern[i + 1] ?? "");
      i += 2;
      continue;
    }
    if (c !== "[") {
      out += c;
      i++;
      continue;
    }
    // scan one character class
    let j = i + 1;
    let negated = false;
    if (pattern[j] === "^") {
      negated = true;
      j++;
    }
    if (pattern[j] === "]") j++; // leading ] is a literal member
    let body = "";
    let closed = false;
    while (j < pattern.length) {
      if (pattern[j] === "\\") {
        body += pattern[j] + (pattern[j + 1] ?? "");
        j += 2;
        continue;
      }
      // a POSIX class inside the class body is "[:" ... ":]" — its inner "]" is not the class end
      if (pattern[j] === "[" && pattern[j + 1] === ":") {
        const close = pattern.indexOf(":]", j + 2);
        if (close !== -1) {
          body += pattern.substring(j, close + 2);
          j = close + 2;
          continue;
        }
      }
      if (pattern[j] === "]") {
        closed = true;
        break;
      }
      body += pattern[j];
      j++;
    }
    if (!closed) {
      out += c;
      i++;
      continue;
    }
    const wholeNegated = /^\[:(\^)([a-z]+):\]$/.exec(body);
    if (wholeNegated && POSIX_CLASSES[wholeNegated[2]]) {
      // [[:^name:]] — negation can only be expressed when it is the whole class body
      out += "[" + (negated ? "" : "^") + POSIX_CLASSES[wholeNegated[2]] + "]";
    } else {
      out += "[" + (negated ? "^" : "") + expand(body) + "]";
    }
    i = j + 1;
  }
  return out;
}

function translatePattern(pattern: string): { source: string; flags: string } {
  let flags = "";
  let p = pattern;
  const hoisted = hoistInlineFlags(p);
  p = hoisted.pattern;
  flags += hoisted.flags;
  if (hoisted.extended) p = stripExtendedMode(p);
  p = translatePosixClasses(p);
  p = translateCodepointEscapes(p);
  p = translateQuoteSections(p);
  p = translateEscapes(p);
  p = translateAnchors(p);
  // upstream always runs with PCRE2_MULTILINE (regexp.cpp:155/193)
  flags += "m";
  // \K unsupported in JS
  if (p.includes("\\K")) throw new PatternError("\\K unsupported");
  return { source: p, flags };
}

function cacheSet(key: string, value: RegExp | null): void {
  patternCache.set(key, value);
  if (patternCache.size > MAX_PATTERN_CACHE) {
    const oldest = patternCache.keys().next();
    if (!oldest.done) patternCache.delete(oldest.value);
  }
}

function compile(pattern: string, extraFlags: string): RegExp {
  const key = extraFlags + "\u0000" + pattern;
  let re = patternCache.get(key);
  if (re !== undefined) {
    if (re === null) throw new PatternError("cached invalid");
    return re;
  }
  if (pattern.length > MAX_PATTERN_LENGTH || hasNestedUnboundedQuantifier(pattern)) {
    cacheSet(key, null);
    throw new PatternError("pattern rejected by length/backtracking guard");
  }
  try {
    const { source, flags } = translatePattern(pattern);
    const allFlags = dedupeFlags(flags + extraFlags);
    try {
      // PCRE2 runs with PCRE2_UTF (regexp.cpp:137/146/155/164): code-point semantics.
      re = new RegExp(source, dedupeFlags(allFlags + "u"));
    } catch {
      // a pattern that only compiles without u keeps working (upstream would report no-match)
      re = new RegExp(source, allFlags);
    }
  } catch {
    cacheSet(key, null);
    throw new PatternError("compile failed: " + pattern);
  }
  cacheSet(key, re);
  return re;
}

function dedupeFlags(f: string): string {
  return [...new Set(f.split(""))].join("");
}

// --- replacement translation (SUBSTITUTE_EXTENDED) ---------------------------

type CaseMode = "U" | "L" | null;

type RepSeg =
  | { t: "lit"; v: string }
  | { t: "raw"; v: string }
  | { t: "group"; n: number }
  | { t: "named"; name: string }
  | { t: "pre" }
  | { t: "post" }
  | { t: "whole" }
  | { t: "subject" }
  | { t: "case"; c: CaseMode };

function parseReplacement(rep: string): RepSeg[] {
  const segs: RepSeg[] = [];
  let lit = "";
  const flush = () => {
    if (lit) {
      segs.push({ t: "lit", v: lit });
      lit = "";
    }
  };
  let i = 0;
  while (i < rep.length) {
    const c = rep[i];
    if (c === "\\") {
      const next = rep[i + 1];
      if (next === undefined) {
        lit += "\\";
        i++;
        continue;
      }
      switch (next) {
        case "n": lit += "\n"; break;
        case "r": lit += "\r"; break;
        case "t": lit += "\t"; break;
        case "f": lit += "\f"; break;
        case "v": lit += "\v"; break;
        case "a": lit += "\x07"; break;
        case "e": lit += "\x1b"; break;
        case "l": // \l lowercase next char
          flush();
          segs.push({ t: "raw", v: (rep[i + 2] ?? "").toLowerCase() });
          i++;
          break;
        case "u": // \u uppercase next char
          flush();
          segs.push({ t: "raw", v: (rep[i + 2] ?? "").toUpperCase() });
          i++;
          break;
        case "L":
          flush();
          segs.push({ t: "case", c: "L" });
          break;
        case "U":
          flush();
          segs.push({ t: "case", c: "U" });
          break;
        case "E":
          flush();
          segs.push({ t: "case", c: null });
          break;
        case "Q": {
          // \Q..\E literal
          let j = i + 2;
          let q = "";
          while (j < rep.length && !(rep[j] === "\\" && rep[j + 1] === "E")) {
            q += rep[j];
            j++;
          }
          lit += q;
          i = j + 1;
          break;
        }
        case "x": {
          if (rep[i + 2] === "{") {
            const end = rep.indexOf("}", i + 3);
            const h = rep.substring(i + 3, end === -1 ? rep.length : end);
            lit += safeCodepoint(parseInt(h, 16));
            i = end === -1 ? rep.length : end;
          } else {
            const h = rep.substring(i + 2, i + 4);
            if (/^[0-9a-fA-F]{1,2}$/.test(h)) {
              lit += String.fromCharCode(parseInt(h, 16));
              i++;
            } else lit += "x";
          }
          break;
        }
        case "o": {
          if (rep[i + 2] === "{") {
            const end = rep.indexOf("}", i + 3);
            const h = rep.substring(i + 3, end === -1 ? rep.length : end);
            lit += safeCodepoint(parseInt(h, 8));
            i = end === -1 ? rep.length : end;
          } else {
            lit += "o";
          }
          break;
        }
        case "G": // first-match boundary — treat as empty
          break;
        default:
          lit += next;
          break;
      }
      i += 2;
      continue;
    }
    if (c === "$") {
      const next = rep[i + 1];
      if (next === "{") {
        const end = rep.indexOf("}", i + 2);
        const name = rep.substring(i + 2, end === -1 ? rep.length : end);
        flush();
        segs.push(/^\d+$/.test(name) ? { t: "group", n: parseInt(name, 10) } : { t: "named", name });
        i = end === -1 ? rep.length : end + 1;
        continue;
      }
      if (next === "0") {
        flush();
        segs.push({ t: "whole" });
        i += 2;
        continue;
      }
      if (next === "&") {
        flush();
        segs.push({ t: "whole" });
        i += 2;
        continue;
      }
      if (next === "`") {
        flush();
        segs.push({ t: "pre" });
        i += 2;
        continue;
      }
      if (next === "'") {
        flush();
        segs.push({ t: "post" });
        i += 2;
        continue;
      }
      if (next === "_" || next === "$" || next === "+" || next === "<") {
        // $_ $<name> $+ $<...> — PCRE2 extras; treat $_ as whole subject, $<name> named
        if (next === "_") {
          flush();
          segs.push({ t: "subject" });
          i += 2;
          continue;
        }
        if (next === "<") {
          const end = rep.indexOf(">", i + 2);
          const name = rep.substring(i + 2, end === -1 ? rep.length : end);
          flush();
          segs.push({ t: "named", name });
          i = end === -1 ? rep.length : end + 1;
          continue;
        }
        lit += c;
        i++;
        continue;
      }
      if (/[1-9]/.test(next ?? "")) {
        let j = i + 1;
        let num = "";
        while (j < rep.length && /\d/.test(rep[j])) {
          num += rep[j];
          j++;
        }
        // JS/PCRE $10 ambiguity: take up to 2 digits if they exist as ref
        flush();
        segs.push({ t: "group", n: parseInt(num, 10) });
        i = j;
        continue;
      }
      lit += c;
      i++;
      continue;
    }
    lit += c;
    i++;
  }
  flush();
  return segs;
}

// --- public API ---------------------------------------------------------------

export function regValid(reg: string): boolean {
  try {
    compile(reg, "");
    return true;
  } catch {
    return false;
  }
}

export function regFind(src: string, match: string): boolean {
  try {
    return compile(match, "").test(src);
  } catch {
    return false;
  }
}

export function regMatch(src: string, match: string): boolean {
  try {
    // PCRE2 ANCHORED|ENDANCHORED: match must span the whole subject
    const re = compile(match, "");
    const reExec = new RegExp(re.source, re.flags.replace("g", ""));
    const m = reExec.exec(src);
    return !!m && m.index === 0 && m[0].length === src.length;
  } catch {
    return false;
  }
}

export function regReplace(src: string, match: string, rep: string, global = true, multiline = true): string {
  let re: RegExp;
  try {
    // upstream always sets PCRE2_MULTILINE; `multiline` param only toggles the redundant modifier
    re = compile(match, "gm");
  } catch {
    return src;
  }
  void multiline;
  const segs = parseReplacement(rep);
  // PCRE2 SUBSTITUTE_EXTENDED applies \U…\E case forcing to the whole substitution output,
  // including text inserted from capture groups — so the mode is a running state applied to every
  // appended piece, not a transform of the literal segments only.
  const build = (m: RegExpExecArray): string => {
    let mode: CaseMode = null;
    const applyCase = (s: string): string => (mode === "U" ? s.toUpperCase() : mode === "L" ? s.toLowerCase() : s);
    let out = "";
    for (const seg of segs) {
      switch (seg.t) {
        case "lit":
          out += applyCase(seg.v);
          break;
        case "raw":
          out += seg.v;
          break;
        case "case":
          mode = seg.c;
          break;
        case "group":
          out += applyCase(m[seg.n] ?? "");
          break;
        case "named":
          out += applyCase((m.groups && m.groups[seg.name]) ?? "");
          break;
        case "whole":
          out += applyCase(m[0]);
          break;
        case "pre":
          out += applyCase(src.substring(0, m.index ?? 0));
          break;
        case "post":
          out += applyCase(src.substring((m.index ?? 0) + m[0].length));
          break;
        case "subject":
          out += applyCase(src);
          break;
      }
    }
    return out;
  };
  try {
    const reExec = new RegExp(re.source, re.flags); // has g
    let out = "";
    let lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = reExec.exec(src)) !== null) {
      out += src.substring(lastIndex, m.index) + build(m);
      lastIndex = m.index + m[0].length;
      if (m[0].length === 0) reExec.lastIndex++;
      if (!global) break;
    }
    out += src.substring(lastIndex);
    return out;
  } catch {
    return src;
  }
}

// flat result list: [m0g0, m0g1, ..., m1g0, ...]; group_only skips full matches
export function regGetAllMatch(src: string, match: string, groupOnly = false): string[] {
  let re: RegExp;
  try {
    re = compile(match, "gm");
  } catch {
    return [];
  }
  const result: string[] = [];
  const begin = groupOnly ? 1 : 0;
  try {
    const matches = src.match(re);
    if (!matches) return result;
    // need group details → iterate with exec
    const reExec = new RegExp(re.source, re.flags);
    let m: RegExpExecArray | null;
    while ((m = reExec.exec(src)) !== null) {
      for (let i = begin; i < m.length; i++) {
        const v = m[i];
        // A group that did not participate in the match must keep its SLOT: jpcre2 pushes an empty
        // String() for PCRE2_UNSET (jpcre2.hpp:4751-4757), and every caller destructures
        // positionally, so dropping undefined shifted all later groups left.
        result.push(v ?? "");
      }
      if (m[0].length === 0) reExec.lastIndex++;
    }
  } catch {
    return result;
  }
  return result;
}

// returns matched groups flat, or null when no match (C++ int return + out params)
export function regGetMatch(src: string, match: string, groupCount = 0): string[] | null {
  const all = regGetAllMatch(src, match, false);
  if (all.length === 0) return null;
  void groupCount;
  return all;
}

export function regTrim(src: string): string {
  return regReplace(src, "^\\s*([\\s\\S]*)\\s*$", "$1", false, false);
}

export function clearRegexCache(): void {
  patternCache.clear();
}
