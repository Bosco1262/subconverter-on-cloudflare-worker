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

class PatternError extends Error {}

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

function escapeLiteralChar(ch: string): string {
  return /[a-zA-Z0-9_]/.test(ch) ? ch : "\\" + ch;
}

// translate \Q...\E (literal quoting) into escaped text
function translateQuoteSections(pattern: string): string {
  let out = "";
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === "\\" && pattern[i + 1] === "Q") {
      let j = i + 2;
      let literal = "";
      while (j < pattern.length && !(pattern[j] === "\\" && pattern[j + 1] === "E")) {
        literal += pattern[j];
        j++;
      }
      for (const ch of literal) out += escapeLiteralChar(ch);
      i = j + 2;
      continue;
    }
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
function hoistInlineFlags(pattern: string): { pattern: string; flags: string } {
  let flags = "";
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
        for (const f of letters) if (!flags.includes(f)) flags += f;
        i = j + 1;
        continue;
      }
    }
    out += c;
    i++;
  }
  return { pattern: out, flags };
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

// \A \z \Z: no JS equivalent — convert to ^/$ and drop m flag
function translateAnchors(pattern: string): { pattern: string; dropM: boolean } {
  let dropM = false;
  let out = pattern;
  if (/\\[AZz]/.test(pattern)) {
    dropM = true;
    out = out
      .replace(/\\A/g, "^")
      .replace(/\\z/g, "$")
      .replace(/\\Z/g, "$");
  }
  return { pattern: out, dropM };
}

// \x{h+} \o{o+} \u{h+} → literal codepoints (avoids needing the u flag)
function translateCodepointEscapes(pattern: string): string {
  return pattern
    .replace(/\\x\{([0-9a-fA-F]{1,6})\}/g, (_, h) => safeCodepoint(parseInt(h, 16)))
    .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_, h) => safeCodepoint(parseInt(h, 16)))
    .replace(/\\o\{([0-7]{1,6})\}/g, (_, h) => safeCodepoint(parseInt(h, 8)));
}

function safeCodepoint(cp: number): string {
  if (!isFinite(cp) || cp < 0 || cp > 0x10ffff) return "";
  if (cp >= 0xd800 && cp <= 0xdfff) return "";
  return String.fromCodePoint(cp);
}

// [[:alpha:]] style POSIX classes (incl. negated [[:^alpha:]])
function translatePosixClasses(pattern: string): string {
  return pattern.replace(/\[\[?:(\^?)([a-z]+):\]\]/g, (m, caret, name) => {
    const cls = POSIX_CLASSES[name];
    if (!cls) return m;
    return "[" + (caret ? "^" : "") + cls + "]";
  });
}

function translatePattern(pattern: string): { source: string; flags: string } {
  let flags = "";
  let p = pattern;
  // strip leading/trailing "m"-affecting constructs
  const hoisted = hoistInlineFlags(p);
  p = hoisted.pattern;
  flags += hoisted.flags;
  p = translatePosixClasses(p);
  p = translateCodepointEscapes(p);
  p = translateQuoteSections(p);
  p = translateEscapes(p);
  const anch = translateAnchors(p);
  p = anch.pattern;
  if (!anch.dropM) flags += "m";
  // \K unsupported in JS
  if (p.includes("\\K")) throw new PatternError("\\K unsupported");
  return { source: p, flags };
}

function compile(pattern: string, extraFlags: string): RegExp {
  const key = extraFlags + "\u0000" + pattern;
  let re = patternCache.get(key);
  if (re !== undefined) {
    if (re === null) throw new PatternError("cached invalid");
    return re;
  }
  try {
    const { source, flags } = translatePattern(pattern);
    const allFlags = dedupeFlags(flags + extraFlags);
    re = new RegExp(source, allFlags);
  } catch {
    patternCache.set(key, null);
    throw new PatternError("compile failed: " + pattern);
  }
  patternCache.set(key, re);
  return re;
}

function dedupeFlags(f: string): string {
  return [...new Set(f.split(""))].join("");
}

// --- replacement translation (SUBSTITUTE_EXTENDED) ---------------------------

type RepSeg =
  | { t: "lit"; v: string }
  | { t: "group"; n: number }
  | { t: "named"; name: string }
  | { t: "pre" }
  | { t: "post" }
  | { t: "whole" }
  | { t: "subject" };

function parseReplacement(rep: string): RepSeg[] {
  const segs: RepSeg[] = [];
  let lit = "";
  let caseMode: "U" | "L" | null = null;
  const flush = () => {
    if (lit) {
      segs.push({ t: "lit", v: caseMode === "U" ? lit.toUpperCase() : caseMode === "L" ? lit.toLowerCase() : lit });
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
          {
            const ch = rep[i + 2] ?? "";
            lit += ch.toLowerCase();
            i++;
          }
          break;
        case "u": // \u uppercase next char
          flush();
          {
            const ch = rep[i + 2] ?? "";
            lit += ch.toUpperCase();
            i++;
          }
          break;
        case "L":
          flush();
          caseMode = "L";
          break;
        case "U":
          flush();
          caseMode = "U";
          break;
        case "E":
          flush();
          caseMode = null;
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
  const build = (m: RegExpExecArray): string => {
    let out = "";
    for (const seg of segs) {
      switch (seg.t) {
        case "lit":
          out += seg.v;
          break;
        case "group":
          out += m[seg.n] ?? "";
          break;
        case "named":
          out += (m.groups && m.groups[seg.name]) ?? "";
          break;
        case "whole":
          out += m[0];
          break;
        case "pre":
          out += src.substring(0, m.index ?? 0);
          break;
        case "post":
          out += src.substring((m.index ?? 0) + m[0].length);
          break;
        case "subject":
          out += src;
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
        if (v !== undefined) result.push(v);
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
