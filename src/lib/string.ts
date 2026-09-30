// Port of src/utils/string.cpp + string.h — faithful to C++ semantics (byte-oriented, ASCII case ops)

export function split(s: string, separator: string): string[] {
  // C++: while (bpos < s.size()) — empty input yields NO elements; trailing empties kept
  const result: string[] = [];
  let bpos = 0;
  let epos = s.indexOf(separator);
  const slen = s.length;
  while (bpos < slen) {
    if (epos === -1) epos = slen;
    result.push(s.substring(bpos, epos));
    bpos = epos + separator.length;
    epos = s.indexOf(separator, bpos);
  }
  return result;
}

export function splitChar(s: string, separator: string): string[] {
  return split(s, separator);
}

export function splitFirst(s: string, separator: string): string[] {
  const pos = s.indexOf(separator);
  if (pos === -1) return [s];
  return [s.substring(0, pos), s.substring(pos + separator.length)];
}

export function join(arr: string[], delimiter: string): string {
  return arr.join(delimiter);
}

export function strFind(str: string, target: string): boolean {
  return str.includes(target);
}

export function startsWith(hay: string, needle: string): boolean {
  return hay.startsWith(needle);
}

export function endsWith(hay: string, needle: string): boolean {
  return hay.endsWith(needle);
}

export function countLeast(hay: string, needle: string, cnt: number): boolean {
  let pos = hay.indexOf(needle);
  while (pos !== -1) {
    cnt--;
    if (!cnt) return true;
    pos = hay.indexOf(needle, pos + 1);
  }
  return false;
}

export function getLineBreak(str: string): string {
  return countLeast(str, "\n", 1) ? "\n" : "\r";
}

export function replaceAllDistinct(str: string, oldValue: string, newValue: string): string {
  if (oldValue.length === 0) return str;
  return str.split(oldValue).join(newValue);
}

export function removeUTF8BOM(data: string): string {
  if (data.startsWith("\uFEFF")) return data.substring(1);
  return data;
}

// std::tolower/toupper in C locale — ASCII only
export function toLower(str: string): string {
  let out = "";
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : str[i];
  }
  return out;
}

export function toUpper(str: string): string {
  let out = "";
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    out += c >= 97 && c <= 122 ? String.fromCharCode(c - 32) : str[i];
  }
  return out;
}

export function trimOf(str: string, target: string, before = true, after = true): string {
  if (!before && !after) return str;
  let pos = 0;
  if (before) {
    pos = 0;
    while (pos < str.length && str[pos] === target) pos++;
    if (pos === str.length && before) {
      // C++: find_first_not_of == npos → return str unchanged
      return str;
    }
  }
  let pos2 = str.length - 1;
  if (after) {
    let last = str.length - 1;
    let found = -1;
    while (last >= pos) {
      if (str[last] !== target) {
        found = last;
        break;
      }
      last--;
    }
    pos2 = found;
  }
  if (pos2 !== -1 && pos2 >= pos) return str.substring(pos, pos2 + 1);
  return str.substring(pos);
}

export function trim(str: string, before = true, after = true): string {
  return trimOf(str, " ", before, after);
}

export function trimQuote(str: string, before = true, after = true): string {
  return trimOf(str, '"', before, after);
}

export function trimWhitespace(str: string, before = false, after = true): string {
  const whitespaces = " \t\f\v\n\r";
  let bpos = 0;
  let epos = str.length;
  if (after) {
    let last = str.length - 1;
    epos = -1;
    while (last >= 0) {
      if (!whitespaces.includes(str[last])) {
        epos = last;
        break;
      }
      last--;
    }
    if (epos === -1) return "";
  }
  if (before) {
    let first = 0;
    bpos = -1;
    while (first <= epos) {
      if (!whitespaces.includes(str[first])) {
        bpos = first;
        break;
      }
      first++;
    }
    if (bpos === -1) return "";
  }
  return str.substring(bpos, epos + 1);
}

export function trimSelfOf(str: string, target: string, before = true, after = true): string {
  return trimOf(str, target, before, after);
}

// std::atoi semantics: skips leading whitespace, optional sign, digits; no digits → 0
export function toInt(str: string, defValue = 0): number {
  if (str.length === 0) return defValue;
  const m = /^[ \t\n\v\f\r]*([+-]?\d+)/.exec(str);
  if (!m) return 0;
  const n = parseInt(m[1], 10);
  // atoi clamps on overflow to INT_MAX/INT_MIN
  if (n > 2147483647) return 2147483647;
  if (n < -2147483648) return -2147483648;
  return n;
}

// to_number<T> via stringstream: invalid or trailing garbage → def_value
export function toNumber(value: string | number, defValue = 0): number {
  const s = String(value);
  const m = /^[ \t\n\v\f\r]*([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)/.exec(s);
  if (!m || m[0].length !== s.length) return defValue;
  return Number(m[1]);
}

// getUrlArg(url, request): finds last "request=" preceded by start/'&'/'?', value up to next '&'
export function getUrlArg(url: string, request: string): string {
  const pattern = request + "=";
  let pos = url.length;
  while (pos) {
    pos = url.lastIndexOf(pattern, pos);
    if (pos !== -1) {
      if (pos === 0 || url[pos - 1] === "&" || url[pos - 1] === "?") {
        pos += pattern.length;
        const amp = url.indexOf("&", pos);
        return amp === -1 ? url.substring(pos) : url.substring(pos, amp);
      }
    } else break;
    pos--;
  }
  return "";
}

export function randomStr(len: number): string {
  let retData = "";
  for (let i = 0; i < len; i++) {
    const r = Math.floor(Math.random() * 62);
    if (r < 26) retData += String.fromCharCode(97 + r);
    else if (r < 52) retData += String.fromCharCode(65 + r - 26);
    else retData += String.fromCharCode(48 + r - 52);
  }
  return retData;
}

export function isStrUTF8(data: string): boolean {
  // operate on UTF-8 bytes like the C++ version
  const bytes = new TextEncoder().encode(data);
  let nBytes = 0;
  for (let i = 0; i < bytes.length; i++) {
    const chr = bytes[i];
    if (nBytes === 0) {
      if (chr >= 0x80) {
        if (chr >= 0xfc && chr <= 0xfd) nBytes = 6;
        else if (chr >= 0xf8) nBytes = 5;
        else if (chr >= 0xf0) nBytes = 4;
        else if (chr >= 0xe0) nBytes = 3;
        else if (chr >= 0xc0) nBytes = 2;
        else return false;
        nBytes--;
      }
    } else {
      if ((chr & 0xc0) !== 0x80) return false;
      nBytes--;
    }
  }
  return nBytes === 0;
}

export function processEscapeChar(str: string): string {
  // handles \n \r \t; other backslashes kept as-is (backward compat)
  let pos = str.indexOf("\\");
  if (pos === -1) return str;
  let out = str;
  while (pos !== -1) {
    if (pos === out.length - 1) break;
    const next = out[pos + 1];
    if (next === "n" || next === "r" || next === "t") {
      out = out.substring(0, pos) + (next === "n" ? "\n" : next === "r" ? "\r" : "\t") + out.substring(pos + 2);
    }
    pos = out.indexOf("\\", pos + 1);
  }
  return out;
}

export function processEscapeCharReverse(str: string): string {
  return str.replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t");
}

export type StringPair = [string, string];

export const NONAME = "{NONAME}";

export function parseCommaKeyValue(input: string, separator: string): StringPair[] {
  const result: StringPair[] = [];
  let bpos = 0;
  let epos = input.indexOf(separator);
  let kv = "";
  const ilen = input.length;
  while (bpos < ilen) {
    if (epos === -1) epos = ilen;
    else if (epos > 0 && input[epos - 1] === "\\") {
      kv += input.substring(bpos, epos - 1);
      kv += separator;
      bpos = epos + 1;
      epos = input.indexOf(separator, bpos);
      continue;
    }
    kv += input.substring(bpos, epos);
    const eqpos = kv.indexOf("=");
    if (eqpos === -1) result.push([NONAME, kv]);
    else result.push([kv.substring(0, eqpos), kv.substring(eqpos + 1)]);
    kv = "";
    bpos = epos + 1;
    epos = input.indexOf(separator, bpos);
  }
  if (kv.length > 0) {
    const eqpos = kv.indexOf("=");
    if (eqpos === -1) result.push([NONAME, kv]);
    else result.push([kv.substring(0, eqpos), kv.substring(eqpos + 1)]);
  }
  return result;
}

export function UTF8ToCodePoint(data: string): string {
  const bytes = new TextEncoder().encode(data);
  let out = "";
  const hex = (n: number) => n.toString(16);
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if (c >> 7 === 0) {
      out += String.fromCharCode(c);
    } else if (c >> 5 === 6) {
      out += "\\u" + hex(((bytes[i + 1] & 0x3f) | ((c & 0x1f) << 6)) >>> 0);
      i++;
    } else if (c >> 4 === 14) {
      out += "\\u" + hex(((bytes[i + 2] & 0x3f) | ((bytes[i + 1] & 0x3f) << 6) | ((c & 0xf) << 12)) >>> 0);
      i += 2;
    } else if (c >> 3 === 30) {
      out += "\\u" + hex(((bytes[i + 3] & 0x3f) | ((bytes[i + 2] & 0x3f) << 6) | ((bytes[i + 1] & 0x3f) << 12) | ((c & 0x7) << 18)) >>> 0);
      i += 3;
    }
  }
  return out;
}
