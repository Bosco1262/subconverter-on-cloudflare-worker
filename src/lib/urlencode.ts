// Port of src/utils/urlencode.cpp — byte-wise, uppercase hex, '+' → space on decode

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8");

function isAlphaNum(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function toHex(x: number): string {
  return x > 9 ? String.fromCharCode(x + 55) : String.fromCharCode(x + 48);
}

function fromHex(code: number): number {
  if (code >= 65 && code <= 90) return code - 65 + 10;
  if (code >= 97 && code <= 122) return code - 97 + 10;
  if (code >= 48 && code <= 57) return code - 48;
  return code;
}

export function urlEncode(str: string): string {
  const bytes = encoder.encode(str);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if (isAlphaNum(c) || c === 45 || c === 95 || c === 46 || c === 126) {
      out += String.fromCharCode(c);
    } else {
      out += "%" + toHex(c >> 4) + toHex(c % 16);
    }
  }
  return out;
}

export function urlDecode(str: string): string {
  const bytes = encoder.encode(str);
  const out: number[] = [];
  const length = bytes.length;
  for (let i = 0; i < length; i++) {
    const c = bytes[i];
    if (c === 43) {
      out.push(32);
    } else if (c === 37) {
      if (i + 2 >= length) return decoder.decode(new Uint8Array(out));
      if (isAlphaNum(bytes[i + 1]) && isAlphaNum(bytes[i + 2])) {
        const high = fromHex(bytes[++i]);
        const low = fromHex(bytes[++i]);
        out.push(high * 16 + low);
      } else {
        out.push(c);
      }
    } else {
      out.push(c);
    }
  }
  return decoder.decode(new Uint8Array(out));
}

export function joinArguments(args: [string, string][]): string {
  let out = "";
  for (const [k, v] of args) {
    out += k + "=" + urlEncode(v) + "&";
  }
  if (out.length > 0) out = out.substring(0, out.length - 1);
  return out;
}
