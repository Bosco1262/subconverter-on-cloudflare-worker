// Port of src/utils/base64/base64.cpp — lenient decode: non-base64 chars copied verbatim, stops at '='

const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const DTABLE = new Int16Array(256).fill(-1);
const ITABLE = new Uint8Array(256);
for (let k = 0; k < BASE64_CHARS.length; k++) {
  DTABLE[BASE64_CHARS.charCodeAt(k)] = k;
  ITABLE[BASE64_CHARS.charCodeAt(k)] = 1;
}
DTABLE["-".charCodeAt(0)] = DTABLE["+".charCodeAt(0)];
ITABLE["-".charCodeAt(0)] = 2;
DTABLE["_".charCodeAt(0)] = DTABLE["/".charCodeAt(0)];
ITABLE["_".charCodeAt(0)] = 2;

const decoder = new TextDecoder("utf-8");

export function base64Encode(stringToEncode: string): string {
  const bytes = new TextEncoder().encode(stringToEncode);
  let ret = "";
  const len = bytes.length;
  let i = 0;
  for (; i + 2 < len; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    ret += BASE64_CHARS[(n >> 18) & 0x3f] + BASE64_CHARS[(n >> 12) & 0x3f] + BASE64_CHARS[(n >> 6) & 0x3f] + BASE64_CHARS[n & 0x3f];
  }
  const rem = len - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    ret += BASE64_CHARS[(n >> 18) & 0x3f] + BASE64_CHARS[(n >> 12) & 0x3f] + "==";
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    ret += BASE64_CHARS[(n >> 18) & 0x3f] + BASE64_CHARS[(n >> 12) & 0x3f] + BASE64_CHARS[(n >> 6) & 0x3f] + "=";
  }
  return ret;
}

export function base64Decode(encodedString: string, acceptUrlsafe = false): string {
  const len = encodedString.length;
  const out: number[] = [];
  const charArray4: number[] = [0, 0, 0, 0];
  let i = 0;
  let in_ = 0;
  while (in_ < len && encodedString[in_] !== "=") {
    const uchar = encodedString.charCodeAt(in_) & 0xff;
    const valid = acceptUrlsafe ? ITABLE[uchar] : ITABLE[uchar] === 1;
    if (!valid) {
      // not base64 data — copy verbatim (C++ behavior)
      out.push(uchar);
      in_++;
      i = 0;
      continue;
    }
    charArray4[i++] = uchar;
    in_++;
    if (i === 4) {
      const d0 = DTABLE[charArray4[0]], d1 = DTABLE[charArray4[1]], d2 = DTABLE[charArray4[2]], d3 = DTABLE[charArray4[3]];
      out.push((d0 << 2) + ((d1 & 0x30) >> 4));
      out.push(((d1 & 0xf) << 4) + ((d2 & 0x3c) >> 2));
      out.push(((d2 & 0x3) << 6) + d3);
      i = 0;
    }
  }
  if (i) {
    for (let j = i; j < 4; j++) charArray4[j] = 0;
    const d0 = DTABLE[charArray4[0]], d1 = DTABLE[charArray4[1]], d2 = DTABLE[charArray4[2]], d3 = DTABLE[charArray4[3]];
    const bytes = [
      (d0 << 2) + ((d1 & 0x30) >> 4),
      ((d1 & 0xf) << 4) + ((d2 & 0x3c) >> 2),
      ((d2 & 0x3) << 6) + d3,
    ];
    for (let j = 0; j < i - 1; j++) out.push(bytes[j]);
  }
  return decoder.decode(new Uint8Array(out));
}

export function urlSafeBase64Reverse(encodedString: string): string {
  return encodedFileReplace(encodedString);
}
function encodedFileReplace(s: string): string {
  return s.split("-").join("+").split("_").join("/");
}

export function urlSafeBase64Apply(encodedString: string): string {
  return encodedString.split("+").join("-").split("/").join("_").split("=").join("");
}

export function urlSafeBase64Decode(encodedString: string): string {
  return base64Decode(encodedString, true);
}

export function urlSafeBase64Encode(stringToEncode: string): string {
  return urlSafeBase64Apply(base64Encode(stringToEncode));
}
