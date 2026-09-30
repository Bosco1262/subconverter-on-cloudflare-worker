// Standard MD5 (RFC 1321) — equivalent to src/utils/md5/md5.cpp
// Operates on UTF-8 bytes, returns lowercase hex digest.

const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];

const K = new Int32Array(64);
for (let i = 0; i < 64; i++) {
  K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;
}

function toBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function rotl(x: number, c: number): number {
  return (x << c) | (x >>> (32 - c));
}

export function md5Bytes(input: Uint8Array): string {
  const origLen = input.length;
  // padding
  const totalLen = ((origLen + 8) >> 6) * 64 + 64;
  const msg = new Uint8Array(totalLen);
  msg.set(input);
  msg[origLen] = 0x80;
  const bitLen = origLen * 8;
  for (let i = 0; i < 8; i++) {
    msg[totalLen - 8 + i] = (bitLen >>> (8 * i)) & 0xff;
  }

  let a0 = 0x67452301 | 0;
  let b0 = 0xefcdab89 | 0;
  let c0 = 0x98badcfe | 0;
  let d0 = 0x10325476 | 0;

  const m = new Int32Array(16);
  for (let chunk = 0; chunk < totalLen; chunk += 64) {
    for (let j = 0; j < 16; j++) {
      const o = chunk + j * 4;
      m[j] = (msg[o] | (msg[o + 1] << 8) | (msg[o + 2] << 16) | (msg[o + 3] << 24)) | 0;
    }
    let A = a0, B = b0, C = c0, D = d0;
    for (let j = 0; j < 64; j++) {
      let F = 0;
      let g = 0;
      if (j < 16) {
        F = (B & C) | (~B & D);
        g = j;
      } else if (j < 32) {
        F = (D & B) | (~D & C);
        g = (5 * j + 1) % 16;
      } else if (j < 48) {
        F = B ^ C ^ D;
        g = (3 * j + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * j) % 16;
      }
      F = (F + A + K[j] + m[g]) | 0;
      A = D;
      D = C;
      C = B;
      B = (B + rotl(F, S[j])) | 0;
    }
    a0 = (a0 + A) | 0;
    b0 = (b0 + B) | 0;
    c0 = (c0 + C) | 0;
    d0 = (d0 + D) | 0;
  }

  const out = new Uint8Array(16);
  const words = [a0, b0, c0, d0];
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) {
      out[i * 4 + j] = (words[i] >>> (8 * j)) & 0xff;
    }
  }
  return [...out].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function md5(str: string): string {
  return md5Bytes(toBytes(str));
}
