import { BitArray$BitArray } from "../../gleam.mjs";

export function subkey(key, input) {
  const kv = new DataView(key.rawBuffer.buffer, key.rawBuffer.byteOffset, 32);
  const iv = new DataView(
    input.rawBuffer.buffer,
    input.rawBuffer.byteOffset,
    16,
  );

  // "expand 32-byte k" constants
  let s0 = 0x61707865;
  let s1 = 0x3320646e;
  let s2 = 0x79622d32;
  let s3 = 0x6b206574;
  let s4 = kv.getUint32(0, true);
  let s5 = kv.getUint32(4, true);
  let s6 = kv.getUint32(8, true);
  let s7 = kv.getUint32(12, true);
  let s8 = kv.getUint32(16, true);
  let s9 = kv.getUint32(20, true);
  let s10 = kv.getUint32(24, true);
  let s11 = kv.getUint32(28, true);
  let s12 = iv.getUint32(0, true);
  let s13 = iv.getUint32(4, true);
  let s14 = iv.getUint32(8, true);
  let s15 = iv.getUint32(12, true);

  for (let i = 0; i < 10; i++) {
    // Column round: QR(0,4,8,12) QR(1,5,9,13) QR(2,6,10,14) QR(3,7,11,15)
    s0 = (s0 + s4) | 0;
    s12 ^= s0;
    s12 = (s12 << 16) | (s12 >>> 16);
    s8 = (s8 + s12) | 0;
    s4 ^= s8;
    s4 = (s4 << 12) | (s4 >>> 20);
    s0 = (s0 + s4) | 0;
    s12 ^= s0;
    s12 = (s12 << 8) | (s12 >>> 24);
    s8 = (s8 + s12) | 0;
    s4 ^= s8;
    s4 = (s4 << 7) | (s4 >>> 25);

    s1 = (s1 + s5) | 0;
    s13 ^= s1;
    s13 = (s13 << 16) | (s13 >>> 16);
    s9 = (s9 + s13) | 0;
    s5 ^= s9;
    s5 = (s5 << 12) | (s5 >>> 20);
    s1 = (s1 + s5) | 0;
    s13 ^= s1;
    s13 = (s13 << 8) | (s13 >>> 24);
    s9 = (s9 + s13) | 0;
    s5 ^= s9;
    s5 = (s5 << 7) | (s5 >>> 25);

    s2 = (s2 + s6) | 0;
    s14 ^= s2;
    s14 = (s14 << 16) | (s14 >>> 16);
    s10 = (s10 + s14) | 0;
    s6 ^= s10;
    s6 = (s6 << 12) | (s6 >>> 20);
    s2 = (s2 + s6) | 0;
    s14 ^= s2;
    s14 = (s14 << 8) | (s14 >>> 24);
    s10 = (s10 + s14) | 0;
    s6 ^= s10;
    s6 = (s6 << 7) | (s6 >>> 25);

    s3 = (s3 + s7) | 0;
    s15 ^= s3;
    s15 = (s15 << 16) | (s15 >>> 16);
    s11 = (s11 + s15) | 0;
    s7 ^= s11;
    s7 = (s7 << 12) | (s7 >>> 20);
    s3 = (s3 + s7) | 0;
    s15 ^= s3;
    s15 = (s15 << 8) | (s15 >>> 24);
    s11 = (s11 + s15) | 0;
    s7 ^= s11;
    s7 = (s7 << 7) | (s7 >>> 25);

    // Diagonal round: QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13) QR(3,4,9,14)
    s0 = (s0 + s5) | 0;
    s15 ^= s0;
    s15 = (s15 << 16) | (s15 >>> 16);
    s10 = (s10 + s15) | 0;
    s5 ^= s10;
    s5 = (s5 << 12) | (s5 >>> 20);
    s0 = (s0 + s5) | 0;
    s15 ^= s0;
    s15 = (s15 << 8) | (s15 >>> 24);
    s10 = (s10 + s15) | 0;
    s5 ^= s10;
    s5 = (s5 << 7) | (s5 >>> 25);

    s1 = (s1 + s6) | 0;
    s12 ^= s1;
    s12 = (s12 << 16) | (s12 >>> 16);
    s11 = (s11 + s12) | 0;
    s6 ^= s11;
    s6 = (s6 << 12) | (s6 >>> 20);
    s1 = (s1 + s6) | 0;
    s12 ^= s1;
    s12 = (s12 << 8) | (s12 >>> 24);
    s11 = (s11 + s12) | 0;
    s6 ^= s11;
    s6 = (s6 << 7) | (s6 >>> 25);

    s2 = (s2 + s7) | 0;
    s13 ^= s2;
    s13 = (s13 << 16) | (s13 >>> 16);
    s8 = (s8 + s13) | 0;
    s7 ^= s8;
    s7 = (s7 << 12) | (s7 >>> 20);
    s2 = (s2 + s7) | 0;
    s13 ^= s2;
    s13 = (s13 << 8) | (s13 >>> 24);
    s8 = (s8 + s13) | 0;
    s7 ^= s8;
    s7 = (s7 << 7) | (s7 >>> 25);

    s3 = (s3 + s4) | 0;
    s14 ^= s3;
    s14 = (s14 << 16) | (s14 >>> 16);
    s9 = (s9 + s14) | 0;
    s4 ^= s9;
    s4 = (s4 << 12) | (s4 >>> 20);
    s3 = (s3 + s4) | 0;
    s14 ^= s3;
    s14 = (s14 << 8) | (s14 >>> 24);
    s9 = (s9 + s14) | 0;
    s4 ^= s9;
    s4 = (s4 << 7) | (s4 >>> 25);
  }

  const out = new DataView(new ArrayBuffer(32));
  out.setUint32(0, s0, true);
  out.setUint32(4, s1, true);
  out.setUint32(8, s2, true);
  out.setUint32(12, s3, true);
  out.setUint32(16, s12, true);
  out.setUint32(20, s13, true);
  out.setUint32(24, s14, true);
  out.setUint32(28, s15, true);

  return BitArray$BitArray(new Uint8Array(out.buffer));
}
