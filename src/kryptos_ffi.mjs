import crypto from "node:crypto";
import { BitArray } from "./gleam.mjs";

export function randomBytes(length) {
  if (length < 0) {
    length = 0;
  }

  const buffer = crypto.randomBytes(length);
  return new BitArray(buffer);
}

export function constantTimeEqual(a, b) {
  if (a.byteSize !== b.byteSize) {
    return false;
  }

  return crypto.timingSafeEqual(a.rawBuffer, b.rawBuffer);
}
