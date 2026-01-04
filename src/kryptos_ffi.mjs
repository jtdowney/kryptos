import crypto from "node:crypto";
import { BitArray$BitArray } from "./gleam.mjs";
import { algorithm_name } from "./kryptos/hash.mjs";

export function randomBytes(length) {
  if (length < 0) {
    length = 0;
  }

  const buffer = crypto.randomBytes(length);
  return BitArray$BitArray(buffer);
}

export function constantTimeEqual(a, b) {
  if (a.byteSize !== b.byteSize) {
    return false;
  }

  return crypto.timingSafeEqual(a.rawBuffer, b.rawBuffer);
}

export function hashNew(algorithm) {
  const name = algorithm_name(algorithm);
  return crypto.createHash(name);
}

export function hashUpdate(hasher, input) {
  hasher.update(input.rawBuffer);
  return hasher;
}

export function hashFinal(hasher) {
  const digest = hasher.digest();
  return BitArray$BitArray(digest);
}
