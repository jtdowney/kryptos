import crypto from "node:crypto";
import { BitArray$BitArray, Result$Ok } from "./gleam.mjs";
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

export function hmacNew(algorithm, key) {
  const algorithmName = algorithm_name(algorithm);
  const hmac = crypto.createHmac(algorithmName, key.rawBuffer);
  return hmac;
}

export function hmacUpdate(hmac, data) {
  hmac.update(data.rawBuffer);
  return hmac;
}

export function hmacFinal(hmac) {
  const digest = hmac.digest();
  return BitArray$BitArray(digest);
}

export function hkdfDerive(algorithm, ikm, salt, info, length) {
  try {
    const name = algorithm_name(algorithm);
    const result = crypto.hkdfSync(
      name,
      ikm.rawBuffer,
      salt.rawBuffer,
      info.rawBuffer,
      length,
    );
    const buffer = new Uint8Array(result);
    return Result$Ok(BitArray$BitArray(buffer));
  } catch {
    return Result$Error(undefined);
  }
}
