import crypto from "node:crypto";

import { BitArray$BitArray, Result$Error, Result$Ok } from "./gleam.mjs";
import { aead_cipher_name, aead_cipher_key } from "./kryptos/aead.mjs";
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

export function pbkdf2Derive(algorithm, password, salt, iterations, length) {
  try {
    const name = algorithm_name(algorithm);
    const result = crypto.pbkdf2Sync(
      password.rawBuffer,
      salt.rawBuffer,
      iterations,
      length,
      name,
    );
    return Result$Ok(BitArray$BitArray(result));
  } catch {
    return Result$Error(undefined);
  }
}

export function aeadSeal(mode, nonce, plaintext, aad) {
  const name = aead_cipher_name(mode);
  const key = aead_cipher_key(mode);
  const cipher = crypto.createCipheriv(name, key.rawBuffer, nonce.rawBuffer);
  cipher.setAAD(aad.rawBuffer);

  const updateOutput = cipher.update(plaintext.rawBuffer);
  const finalOutput = cipher.final();
  const ciphertext = Buffer.concat([updateOutput, finalOutput]);
  const tag = cipher.getAuthTag();
  return Result$Ok([BitArray$BitArray(ciphertext), BitArray$BitArray(tag)]);
}

export function aeadOpen(mode, nonce, tag, ciphertext, aad) {
  try {
    const name = aead_cipher_name(mode);
    const key = aead_cipher_key(mode);
    const decipher = crypto.createDecipheriv(
      name,
      key.rawBuffer,
      nonce.rawBuffer,
    );
    decipher.setAAD(aad.rawBuffer);
    decipher.setAuthTag(tag.rawBuffer);

    const updateOutput = decipher.update(ciphertext.rawBuffer);
    const finalOutput = decipher.final();
    const plaintext = Buffer.concat([updateOutput, finalOutput]);
    return Result$Ok(BitArray$BitArray(plaintext));
  } catch {
    return Result$Error(undefined);
  }
}

function ecCurveName(curve) {
  switch (curve.constructor.name) {
    case "P224":
      return "secp224r1";
    case "P256":
      return "prime256v1";
    case "P384":
      return "secp384r1";
    case "P521":
      return "secp521r1";
    case "Secp256k1":
      return "secp256k1";
    default:
      throw new Error(`Unsupported curve: ${curve.constructor.name}`);
  }
}

export function ecGenerateKeyPair(curve) {
  const curveName = ecCurveName(curve);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: curveName,
  });

  return [privateKey, publicKey];
}

export function ecdsaSign(privateKey, message, hashAlgorithm) {
  const algorithmName = algorithm_name(hashAlgorithm);
  const signature = crypto.sign(algorithmName, message.rawBuffer, {
    key: privateKey,
    dsaEncoding: "der",
  });
  return BitArray$BitArray(signature);
}

export function ecdsaVerify(publicKey, message, signature, hashAlgorithm) {
  try {
    const algorithmName = algorithm_name(hashAlgorithm);
    return crypto.verify(
      algorithmName,
      message.rawBuffer,
      {
        key: publicKey,
        dsaEncoding: "der",
      },
      signature.rawBuffer,
    );
  } catch {
    return false;
  }
}
