import crypto from "node:crypto";

import { BitArray$BitArray, Result$Error, Result$Ok } from "./gleam.mjs";
import { aead_cipher_name, aead_cipher_key } from "./kryptos/aead.mjs";
import { algorithm_name } from "./kryptos/hash.mjs";
import { key_size as xdh_key_size } from "./kryptos/xdh.mjs";

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

function ecCurveToJwkCrv(curveName) {
  switch (curveName) {
    case "prime256v1":
      return "P-256";
    case "secp384r1":
      return "P-384";
    case "secp521r1":
      return "P-521";
    case "secp256k1":
      return "secp256k1";
    default:
      throw new Error(`Unsupported curve: ${curveName}`);
  }
}

function ecCurveCoordSize(curveName) {
  switch (curveName) {
    case "prime256v1":
    case "secp256k1":
      return 32;
    case "secp384r1":
      return 48;
    case "secp521r1":
      return 66;
    default:
      throw new Error(`Unsupported curve: ${curveName}`);
  }
}

export function ecPrivateKeyFromBytes(curve, privateScalar) {
  try {
    const curveName = ecCurveName(curve);
    const coordSize = ecCurveCoordSize(curveName);

    // Use ECDH to compute the public point from the private scalar
    const ecdh = crypto.createECDH(curveName);
    const privBuffer = Buffer.from(privateScalar.rawBuffer);
    ecdh.setPrivateKey(privBuffer);
    const publicPoint = ecdh.getPublicKey();

    // Public point is in uncompressed format: 0x04 || x || y
    const x = publicPoint.subarray(1, 1 + coordSize);
    const y = publicPoint.subarray(1 + coordSize);

    // Create JWK with all required fields
    // Must use Buffer for base64url encoding
    const jwk = {
      kty: "EC",
      crv: ecCurveToJwkCrv(curveName),
      x: Buffer.from(x).toString("base64url"),
      y: Buffer.from(y).toString("base64url"),
      d: privBuffer.toString("base64url"),
    };

    const privateKey = crypto.createPrivateKey({ key: jwk, format: "jwk" });
    const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });

    return Result$Ok([privateKey, publicKey]);
  } catch {
    return Result$Error(undefined);
  }
}

// OID for ecPublicKey (1.2.840.10045.2.1)
const EC_PUBLIC_KEY_OID = Buffer.from([
  0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
]);

function validateSpkiUsesNamedCurve(derBytes) {
  const buf = Buffer.from(derBytes);
  const oidIndex = buf.indexOf(EC_PUBLIC_KEY_OID);
  if (oidIndex === -1) {
    return false;
  }

  const paramTagIndex = oidIndex + EC_PUBLIC_KEY_OID.length;
  if (paramTagIndex >= buf.length) {
    return false;
  }

  const paramTag = buf[paramTagIndex];
  return paramTag === 0x06;
}

export function ecPublicKeyFromX509(derBytes) {
  try {
    if (!validateSpkiUsesNamedCurve(derBytes.rawBuffer)) {
      return Result$Error(undefined);
    }

    const publicKey = crypto.createPublicKey({
      key: derBytes.rawBuffer,
      format: "der",
      type: "spki",
    });
    return Result$Ok(publicKey);
  } catch {
    return Result$Error(undefined);
  }
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

export function ecdhComputeSharedSecret(privateKey, peerPublicKey) {
  try {
    const sharedSecret = crypto.diffieHellman({
      privateKey: privateKey,
      publicKey: peerPublicKey,
    });
    return Result$Ok(BitArray$BitArray(sharedSecret));
  } catch {
    return Result$Error(undefined);
  }
}

export function xdhGenerateKeyPair(curve) {
  const curveName = curve.constructor.name.toLowerCase();
  const { privateKey, publicKey } = crypto.generateKeyPairSync(curveName);
  return [privateKey, publicKey];
}

export function xdhComputeSharedSecret(privateKey, peerPublicKey) {
  try {
    const sharedSecret = crypto.diffieHellman({
      privateKey: privateKey,
      publicKey: peerPublicKey,
    });
    return Result$Ok(BitArray$BitArray(sharedSecret));
  } catch {
    return Result$Error(undefined);
  }
}

// DER prefixes for X25519/X448 keys
const XDH_PRIVATE_DER_PREFIX = {
  x25519: Buffer.from("302e020100300506032b656e04220420", "hex"),
  x448: Buffer.from("3046020100300506032b656f043a0438", "hex"),
};

const XDH_PUBLIC_DER_PREFIX = {
  x25519: Buffer.from("302a300506032b656e032100", "hex"),
  x448: Buffer.from("3042300506032b656f033900", "hex"),
};

export function xdhPrivateKeyFromBytes(curve, privateBytes) {
  try {
    const curveName = curve.constructor.name.toLowerCase();
    const expectedSize = xdh_key_size(curve);
    if (privateBytes.byteSize !== expectedSize) {
      return Result$Error(undefined);
    }
    const prefix = XDH_PRIVATE_DER_PREFIX[curveName];
    const der = Buffer.concat([prefix, Buffer.from(privateBytes.rawBuffer)]);
    const privateKey = crypto.createPrivateKey({
      key: der,
      format: "der",
      type: "pkcs8",
    });
    const publicKey = crypto.createPublicKey(privateKey);
    return Result$Ok([privateKey, publicKey]);
  } catch {
    return Result$Error(undefined);
  }
}

export function xdhPublicKeyFromBytes(curve, publicBytes) {
  try {
    const curveName = curve.constructor.name.toLowerCase();
    const expectedSize = xdh_key_size(curve);
    if (publicBytes.byteSize !== expectedSize) {
      return Result$Error(undefined);
    }
    const prefix = XDH_PUBLIC_DER_PREFIX[curveName];
    const der = Buffer.concat([prefix, Buffer.from(publicBytes.rawBuffer)]);
    const publicKey = crypto.createPublicKey({
      key: der,
      format: "der",
      type: "spki",
    });
    return Result$Ok(publicKey);
  } catch {
    return Result$Error(undefined);
  }
}
