import crypto from "node:crypto";

import { BitArray$BitArray, Result$Error, Result$Ok } from "./gleam.mjs";
import { tag_size } from "./kryptos/aead.mjs";
import { cipher_name, cipher_key, cipher_iv } from "./kryptos/block.mjs";
import { key_size as eddsa_key_size } from "./kryptos/eddsa.mjs";
import { algorithm_name } from "./kryptos/hash.mjs";
import { key_size as xdh_key_size } from "./kryptos/xdh.mjs";

// =============================================================================
// Utilities & Random
// =============================================================================

export function randomBytes(length) {
  if (length < 0) {
    length = 0;
  }

  const buffer = crypto.randomBytes(length);
  return BitArray$BitArray(buffer);
}

export function randomUuid() {
  return crypto.randomUUID();
}

export function constantTimeEqual(a, b) {
  if (a.byteSize !== b.byteSize) {
    return false;
  }

  return crypto.timingSafeEqual(a.rawBuffer, b.rawBuffer);
}

// =============================================================================
// Hash Functions
// =============================================================================

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

// =============================================================================
// HMAC
// =============================================================================

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

// =============================================================================
// Key Derivation Functions (HKDF, PBKDF2)
// =============================================================================

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

// =============================================================================
// AEAD Ciphers (GCM, CCM, ChaCha20-Poly1305)
// =============================================================================

function aead_cipher_name(ctx) {
  const name = ctx.constructor.name;
  if (name === "ChaCha20Poly1305") {
    return "chacha20-poly1305";
  }

  const keySize = ctx.cipher.key_size;
  const suffix = name === "Gcm" ? "gcm" : "ccm";

  switch (keySize) {
    case 128:
      return `aes-128-${suffix}`;
    case 192:
      return `aes-192-${suffix}`;
    case 256:
      return `aes-256-${suffix}`;
    default:
      throw new Error(`Unknown key size: ${keySize}`);
  }
}

function aead_cipher_key(mode) {
  const modeName = mode.constructor.name;
  if (modeName === "ChaCha20Poly1305") {
    return mode.key;
  }
  return mode.cipher.key;
}

export function aeadSeal(mode, nonce, plaintext, aad) {
  const name = aead_cipher_name(mode);
  const key = aead_cipher_key(mode);
  const tagSize = tag_size(mode);

  const isCcm = name.includes("ccm");
  const cipherOptions = isCcm ? { authTagLength: tagSize } : undefined;
  const aadOptions = isCcm
    ? { plaintextLength: plaintext.byteSize }
    : undefined;

  const cipher = crypto.createCipheriv(
    name,
    key.rawBuffer,
    nonce.rawBuffer,
    cipherOptions,
  );
  cipher.setAAD(aad.rawBuffer, aadOptions);

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
    const tagSize = tag_size(mode);

    const isCcm = name.includes("ccm");
    const cipherOptions = isCcm ? { authTagLength: tagSize } : undefined;
    const aadOptions = isCcm
      ? { plaintextLength: ciphertext.byteSize }
      : undefined;

    const decipher = crypto.createDecipheriv(
      name,
      key.rawBuffer,
      nonce.rawBuffer,
      cipherOptions,
    );
    decipher.setAAD(aad.rawBuffer, aadOptions);
    decipher.setAuthTag(tag.rawBuffer);

    const updateOutput = decipher.update(ciphertext.rawBuffer);
    const finalOutput = decipher.final();
    const plaintext = Buffer.concat([updateOutput, finalOutput]);
    return Result$Ok(BitArray$BitArray(plaintext));
  } catch {
    return Result$Error(undefined);
  }
}

// =============================================================================
// Block Ciphers (ECB, CBC, CTR)
// =============================================================================

function cipherNeedsPadding(mode) {
  const modeName = mode.constructor.name;
  return modeName !== "Ctr";
}

export function cipherEncrypt(mode, plaintext) {
  try {
    const name = cipher_name(mode);
    const key = cipher_key(mode);
    const iv = cipher_iv(mode);

    const ivBuffer = iv.byteSize === 0 ? null : iv.rawBuffer;

    const cipher = crypto.createCipheriv(name, key.rawBuffer, ivBuffer);
    cipher.setAutoPadding(cipherNeedsPadding(mode));

    const updateOutput = cipher.update(plaintext.rawBuffer);
    const finalOutput = cipher.final();
    const ciphertext = Buffer.concat([updateOutput, finalOutput]);

    return Result$Ok(BitArray$BitArray(ciphertext));
  } catch {
    return Result$Error(undefined);
  }
}

export function cipherDecrypt(mode, ciphertext) {
  try {
    const name = cipher_name(mode);
    const key = cipher_key(mode);
    const iv = cipher_iv(mode);

    const ivBuffer = iv.byteSize === 0 ? null : iv.rawBuffer;

    const decipher = crypto.createDecipheriv(name, key.rawBuffer, ivBuffer);
    decipher.setAutoPadding(cipherNeedsPadding(mode));

    const updateOutput = decipher.update(ciphertext.rawBuffer);
    const finalOutput = decipher.final();
    const plaintext = Buffer.concat([updateOutput, finalOutput]);

    return Result$Ok(BitArray$BitArray(plaintext));
  } catch {
    return Result$Error(undefined);
  }
}

// =============================================================================
// Curve Helpers (shared by EC, EdDSA, XDH)
// =============================================================================

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

// =============================================================================
// Elliptic Curve (EC/ECDSA/ECDH)
// =============================================================================

export function ecGenerateKeyPair(curve) {
  const curveName = ecCurveName(curve);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: curveName,
  });

  return [privateKey, publicKey];
}

export function ecPrivateKeyFromBytes(curve, privateScalar) {
  try {
    const curveName = ecCurveName(curve);
    const coordSize = ecCurveCoordSize(curveName);

    const ecdh = crypto.createECDH(curveName);
    const privBuffer = Buffer.from(privateScalar.rawBuffer);
    ecdh.setPrivateKey(privBuffer);
    const publicPoint = ecdh.getPublicKey();

    const x = publicPoint.subarray(1, 1 + coordSize);
    const y = publicPoint.subarray(1 + coordSize);

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

export function ecPublicKeyFromRawPoint(curve, point) {
  try {
    const curveName = ecCurveName(curve);
    const coordSize = ecCurveCoordSize(curveName);
    const expectedSize = 1 + 2 * coordSize;

    if (point.byteSize !== expectedSize) {
      return Result$Error(undefined);
    }

    const pointBuffer = Buffer.from(point.rawBuffer);

    if (pointBuffer[0] !== 0x04) {
      return Result$Error(undefined);
    }

    const x = pointBuffer.subarray(1, 1 + coordSize);
    const y = pointBuffer.subarray(1 + coordSize);

    const jwk = {
      kty: "EC",
      crv: ecCurveToJwkCrv(curveName),
      x: x.toString("base64url"),
      y: y.toString("base64url"),
    };

    const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
    return Result$Ok(publicKey);
  } catch {
    return Result$Error(undefined);
  }
}

function jwkCrvToEcCurveName(crv) {
  switch (crv) {
    case "P-256":
      return "prime256v1";
    case "P-384":
      return "secp384r1";
    case "P-521":
      return "secp521r1";
    case "secp256k1":
      return "secp256k1";
    default:
      throw new Error(`Unknown curve: ${crv}`);
  }
}

function padStart(buffer, length) {
  if (buffer.length >= length) return buffer;
  const padding = Buffer.alloc(length - buffer.length, 0);
  return Buffer.concat([padding, buffer]);
}

export function ecPublicKeyToRawPoint(key) {
  const jwk = key.export({ format: "jwk" });
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");

  const coordSize = ecCurveCoordSize(jwkCrvToEcCurveName(jwk.crv));
  const xPadded = padStart(x, coordSize);
  const yPadded = padStart(y, coordSize);

  return BitArray$BitArray(
    Buffer.concat([Buffer.from([0x04]), xPadded, yPadded]),
  );
}

export function ecPublicKeyFromPrivate(privateKey) {
  return crypto.createPublicKey(privateKey);
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

// EC Import/Export Helpers

function importPrivateKeyPem(pem, type, allowedTypes) {
  try {
    const privateKey = crypto.createPrivateKey({
      key: pem,
      format: "pem",
      type: type,
    });

    if (!allowedTypes.includes(privateKey.asymmetricKeyType)) {
      return Result$Error(undefined);
    }

    const publicKey = crypto.createPublicKey(privateKey);
    return Result$Ok([privateKey, publicKey]);
  } catch {
    return Result$Error(undefined);
  }
}

function importPrivateKeyDer(der, type, allowedTypes) {
  try {
    const privateKey = crypto.createPrivateKey({
      key: der.rawBuffer,
      format: "der",
      type: type,
    });

    if (!allowedTypes.includes(privateKey.asymmetricKeyType)) {
      return Result$Error(undefined);
    }

    const publicKey = crypto.createPublicKey(privateKey);
    return Result$Ok([privateKey, publicKey]);
  } catch {
    return Result$Error(undefined);
  }
}

function importPublicKeyPem(pem, type, allowedTypes) {
  try {
    const publicKey = crypto.createPublicKey({
      key: pem,
      format: "pem",
      type: type,
    });

    if (!allowedTypes.includes(publicKey.asymmetricKeyType)) {
      return Result$Error(undefined);
    }

    return Result$Ok(publicKey);
  } catch {
    return Result$Error(undefined);
  }
}

function importPublicKeyDer(der, type, allowedTypes, validate) {
  try {
    if (validate && !validate(der.rawBuffer)) {
      return Result$Error(undefined);
    }

    const publicKey = crypto.createPublicKey({
      key: der.rawBuffer,
      format: "der",
      type: type,
    });

    if (!allowedTypes.includes(publicKey.asymmetricKeyType)) {
      return Result$Error(undefined);
    }

    return Result$Ok(publicKey);
  } catch {
    return Result$Error(undefined);
  }
}

// EC Import Functions

export function ecImportPrivateKeyPem(pem) {
  return importPrivateKeyPem(pem, "pkcs8", ["ec"]);
}

export function ecImportPrivateKeyDer(der) {
  return importPrivateKeyDer(der, "pkcs8", ["ec"]);
}

export function ecImportPublicKeyPem(pem) {
  return importPublicKeyPem(pem, "spki", ["ec"]);
}

export function ecImportPublicKeyDer(der) {
  return importPublicKeyDer(der, "spki", ["ec"], validateSpkiUsesNamedCurve);
}

// EC Export Functions

export function ecExportPrivateKeyPem(key) {
  try {
    const exported = key.export({ format: "pem", type: "pkcs8" });
    return Result$Ok(exported);
  } catch {
    return Result$Error(undefined);
  }
}

export function ecExportPrivateKeyDer(key) {
  try {
    const exported = key.export({ format: "der", type: "pkcs8" });
    return Result$Ok(BitArray$BitArray(exported));
  } catch {
    return Result$Error(undefined);
  }
}

export function ecExportPublicKeyPem(key) {
  try {
    const exported = key.export({ format: "pem", type: "spki" });
    return Result$Ok(exported);
  } catch {
    return Result$Error(undefined);
  }
}

export function ecExportPublicKeyDer(key) {
  try {
    const exported = key.export({ format: "der", type: "spki" });
    return Result$Ok(BitArray$BitArray(exported));
  } catch {
    return Result$Error(undefined);
  }
}

// =============================================================================
// X25519/X448 Key Exchange (XDH)
// =============================================================================

const XDH_PRIVATE_DER_PREFIX = {
  x25519: Buffer.from("302e020100300506032b656e04220420", "hex"),
  x448: Buffer.from("3046020100300506032b656f043a0438", "hex"),
};

const XDH_PUBLIC_DER_PREFIX = {
  x25519: Buffer.from("302a300506032b656e032100", "hex"),
  x448: Buffer.from("3042300506032b656f033900", "hex"),
};

export function xdhGenerateKeyPair(curve) {
  const curveName = curve.constructor.name.toLowerCase();
  const { privateKey, publicKey } = crypto.generateKeyPairSync(curveName);
  return [privateKey, publicKey];
}

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

export function xdhPublicKeyFromPrivate(privateKey) {
  return crypto.createPublicKey(privateKey);
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

// XDH Import Functions

export function xdhImportPrivateKeyPem(pem) {
  return importPrivateKeyPem(pem, "pkcs8", ["x25519", "x448"]);
}

export function xdhImportPrivateKeyDer(der) {
  return importPrivateKeyDer(der, "pkcs8", ["x25519", "x448"]);
}

export function xdhImportPublicKeyPem(pem) {
  return importPublicKeyPem(pem, "spki", ["x25519", "x448"]);
}

export function xdhImportPublicKeyDer(der) {
  return importPublicKeyDer(der, "spki", ["x25519", "x448"]);
}

// XDH Export Functions

export function xdhExportPrivateKeyPem(key) {
  try {
    const exported = key.export({ format: "pem", type: "pkcs8" });
    return Result$Ok(exported);
  } catch {
    return Result$Error(undefined);
  }
}

export function xdhExportPrivateKeyDer(key) {
  try {
    const exported = key.export({ format: "der", type: "pkcs8" });
    return Result$Ok(BitArray$BitArray(exported));
  } catch {
    return Result$Error(undefined);
  }
}

export function xdhExportPublicKeyPem(key) {
  try {
    const exported = key.export({ format: "pem", type: "spki" });
    return Result$Ok(exported);
  } catch {
    return Result$Error(undefined);
  }
}

export function xdhExportPublicKeyDer(key) {
  try {
    const exported = key.export({ format: "der", type: "spki" });
    return Result$Ok(BitArray$BitArray(exported));
  } catch {
    return Result$Error(undefined);
  }
}

// =============================================================================
// RSA
// =============================================================================

export function rsaGenerateKeyPair(bits) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: bits,
    publicExponent: 65537,
  });
  return [privateKey, publicKey];
}

export function rsaPublicKeyFromPrivate(privateKey) {
  return crypto.createPublicKey(privateKey);
}

// RSA Signing

function rsaPssSaltLength(saltLength) {
  const name = saltLength.constructor.name;
  switch (name) {
    case "SaltLengthHashLen":
      return crypto.constants.RSA_PSS_SALTLEN_DIGEST;
    case "SaltLengthMax":
      return crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN;
    case "SaltLengthExplicit":
      return saltLength[0];
    default:
      throw new Error(`Unknown salt length: ${name}`);
  }
}

function rsaSignPaddingOpts(padding) {
  const paddingName = padding.constructor.name;
  if (paddingName === "Pkcs1v15") {
    return { padding: crypto.constants.RSA_PKCS1_PADDING };
  } else if (paddingName === "Pss") {
    const saltLength = rsaPssSaltLength(padding[0]);
    return {
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: saltLength,
    };
  }
  throw new Error(`Unknown sign padding: ${paddingName}`);
}

export function rsaSign(privateKey, message, hash, padding) {
  const algorithmName = algorithm_name(hash);
  const opts = rsaSignPaddingOpts(padding);
  const signature = crypto.sign(algorithmName, message.rawBuffer, {
    key: privateKey,
    ...opts,
  });
  return BitArray$BitArray(signature);
}

export function rsaVerify(publicKey, message, signature, hash, padding) {
  try {
    const algorithmName = algorithm_name(hash);
    const opts = rsaSignPaddingOpts(padding);
    if (opts.saltLength === crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN) {
      opts.saltLength = crypto.constants.RSA_PSS_SALTLEN_AUTO;
    }
    return crypto.verify(
      algorithmName,
      message.rawBuffer,
      { key: publicKey, ...opts },
      signature.rawBuffer,
    );
  } catch {
    return false;
  }
}

// RSA Encryption

function rsaEncryptPaddingOpts(padding) {
  const paddingName = padding.constructor.name;
  if (paddingName === "EncryptPkcs1v15") {
    return { padding: crypto.constants.RSA_PKCS1_PADDING };
  } else if (paddingName === "Oaep") {
    const hash = padding.hash;
    const label = padding.label;
    const algorithmName = algorithm_name(hash);
    const opts = {
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: algorithmName,
    };
    if (label.byteSize > 0) {
      opts.oaepLabel = label.rawBuffer;
    }
    return opts;
  }
  throw new Error(`Unknown encrypt padding: ${paddingName}`);
}

export function rsaEncrypt(publicKey, plaintext, padding) {
  try {
    const opts = rsaEncryptPaddingOpts(padding);
    const ciphertext = crypto.publicEncrypt(
      { key: publicKey, ...opts },
      plaintext.rawBuffer,
    );
    return Result$Ok(BitArray$BitArray(ciphertext));
  } catch {
    return Result$Error(undefined);
  }
}

export function rsaDecrypt(privateKey, ciphertext, padding) {
  try {
    const opts = rsaEncryptPaddingOpts(padding);
    const plaintext = crypto.privateDecrypt(
      { key: privateKey, ...opts },
      ciphertext.rawBuffer,
    );
    return Result$Ok(BitArray$BitArray(plaintext));
  } catch {
    return Result$Error(undefined);
  }
}

// RSA Import Functions

function rsaFormatToType(format, isPrivate) {
  const formatName = format.constructor.name;
  if (isPrivate) {
    return formatName === "Pkcs1" ? "pkcs1" : "pkcs8";
  } else {
    return formatName === "RsaPublicKey" ? "pkcs1" : "spki";
  }
}

export function rsaPrivateKeyFromPkcs8(derBytes) {
  try {
    const privateKey = crypto.createPrivateKey({
      key: derBytes.rawBuffer,
      format: "der",
      type: "pkcs8",
    });
    if (privateKey.asymmetricKeyType !== "rsa") {
      return Result$Error(undefined);
    }
    const publicKey = crypto.createPublicKey(privateKey);
    return Result$Ok([privateKey, publicKey]);
  } catch {
    return Result$Error(undefined);
  }
}

export function rsaPublicKeyFromX509(derBytes) {
  try {
    const publicKey = crypto.createPublicKey({
      key: derBytes.rawBuffer,
      format: "der",
      type: "spki",
    });
    if (publicKey.asymmetricKeyType !== "rsa") {
      return Result$Error(undefined);
    }
    return Result$Ok(publicKey);
  } catch {
    return Result$Error(undefined);
  }
}

export function rsaImportPrivateKeyPem(pem, format) {
  const type = rsaFormatToType(format, true);
  return importPrivateKeyPem(pem, type, ["rsa"]);
}

export function rsaImportPrivateKeyDer(der, format) {
  const type = rsaFormatToType(format, true);
  return importPrivateKeyDer(der, type, ["rsa"]);
}

export function rsaImportPublicKeyPem(pem, format) {
  const type = rsaFormatToType(format, false);
  return importPublicKeyPem(pem, type, ["rsa"]);
}

export function rsaImportPublicKeyDer(der, format) {
  const type = rsaFormatToType(format, false);
  return importPublicKeyDer(der, type, ["rsa"]);
}

// RSA Export Functions

export function rsaExportPrivateKeyPem(key, format) {
  try {
    const type = rsaFormatToType(format, true);
    const exported = key.export({ format: "pem", type });
    return Result$Ok(exported);
  } catch {
    return Result$Error(undefined);
  }
}

export function rsaExportPrivateKeyDer(key, format) {
  try {
    const type = rsaFormatToType(format, true);
    const exported = key.export({ format: "der", type });
    return Result$Ok(BitArray$BitArray(exported));
  } catch {
    return Result$Error(undefined);
  }
}

export function rsaExportPublicKeyPem(key, format) {
  try {
    const type = rsaFormatToType(format, false);
    const exported = key.export({ format: "pem", type });
    return Result$Ok(exported);
  } catch {
    return Result$Error(undefined);
  }
}

export function rsaExportPublicKeyDer(key, format) {
  try {
    const type = rsaFormatToType(format, false);
    const exported = key.export({ format: "der", type });
    return Result$Ok(BitArray$BitArray(exported));
  } catch {
    return Result$Error(undefined);
  }
}

// =============================================================================
// EdDSA (Ed25519/Ed448)
// =============================================================================

const EDDSA_PRIVATE_DER_PREFIX = {
  ed25519: Buffer.from("302e020100300506032b657004220420", "hex"),
  ed448: Buffer.from("3047020100300506032b6571043b0439", "hex"),
};

const EDDSA_PUBLIC_DER_PREFIX = {
  ed25519: Buffer.from("302a300506032b6570032100", "hex"),
  ed448: Buffer.from("3043300506032b6571033a00", "hex"),
};

export function eddsaGenerateKeyPair(curve) {
  const curveName = curve.constructor.name.toLowerCase();
  const { privateKey, publicKey } = crypto.generateKeyPairSync(curveName);
  return [privateKey, publicKey];
}

export function eddsaPrivateKeyFromBytes(curve, privateBytes) {
  try {
    const curveName = curve.constructor.name.toLowerCase();
    const expectedSize = eddsa_key_size(curve);
    if (privateBytes.byteSize !== expectedSize) {
      return Result$Error(undefined);
    }
    const prefix = EDDSA_PRIVATE_DER_PREFIX[curveName];
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

export function eddsaPublicKeyFromBytes(curve, publicBytes) {
  try {
    const curveName = curve.constructor.name.toLowerCase();
    const expectedSize = eddsa_key_size(curve);
    if (publicBytes.byteSize !== expectedSize) {
      return Result$Error(undefined);
    }
    const prefix = EDDSA_PUBLIC_DER_PREFIX[curveName];
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

export function eddsaPublicKeyFromPrivate(privateKey) {
  return crypto.createPublicKey(privateKey);
}

export function eddsaSign(privateKey, message) {
  const signature = crypto.sign(null, message.rawBuffer, privateKey);
  return BitArray$BitArray(signature);
}

export function eddsaVerify(publicKey, message, signature) {
  try {
    return crypto.verify(
      null,
      message.rawBuffer,
      publicKey,
      signature.rawBuffer,
    );
  } catch {
    return false;
  }
}

// EdDSA Import Functions

export function eddsaImportPrivateKeyPem(pem) {
  return importPrivateKeyPem(pem, "pkcs8", ["ed25519", "ed448"]);
}

export function eddsaImportPrivateKeyDer(der) {
  return importPrivateKeyDer(der, "pkcs8", ["ed25519", "ed448"]);
}

export function eddsaImportPublicKeyPem(pem) {
  return importPublicKeyPem(pem, "spki", ["ed25519", "ed448"]);
}

export function eddsaImportPublicKeyDer(der) {
  return importPublicKeyDer(der, "spki", ["ed25519", "ed448"]);
}

// EdDSA Export Functions

export function eddsaExportPrivateKeyPem(key) {
  try {
    const exported = key.export({ format: "pem", type: "pkcs8" });
    return Result$Ok(exported);
  } catch {
    return Result$Error(undefined);
  }
}

export function eddsaExportPrivateKeyDer(key) {
  try {
    const exported = key.export({ format: "der", type: "pkcs8" });
    return Result$Ok(BitArray$BitArray(exported));
  } catch {
    return Result$Error(undefined);
  }
}

export function eddsaExportPublicKeyPem(key) {
  try {
    const exported = key.export({ format: "pem", type: "spki" });
    return Result$Ok(exported);
  } catch {
    return Result$Error(undefined);
  }
}

export function eddsaExportPublicKeyDer(key) {
  try {
    const exported = key.export({ format: "der", type: "spki" });
    return Result$Ok(BitArray$BitArray(exported));
  } catch {
    return Result$Error(undefined);
  }
}
