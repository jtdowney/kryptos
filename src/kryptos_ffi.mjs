import crypto from "node:crypto";

import { BitArray$BitArray, Result$Error, Result$Ok } from "./gleam.mjs";
import {
  cipher_key as aeadCipherKey,
  cipher_name as aeadCipherName,
  is_ccm as aeadIsCcm,
  tag_size as aeadTagSize,
} from "./kryptos/aead.mjs";
import {
  aes_key as blockAesKey,
  cipher_iv as blockCipherIv,
  cipher_key as blockCipherKey,
  cipher_name as blockCipherName,
  is_ctr as blockIsCtr,
  key_size as blockKeySize,
} from "./kryptos/block.mjs";
import {
  Curve$P256,
  Curve$P384,
  Curve$P521,
  Curve$Secp256k1,
  Curve$isP256,
  Curve$isP384,
  Curve$isP521,
  Curve$isSecp256k1,
  coordinate_size as ecCoordinateSize,
} from "./kryptos/ec.mjs";
import {
  Curve$isEd25519,
  Curve$isEd448,
  Curve$Ed25519,
  Curve$Ed448,
  key_size as eddsaKeySize,
} from "./kryptos/eddsa.mjs";
import {
  HashAlgorithm$isShake128,
  HashAlgorithm$isShake256,
  HashAlgorithm$Shake128$0,
  HashAlgorithm$Shake256$0,
  algorithm_name as hashAlgorithmName,
} from "./kryptos/hash.mjs";
import {
  EncryptPadding$isEncryptPkcs1v15,
  EncryptPadding$isOaep,
  PrivateKeyFormat$isPkcs1,
  PrivateKeyFormat$isPkcs8,
  PssSaltLength$SaltLengthExplicit$0,
  PssSaltLength$isSaltLengthExplicit,
  PssSaltLength$isSaltLengthHashLen,
  PssSaltLength$isSaltLengthMax,
  PublicKeyFormat$isRsaPublicKey,
  PublicKeyFormat$isSpki,
  SignPadding$Pss$0,
  SignPadding$isPkcs1v15,
  SignPadding$isPss,
} from "./kryptos/rsa.mjs";
import {
  Curve$isX25519,
  Curve$isX448,
  Curve$X25519,
  Curve$X448,
  key_size as xdhKeySize,
} from "./kryptos/xdh.mjs";

// =============================================================================
// Utilities & Random
// =============================================================================

export function randomBytes(length) {
  const safeLength = Math.max(0, length);
  const buffer = crypto.randomBytes(safeLength);
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

function getXofOutputLength(algorithm) {
  if (HashAlgorithm$isShake128(algorithm)) {
    return HashAlgorithm$Shake128$0(algorithm);
  }
  if (HashAlgorithm$isShake256(algorithm)) {
    return HashAlgorithm$Shake256$0(algorithm);
  }
  return null;
}

export function hashNew(algorithm) {
  try {
    const name = hashAlgorithmName(algorithm);
    const outputLength = getXofOutputLength(algorithm);
    const options = outputLength !== null ? { outputLength } : undefined;
    return Result$Ok(crypto.createHash(name, options));
  } catch {
    return Result$Error(undefined);
  }
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
  try {
    const algorithmName = hashAlgorithmName(algorithm);
    return Result$Ok(crypto.createHmac(algorithmName, key.rawBuffer));
  } catch {
    return Result$Error(undefined);
  }
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
    const name = hashAlgorithmName(algorithm);
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
    const name = hashAlgorithmName(algorithm);
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

export function aeadSeal(ctx, nonce, plaintext, aad) {
  try {
    const name = aeadCipherName(ctx);
    const key = aeadCipherKey(ctx);
    const authTagLength = aeadTagSize(ctx);

    const aadOptions = aeadIsCcm(ctx)
      ? { plaintextLength: plaintext.byteSize }
      : undefined;

    const cipher = crypto.createCipheriv(name, key.rawBuffer, nonce.rawBuffer, {
      authTagLength,
    });
    cipher.setAAD(aad.rawBuffer, aadOptions);

    const updateOutput = cipher.update(plaintext.rawBuffer);
    const finalOutput = cipher.final();
    const ciphertext = Buffer.concat([updateOutput, finalOutput]);
    const tag = cipher.getAuthTag();
    return Result$Ok([BitArray$BitArray(ciphertext), BitArray$BitArray(tag)]);
  } catch {
    return Result$Error(undefined);
  }
}

export function aeadOpen(ctx, nonce, tag, ciphertext, aad) {
  try {
    const name = aeadCipherName(ctx);
    const key = aeadCipherKey(ctx);
    const authTagLength = aeadTagSize(ctx);

    const aadOptions = aeadIsCcm(ctx)
      ? { plaintextLength: ciphertext.byteSize }
      : undefined;

    const decipher = crypto.createDecipheriv(
      name,
      key.rawBuffer,
      nonce.rawBuffer,
      { authTagLength },
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

function blockCipherNeedsPadding(ctx) {
  return !blockIsCtr(ctx);
}

export function blockCipherEncrypt(mode, plaintext) {
  try {
    const name = blockCipherName(mode);
    const key = blockCipherKey(mode);
    const iv = blockCipherIv(mode);

    const ivBuffer = iv.byteSize === 0 ? null : iv.rawBuffer;

    const cipher = crypto.createCipheriv(name, key.rawBuffer, ivBuffer);
    cipher.setAutoPadding(blockCipherNeedsPadding(mode));

    const updateOutput = cipher.update(plaintext.rawBuffer);
    const finalOutput = cipher.final();
    const ciphertext = Buffer.concat([updateOutput, finalOutput]);

    return Result$Ok(BitArray$BitArray(ciphertext));
  } catch {
    return Result$Error(undefined);
  }
}

export function blockCipherDecrypt(mode, ciphertext) {
  try {
    const name = blockCipherName(mode);
    const key = blockCipherKey(mode);
    const iv = blockCipherIv(mode);

    const ivBuffer = iv.byteSize === 0 ? null : iv.rawBuffer;

    const decipher = crypto.createDecipheriv(name, key.rawBuffer, ivBuffer);
    decipher.setAutoPadding(blockCipherNeedsPadding(mode));

    const updateOutput = decipher.update(ciphertext.rawBuffer);
    const finalOutput = decipher.final();
    const plaintext = Buffer.concat([updateOutput, finalOutput]);

    return Result$Ok(BitArray$BitArray(plaintext));
  } catch {
    return Result$Error(undefined);
  }
}

// =============================================================================
// Key Wrapping (AES-KW, RFC 3394)
// =============================================================================

// RFC 3394 default IV
const KEYWRAP_DEFAULT_IV = Buffer.from([
  0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6,
]);

function keywrapCipherName(cipher) {
  const keySize = blockKeySize(cipher);
  switch (keySize) {
    case 128:
      return "aes128-wrap";
    case 192:
      return "aes192-wrap";
    case 256:
      return "aes256-wrap";
    default:
      throw new Error(`Unknown key size: ${keySize}`);
  }
}

export function blockCipherWrap(cipher, plaintext) {
  try {
    const algorithm = keywrapCipherName(cipher);
    const key = blockAesKey(cipher).rawBuffer;

    const cipherObj = crypto.createCipheriv(algorithm, key, KEYWRAP_DEFAULT_IV);
    const updateOutput = cipherObj.update(plaintext.rawBuffer);
    const finalOutput = cipherObj.final();
    const ciphertext = Buffer.concat([updateOutput, finalOutput]);

    return Result$Ok(BitArray$BitArray(ciphertext));
  } catch {
    return Result$Error(undefined);
  }
}

export function blockCipherUnwrap(cipher, ciphertext) {
  try {
    const algorithm = keywrapCipherName(cipher);
    const key = blockAesKey(cipher).rawBuffer;

    const decipherObj = crypto.createDecipheriv(
      algorithm,
      key,
      KEYWRAP_DEFAULT_IV,
    );
    const updateOutput = decipherObj.update(ciphertext.rawBuffer);
    const finalOutput = decipherObj.final();
    const plaintext = Buffer.concat([updateOutput, finalOutput]);

    return Result$Ok(BitArray$BitArray(plaintext));
  } catch {
    return Result$Error(undefined);
  }
}

// =============================================================================
// Curve Helpers (shared by EC, EdDSA, XDH)
// =============================================================================

function ecCurveToOpensslName(curve) {
  if (Curve$isP256(curve)) return "prime256v1";
  if (Curve$isP384(curve)) return "secp384r1";
  if (Curve$isP521(curve)) return "secp521r1";
  if (Curve$isSecp256k1(curve)) return "secp256k1";
  throw new Error(`Unsupported curve: ${curve.constructor.name}`);
}

function ecCurveToJwkCrv(curve) {
  if (Curve$isP256(curve)) return "P-256";
  if (Curve$isP384(curve)) return "P-384";
  if (Curve$isP521(curve)) return "P-521";
  if (Curve$isSecp256k1(curve)) return "secp256k1";
  throw new Error(`Unsupported curve: ${curve.constructor.name}`);
}

function jwkCrvToCurve(crv) {
  switch (crv) {
    case "P-256":
      return Curve$P256();
    case "P-384":
      return Curve$P384();
    case "P-521":
      return Curve$P521();
    case "secp256k1":
      return Curve$Secp256k1();
    default:
      throw new Error(`Unsupported JWK crv: ${crv}`);
  }
}

function padStart(buffer, length) {
  if (buffer.length >= length) return buffer;
  const padding = Buffer.alloc(length - buffer.length, 0);
  return Buffer.concat([padding, buffer]);
}

export function ecPublicKeyFromPrivate(privateKey) {
  if (privateKey.asymmetricKeyType !== "ec") {
    throw new Error(
      `Expected EC private key, got ${privateKey.asymmetricKeyType}`,
    );
  }
  return crypto.createPublicKey(privateKey);
}

export function ecPrivateKeyCurve(key) {
  const jwk = key.export({ format: "jwk" });
  return jwkCrvToCurve(jwk.crv);
}

export function ecPublicKeyCurve(key) {
  const jwk = key.export({ format: "jwk" });
  return jwkCrvToCurve(jwk.crv);
}

export function eddsaPublicKeyFromPrivate(privateKey) {
  const keyType = privateKey.asymmetricKeyType;
  if (keyType !== "ed25519" && keyType !== "ed448") {
    throw new Error(`Expected EdDSA private key, got ${keyType}`);
  }
  return crypto.createPublicKey(privateKey);
}

function keyTypeToEddsaCurve(keyType) {
  switch (keyType) {
    case "ed25519":
      return Curve$Ed25519();
    case "ed448":
      return Curve$Ed448();
    default:
      throw new Error(`Unsupported EdDSA key type: ${keyType}`);
  }
}

export function eddsaPrivateKeyCurve(key) {
  return keyTypeToEddsaCurve(key.asymmetricKeyType);
}

export function eddsaPublicKeyCurve(key) {
  return keyTypeToEddsaCurve(key.asymmetricKeyType);
}

export function rsaPublicKeyFromPrivate(privateKey) {
  if (privateKey.asymmetricKeyType !== "rsa") {
    throw new Error(
      `Expected RSA private key, got ${privateKey.asymmetricKeyType}`,
    );
  }
  return crypto.createPublicKey(privateKey);
}

export function rsaPrivateKeyModulusBits(key) {
  return key.asymmetricKeyDetails.modulusLength;
}

export function rsaPublicKeyModulusBits(key) {
  return key.asymmetricKeyDetails.modulusLength;
}

function base64UrlToInt(base64url) {
  const buffer = Buffer.from(base64url, "base64url");
  let result = 0n;
  for (const byte of buffer) {
    result = (result << 8n) | BigInt(byte);
  }
  return Number(result);
}

export function rsaPrivateKeyPublicExponent(key) {
  const jwk = key.export({ format: "jwk" });
  return base64UrlToInt(jwk.e);
}

export function rsaPublicKeyPublicExponent(key) {
  const jwk = key.export({ format: "jwk" });
  return base64UrlToInt(jwk.e);
}

export function rsaPrivateKeyModulus(key) {
  const jwk = key.export({ format: "jwk" });
  return BitArray$BitArray(Buffer.from(jwk.n, "base64url"));
}

export function rsaPublicKeyModulus(key) {
  const jwk = key.export({ format: "jwk" });
  return BitArray$BitArray(Buffer.from(jwk.n, "base64url"));
}

export function rsaPrivateKeyPublicExponentBytes(key) {
  const jwk = key.export({ format: "jwk" });
  return BitArray$BitArray(Buffer.from(jwk.e, "base64url"));
}

export function rsaPublicKeyExponentBytes(key) {
  const jwk = key.export({ format: "jwk" });
  return BitArray$BitArray(Buffer.from(jwk.e, "base64url"));
}

export function rsaPrivateKeyPrivateExponentBytes(key) {
  const jwk = key.export({ format: "jwk" });
  return BitArray$BitArray(Buffer.from(jwk.d, "base64url"));
}

export function rsaPrivateKeyPrime1(key) {
  const jwk = key.export({ format: "jwk" });
  return BitArray$BitArray(Buffer.from(jwk.p, "base64url"));
}

export function rsaPrivateKeyPrime2(key) {
  const jwk = key.export({ format: "jwk" });
  return BitArray$BitArray(Buffer.from(jwk.q, "base64url"));
}

export function rsaPrivateKeyExponent1(key) {
  const jwk = key.export({ format: "jwk" });
  return BitArray$BitArray(Buffer.from(jwk.dp, "base64url"));
}

export function rsaPrivateKeyExponent2(key) {
  const jwk = key.export({ format: "jwk" });
  return BitArray$BitArray(Buffer.from(jwk.dq, "base64url"));
}

export function rsaPrivateKeyCoefficient(key) {
  const jwk = key.export({ format: "jwk" });
  return BitArray$BitArray(Buffer.from(jwk.qi, "base64url"));
}

export function rsaPublicKeyFromComponents(n, e) {
  try {
    const jwk = {
      kty: "RSA",
      n: Buffer.from(n.rawBuffer).toString("base64url"),
      e: Buffer.from(e.rawBuffer).toString("base64url"),
    };
    const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
    return Result$Ok(publicKey);
  } catch {
    return Result$Error(undefined);
  }
}

export function modPow(baseBits, expBits, modBits) {
  const base = BigInt(
    "0x" + (Buffer.from(baseBits.rawBuffer).toString("hex") || "0"),
  );
  const exp = BigInt(
    "0x" + (Buffer.from(expBits.rawBuffer).toString("hex") || "0"),
  );
  const mod = BigInt(
    "0x" + (Buffer.from(modBits.rawBuffer).toString("hex") || "0"),
  );

  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e % 2n === 1n) result = (result * b) % mod;
    e /= 2n;
    b = (b * b) % mod;
  }

  let hex = result.toString(16);
  if (hex.length % 2 !== 0) hex = "0" + hex;
  return BitArray$BitArray(Buffer.from(hex, "hex"));
}

export function rsaPrivateKeyFromFullComponents(n, e, d, p, q, dp, dq, qi) {
  try {
    const jwk = {
      kty: "RSA",
      n: Buffer.from(n.rawBuffer).toString("base64url"),
      e: Buffer.from(e.rawBuffer).toString("base64url"),
      d: Buffer.from(d.rawBuffer).toString("base64url"),
      p: Buffer.from(p.rawBuffer).toString("base64url"),
      q: Buffer.from(q.rawBuffer).toString("base64url"),
      dp: Buffer.from(dp.rawBuffer).toString("base64url"),
      dq: Buffer.from(dq.rawBuffer).toString("base64url"),
      qi: Buffer.from(qi.rawBuffer).toString("base64url"),
    };
    const privateKey = crypto.createPrivateKey({ key: jwk, format: "jwk" });
    const publicKey = crypto.createPublicKey(privateKey);
    return Result$Ok([privateKey, publicKey]);
  } catch {
    return Result$Error(undefined);
  }
}

export function xdhPublicKeyFromPrivate(privateKey) {
  const keyType = privateKey.asymmetricKeyType;
  if (keyType !== "x25519" && keyType !== "x448") {
    throw new Error(`Expected XDH private key, got ${keyType}`);
  }
  return crypto.createPublicKey(privateKey);
}

function keyTypeToXdhCurve(keyType) {
  switch (keyType) {
    case "x25519":
      return Curve$X25519();
    case "x448":
      return Curve$X448();
    default:
      throw new Error(`Unsupported XDH key type: ${keyType}`);
  }
}

export function xdhPrivateKeyCurve(key) {
  return keyTypeToXdhCurve(key.asymmetricKeyType);
}

export function xdhPublicKeyCurve(key) {
  return keyTypeToXdhCurve(key.asymmetricKeyType);
}

// OID 1.2.840.10045.2.1 (id-ecPublicKey)
const EC_PUBLIC_KEY_OID = Buffer.from([
  0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
]);

// Extracts DER bytes from a PEM-encoded string.
function pemToDer(pem) {
  const lines = pem.split("\n");
  const base64Lines = lines.filter(
    (line) => !line.startsWith("-----") && line.trim() !== "",
  );
  const base64 = base64Lines.join("");
  return Buffer.from(base64, "base64");
}

// Validates that an EC SPKI DER uses a named curve OID (not explicit parameters).
// This mirrors Erlang's behavior which only accepts {namedCurve, OID} format.
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
  const namedCurve = ecCurveToOpensslName(curve);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve,
  });

  return [privateKey, publicKey];
}

export function ecPrivateKeyFromBytes(curve, privateScalar) {
  try {
    const curveName = ecCurveToOpensslName(curve);
    const coordSize = ecCoordinateSize(curve);
    let privBuffer = Buffer.from(privateScalar.rawBuffer);

    // Handle DER integer encoding: may have leading 0x00 for sign or be shorter
    if (privBuffer.length === 0 || privBuffer.length > coordSize + 1) {
      return Result$Error(undefined);
    }
    if (privBuffer.length === coordSize + 1) {
      if (privBuffer[0] !== 0x00) {
        return Result$Error(undefined);
      }
      privBuffer = privBuffer.subarray(1);
    } else if (privBuffer.length < coordSize) {
      // Pad with leading zeros
      const padded = Buffer.alloc(coordSize);
      privBuffer.copy(padded, coordSize - privBuffer.length);
      privBuffer = padded;
    }

    const ecdh = crypto.createECDH(curveName);
    ecdh.setPrivateKey(privBuffer);
    const publicPoint = ecdh.getPublicKey();

    const x = publicPoint.subarray(1, 1 + coordSize);
    const y = publicPoint.subarray(1 + coordSize);

    const jwk = {
      kty: "EC",
      crv: ecCurveToJwkCrv(curve),
      x: x.toString("base64url"),
      y: y.toString("base64url"),
      d: privBuffer.toString("base64url"),
    };

    const privateKey = crypto.createPrivateKey({ key: jwk, format: "jwk" });
    const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });

    return Result$Ok([privateKey, publicKey]);
  } catch {
    return Result$Error(undefined);
  }
}

export function ecPrivateKeyToBytes(privateKey) {
  const jwk = privateKey.export({ format: "jwk" });
  return BitArray$BitArray(Buffer.from(jwk.d, "base64url"));
}

export function ecPublicKeyFromDer(derBytes) {
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
    const coordSize = ecCoordinateSize(curve);
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
      crv: ecCurveToJwkCrv(curve),
      x: x.toString("base64url"),
      y: y.toString("base64url"),
    };

    const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });

    // Validate point is on the curve by attempting ECDH computation.
    // This mirrors Erlang's validate_ec_point which uses crypto:compute_key.
    const curveName = ecCurveToOpensslName(curve);
    const ecdh = crypto.createECDH(curveName);
    ecdh.generateKeys();
    ecdh.computeSecret(pointBuffer);

    return Result$Ok(publicKey);
  } catch {
    return Result$Error(undefined);
  }
}

export function ecPublicKeyToRawPoint(key) {
  const jwk = key.export({ format: "jwk" });
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");

  const coordSize = ecCoordinateSize(jwkCrvToCurve(jwk.crv));
  const xPadded = padStart(x, coordSize);
  const yPadded = padStart(y, coordSize);

  return BitArray$BitArray(
    Buffer.concat([Buffer.from([0x04]), xPadded, yPadded]),
  );
}

export function ecdsaSign(privateKey, message, hashAlgorithm) {
  const algorithmName = hashAlgorithmName(hashAlgorithm);
  const signature = crypto.sign(algorithmName, message.rawBuffer, {
    key: privateKey,
    dsaEncoding: "der",
  });
  return BitArray$BitArray(signature);
}

export function ecdsaVerify(publicKey, message, signature, hashAlgorithm) {
  try {
    const algorithmName = hashAlgorithmName(hashAlgorithm);
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
      privateKey,
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
      type,
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
      type,
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
      type,
    });

    if (!allowedTypes.includes(publicKey.asymmetricKeyType)) {
      return Result$Error(undefined);
    }

    return Result$Ok(publicKey);
  } catch {
    return Result$Error(undefined);
  }
}

function importPublicKeyDer(der, type, allowedTypes, preValidate) {
  try {
    if (preValidate && !preValidate(der.rawBuffer)) {
      return Result$Error(undefined);
    }

    const publicKey = crypto.createPublicKey({
      key: der.rawBuffer,
      format: "der",
      type,
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
  try {
    // Extract DER from PEM and validate it uses named curves
    const derBytes = pemToDer(pem);
    if (!validateSpkiUsesNamedCurve(derBytes)) {
      return Result$Error(undefined);
    }

    return importPublicKeyPem(pem, "spki", ["ec"]);
  } catch {
    return Result$Error(undefined);
  }
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

// DER prefixes for wrapping raw key bytes into PKCS#8/SPKI format (RFC 8410).
// These are stable, standardized encodings that prepend ASN.1 structure to raw keys.
//
// PKCS#8 PrivateKeyInfo structure (RFC 5958):
//   SEQUENCE {
//     INTEGER 0 (version)
//     SEQUENCE { OBJECT IDENTIFIER (algorithm OID) }
//     OCTET STRING { OCTET STRING (raw private key) }
//   }
//
// X25519 OID: 1.3.101.110 (06 03 2b 65 6e)
// X448 OID:   1.3.101.111 (06 03 2b 65 6f)
const XDH_PRIVATE_DER_PREFIX = {
  // 30 2e        SEQUENCE (46 bytes total)
  //   02 01 00   INTEGER 0 (version)
  //   30 05      SEQUENCE (5 bytes)
  //     06 03 2b 65 6e  OID 1.3.101.110 (X25519)
  //   04 22      OCTET STRING (34 bytes)
  //     04 20    OCTET STRING (32 bytes) - the raw key follows
  x25519: Buffer.from("302e020100300506032b656e04220420", "hex"),
  // 30 46        SEQUENCE (70 bytes total)
  //   02 01 00   INTEGER 0 (version)
  //   30 05      SEQUENCE (5 bytes)
  //     06 03 2b 65 6f  OID 1.3.101.111 (X448)
  //   04 3a      OCTET STRING (58 bytes)
  //     04 38    OCTET STRING (56 bytes) - the raw key follows
  x448: Buffer.from("3046020100300506032b656f043a0438", "hex"),
};

// SPKI SubjectPublicKeyInfo structure (RFC 5280):
//   SEQUENCE {
//     SEQUENCE { OBJECT IDENTIFIER (algorithm OID) }
//     BIT STRING (raw public key)
//   }
const XDH_PUBLIC_DER_PREFIX = {
  // 30 2a        SEQUENCE (42 bytes total)
  //   30 05      SEQUENCE (5 bytes)
  //     06 03 2b 65 6e  OID 1.3.101.110 (X25519)
  //   03 21 00   BIT STRING (33 bytes, 0 unused bits) - 32-byte key follows
  x25519: Buffer.from("302a300506032b656e032100", "hex"),
  // 30 42        SEQUENCE (66 bytes total)
  //   30 05      SEQUENCE (5 bytes)
  //     06 03 2b 65 6f  OID 1.3.101.111 (X448)
  //   03 39 00   BIT STRING (57 bytes, 0 unused bits) - 56-byte key follows
  x448: Buffer.from("3042300506032b656f033900", "hex"),
};

function xdhCurveName(curve) {
  if (Curve$isX25519(curve)) return "x25519";
  if (Curve$isX448(curve)) return "x448";
  throw new Error(`Unsupported XDH curve: ${curve.constructor.name}`);
}

export function xdhGenerateKeyPair(curve) {
  const curveName = xdhCurveName(curve);
  const { privateKey, publicKey } = crypto.generateKeyPairSync(curveName);
  return [privateKey, publicKey];
}

export function xdhPrivateKeyFromBytes(curve, privateBytes) {
  try {
    const curveName = xdhCurveName(curve);
    const expectedSize = xdhKeySize(curve);
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
    const curveName = xdhCurveName(curve);
    const expectedSize = xdhKeySize(curve);
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

export function xdhPrivateKeyToBytes(privateKey) {
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  const curveName = privateKey.asymmetricKeyType;
  const prefixLen = XDH_PRIVATE_DER_PREFIX[curveName].length;
  return BitArray$BitArray(der.subarray(prefixLen));
}

export function xdhPublicKeyToBytes(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  const curveName = publicKey.asymmetricKeyType;
  const prefixLen = XDH_PUBLIC_DER_PREFIX[curveName].length;
  return BitArray$BitArray(der.subarray(prefixLen));
}

export function xdhComputeSharedSecret(privateKey, peerPublicKey) {
  try {
    const sharedSecret = crypto.diffieHellman({
      privateKey,
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

const RSA_PUBLIC_EXPONENT = 65537;

export function rsaGenerateKeyPair(modulusLength) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength,
    publicExponent: RSA_PUBLIC_EXPONENT,
  });
  return [privateKey, publicKey];
}

// RSA Signing

function rsaPssSaltLength(saltLength) {
  if (PssSaltLength$isSaltLengthHashLen(saltLength)) {
    return crypto.constants.RSA_PSS_SALTLEN_DIGEST;
  }
  if (PssSaltLength$isSaltLengthMax(saltLength)) {
    return crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN;
  }
  if (PssSaltLength$isSaltLengthExplicit(saltLength)) {
    return PssSaltLength$SaltLengthExplicit$0(saltLength);
  }
  throw new Error(`Unknown salt length: ${saltLength.constructor.name}`);
}

function rsaSignPaddingOpts(padding) {
  if (SignPadding$isPkcs1v15(padding)) {
    return { padding: crypto.constants.RSA_PKCS1_PADDING };
  }
  if (SignPadding$isPss(padding)) {
    const saltLength = rsaPssSaltLength(SignPadding$Pss$0(padding));
    return {
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength,
    };
  }
  throw new Error(`Unknown sign padding: ${padding.constructor.name}`);
}

export function rsaSign(privateKey, message, hash, padding) {
  const algorithmName = hashAlgorithmName(hash);
  const signature = crypto.sign(algorithmName, message.rawBuffer, {
    key: privateKey,
    ...rsaSignPaddingOpts(padding),
  });
  return BitArray$BitArray(signature);
}

export function rsaVerify(publicKey, message, signature, hash, padding) {
  try {
    const algorithmName = hashAlgorithmName(hash);
    const opts = rsaSignPaddingOpts(padding);
    // Node.js requires RSA_PSS_SALTLEN_AUTO for verification because
    // RSA_PSS_SALTLEN_MAX_SIGN (-2) is only valid during signing.
    // AUTO allows verification to detect the salt length from the signature.
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
  if (EncryptPadding$isEncryptPkcs1v15(padding)) {
    return { padding: crypto.constants.RSA_PKCS1_PADDING };
  }
  if (EncryptPadding$isOaep(padding)) {
    const opts = {
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: hashAlgorithmName(padding.hash),
    };
    if (padding.label?.byteSize > 0) {
      opts.oaepLabel = padding.label.rawBuffer;
    }
    return opts;
  }
  throw new Error(`Unknown encrypt padding: ${padding.constructor.name}`);
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
  if (isPrivate) {
    if (PrivateKeyFormat$isPkcs1(format)) return "pkcs1";
    if (PrivateKeyFormat$isPkcs8(format)) return "pkcs8";
    throw new Error(`Unknown private key format: ${format.constructor.name}`);
  } else {
    if (PublicKeyFormat$isRsaPublicKey(format)) return "pkcs1";
    if (PublicKeyFormat$isSpki(format)) return "spki";
    throw new Error(`Unknown public key format: ${format.constructor.name}`);
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

// DER prefixes for wrapping raw key bytes into PKCS#8/SPKI format (RFC 8410).
// These are stable, standardized encodings that prepend ASN.1 structure to raw keys.
//
// Ed25519 OID: 1.3.101.112 (06 03 2b 65 70)
// Ed448 OID:   1.3.101.113 (06 03 2b 65 71)
const EDDSA_PRIVATE_DER_PREFIX = {
  // 30 2e        SEQUENCE (46 bytes total)
  //   02 01 00   INTEGER 0 (version)
  //   30 05      SEQUENCE (5 bytes)
  //     06 03 2b 65 70  OID 1.3.101.112 (Ed25519)
  //   04 22      OCTET STRING (34 bytes)
  //     04 20    OCTET STRING (32 bytes) - the raw key follows
  ed25519: Buffer.from("302e020100300506032b657004220420", "hex"),
  // 30 47        SEQUENCE (71 bytes total)
  //   02 01 00   INTEGER 0 (version)
  //   30 05      SEQUENCE (5 bytes)
  //     06 03 2b 65 71  OID 1.3.101.113 (Ed448)
  //   04 3b      OCTET STRING (59 bytes)
  //     04 39    OCTET STRING (57 bytes) - the raw key follows
  ed448: Buffer.from("3047020100300506032b6571043b0439", "hex"),
};

const EDDSA_PUBLIC_DER_PREFIX = {
  // 30 2a        SEQUENCE (42 bytes total)
  //   30 05      SEQUENCE (5 bytes)
  //     06 03 2b 65 70  OID 1.3.101.112 (Ed25519)
  //   03 21 00   BIT STRING (33 bytes, 0 unused bits) - 32-byte key follows
  ed25519: Buffer.from("302a300506032b6570032100", "hex"),
  // 30 43        SEQUENCE (67 bytes total)
  //   30 05      SEQUENCE (5 bytes)
  //     06 03 2b 65 71  OID 1.3.101.113 (Ed448)
  //   03 3a 00   BIT STRING (58 bytes, 0 unused bits) - 57-byte key follows
  ed448: Buffer.from("3043300506032b6571033a00", "hex"),
};

function eddsaCurveName(curve) {
  if (Curve$isEd25519(curve)) return "ed25519";
  if (Curve$isEd448(curve)) return "ed448";
  throw new Error(`Unsupported EdDSA curve: ${curve.constructor.name}`);
}

export function eddsaGenerateKeyPair(curve) {
  const curveName = eddsaCurveName(curve);
  const { privateKey, publicKey } = crypto.generateKeyPairSync(curveName);
  return [privateKey, publicKey];
}

export function eddsaPrivateKeyFromBytes(curve, privateBytes) {
  try {
    const curveName = eddsaCurveName(curve);
    const expectedSize = eddsaKeySize(curve);
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
    const curveName = eddsaCurveName(curve);
    const expectedSize = eddsaKeySize(curve);
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

export function eddsaPrivateKeyToBytes(privateKey) {
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  const curveName = privateKey.asymmetricKeyType;
  const prefixLen = EDDSA_PRIVATE_DER_PREFIX[curveName].length;
  return BitArray$BitArray(der.subarray(prefixLen));
}

export function eddsaPublicKeyToBytes(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  const curveName = publicKey.asymmetricKeyType;
  const prefixLen = EDDSA_PUBLIC_DER_PREFIX[curveName].length;
  return BitArray$BitArray(der.subarray(prefixLen));
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
