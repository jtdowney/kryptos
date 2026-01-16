//// RSA (Rivest-Shamir-Adleman) cryptography.
////
//// This module provides RSA key generation, signing, and encryption operations.
//// RSA keys can be used for both digital signatures and encryption.
////
//// ## Key Generation
////
//// ```gleam
//// import kryptos/rsa
////
//// let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
//// ```
////
//// ## Signing (RSA-PSS)
////
//// ```gleam
//// import kryptos/rsa
//// import kryptos/hash
////
//// let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
//// let message = <<"hello world":utf8>>
//// let padding = rsa.Pss(rsa.SaltLengthHashLen)
//// let signature = rsa.sign(private_key, message, hash.Sha256, padding)
//// let valid = rsa.verify(public_key, message, signature, hash.Sha256, padding)
//// ```
////
//// ## Encryption (RSA-OAEP)
////
//// ```gleam
//// import kryptos/rsa
//// import kryptos/hash
////
//// let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
//// let plaintext = <<"secret":utf8>>
//// let padding = rsa.Oaep(hash: hash.Sha256, label: <<>>)
//// let assert Ok(ciphertext) = rsa.encrypt(public_key, plaintext, padding)
//// let assert Ok(decrypted) = rsa.decrypt(private_key, ciphertext, padding)
//// ```

import gleam/result
import gleam/string
import kryptos/hash.{type HashAlgorithm}
import kryptos/internal/rsa_crt

/// An RSA private key.
pub type PrivateKey

/// An RSA public key.
pub type PublicKey

/// Format for encoding/decoding RSA private keys.
pub type PrivateKeyFormat {
  /// PKCS#8 format (PrivateKeyInfo) - works with all key types.
  Pkcs8
  /// PKCS#1 format (RSAPrivateKey) - RSA-specific.
  Pkcs1
}

/// Format for encoding/decoding RSA public keys.
pub type PublicKeyFormat {
  /// SPKI format (SubjectPublicKeyInfo) - works with all key types.
  Spki
  /// PKCS#1 format (RSAPublicKey) - RSA-specific.
  RsaPublicKey
}

/// The minimum allowed RSA key size in bits.
pub const min_key_size = 1024

/// Salt length options for RSA-PSS signatures.
pub type PssSaltLength {
  /// Salt length equals hash output length (recommended).
  SaltLengthHashLen
  /// Maximum salt length for the key and hash combination.
  SaltLengthMax
  /// Explicit salt length in bytes.
  SaltLengthExplicit(Int)
}

/// Padding scheme for RSA signatures.
pub type SignPadding {
  /// PKCS#1 v1.5 signature padding.
  Pkcs1v15
  /// RSA-PSS (Probabilistic Signature Scheme) padding.
  Pss(PssSaltLength)
}

/// Padding scheme for RSA encryption.
pub type EncryptPadding {
  /// PKCS#1 v1.5 encryption padding.
  ///
  /// **Warning**: Vulnerable to padding oracle attacks. Prefer OAEP for new applications.
  ///
  /// **JavaScript target**: Decryption may fail on Node.js 20.x due to CVE-2023-46809
  /// which disables PKCS#1 v1.5 decryption to prevent the Marvin timing attack. Use
  /// Node.js 22+ or OAEP padding instead.
  EncryptPkcs1v15
  /// RSA-OAEP (Optimal Asymmetric Encryption Padding).
  ///
  /// The hash algorithm is used for both OAEP and MGF1.
  /// The label is optional associated data (usually empty).
  Oaep(hash: HashAlgorithm, label: BitArray)
}

/// Generates an RSA key pair with the specified key size.
///
/// The key can be used for both signing and encryption operations.
///
/// ## Parameters
/// - `bits`: The key size in bits (must be >= 1024)
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` if bits < 1024.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
/// ```
pub fn generate_key_pair(bits: Int) -> Result(#(PrivateKey, PublicKey), Nil) {
  case bits >= min_key_size {
    True -> Ok(do_generate_key_pair(bits))
    False -> Error(Nil)
  }
}

@external(erlang, "kryptos_ffi", "rsa_generate_key_pair")
@external(javascript, "../kryptos_ffi.mjs", "rsaGenerateKeyPair")
fn do_generate_key_pair(bits: Int) -> #(PrivateKey, PublicKey)

/// Signs a message using RSA with the specified hash algorithm and padding.
///
/// The message is hashed internally using the provided algorithm before signing.
///
/// ## Parameters
/// - `private_key`: An RSA private key
/// - `message`: The message to sign (any length)
/// - `hash`: The hash algorithm to use
/// - `padding`: The signature padding scheme (Pkcs1v15 or Pss)
///
/// ## Returns
/// The RSA signature.
@external(erlang, "kryptos_ffi", "rsa_sign")
@external(javascript, "../kryptos_ffi.mjs", "rsaSign")
pub fn sign(
  private_key: PrivateKey,
  message: BitArray,
  hash: HashAlgorithm,
  padding: SignPadding,
) -> BitArray

/// Verifies an RSA signature against a message.
///
/// The message is hashed internally using the provided algorithm before
/// verification. The same hash algorithm and padding used during signing
/// must be used for verification.
///
/// ## Parameters
/// - `public_key`: The RSA public key corresponding to the signing key
/// - `message`: The original message that was signed
/// - `signature`: The signature to verify
/// - `hash`: The hash algorithm used during signing
/// - `padding`: The signature padding scheme used during signing
///
/// ## Returns
/// `True` if the signature is valid, `False` otherwise.
@external(erlang, "kryptos_ffi", "rsa_verify")
@external(javascript, "../kryptos_ffi.mjs", "rsaVerify")
pub fn verify(
  public_key: PublicKey,
  message message: BitArray,
  signature signature: BitArray,
  hash hash: HashAlgorithm,
  padding padding: SignPadding,
) -> Bool

/// Encrypts data using RSA with the specified padding scheme.
///
/// **Note**: RSA encryption should only be used for small amounts of data
/// (typically symmetric keys). For bulk encryption, use a symmetric cipher
/// with a randomly generated key, then encrypt that key with RSA.
///
/// ## Parameters
/// - `public_key`: The RSA public key
/// - `plaintext`: The data to encrypt
/// - `padding`: The encryption padding scheme (EncryptPkcs1v15 or Oaep)
///
/// ## Returns
/// `Ok(ciphertext)` on success, `Error(Nil)` if plaintext is too long.
@external(erlang, "kryptos_ffi", "rsa_encrypt")
@external(javascript, "../kryptos_ffi.mjs", "rsaEncrypt")
pub fn encrypt(
  public_key: PublicKey,
  plaintext: BitArray,
  padding: EncryptPadding,
) -> Result(BitArray, Nil)

/// Decrypts data using RSA with the specified padding scheme.
///
/// ## Parameters
/// - `private_key`: The RSA private key
/// - `ciphertext`: The encrypted data
/// - `padding`: The encryption padding scheme (must match encryption)
///
/// ## Returns
/// `Ok(plaintext)` on success, `Error(Nil)` on decryption failure.
@external(erlang, "kryptos_ffi", "rsa_decrypt")
@external(javascript, "../kryptos_ffi.mjs", "rsaDecrypt")
pub fn decrypt(
  private_key: PrivateKey,
  ciphertext: BitArray,
  padding: EncryptPadding,
) -> Result(BitArray, Nil)

/// Imports an RSA private key from PEM-encoded data.
///
/// ## Parameters
/// - `pem`: PEM-encoded key string
/// - `format`: The key format (Pkcs8 or Pkcs1)
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "rsa_import_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "rsaImportPrivateKeyPem")
pub fn from_pem(
  pem: String,
  format: PrivateKeyFormat,
) -> Result(#(PrivateKey, PublicKey), Nil)

/// Imports an RSA private key from DER-encoded data.
///
/// ## Parameters
/// - `der`: DER-encoded key data
/// - `format`: The key format (Pkcs8 or Pkcs1)
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "rsa_import_private_key_der")
@external(javascript, "../kryptos_ffi.mjs", "rsaImportPrivateKeyDer")
pub fn from_der(
  der: BitArray,
  format: PrivateKeyFormat,
) -> Result(#(PrivateKey, PublicKey), Nil)

/// Exports an RSA private key to PEM format.
///
/// ## Parameters
/// - `key`: The private key to export
/// - `format`: The output format (Pkcs8 or Pkcs1)
///
/// ## Returns
/// `Ok(pem_string)` on success, `Error(Nil)` on failure.
pub fn to_pem(key: PrivateKey, format: PrivateKeyFormat) -> Result(String, Nil) {
  do_to_pem(key, format) |> result.map(fn(pem) { string.trim_end(pem) <> "\n" })
}

@external(erlang, "kryptos_ffi", "rsa_export_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "rsaExportPrivateKeyPem")
fn do_to_pem(key: PrivateKey, format: PrivateKeyFormat) -> Result(String, Nil)

/// Exports an RSA private key to DER format.
///
/// ## Parameters
/// - `key`: The private key to export
/// - `format`: The output format (Pkcs8 or Pkcs1)
///
/// ## Returns
/// `Ok(der_data)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "rsa_export_private_key_der")
@external(javascript, "../kryptos_ffi.mjs", "rsaExportPrivateKeyDer")
pub fn to_der(
  key: PrivateKey,
  format: PrivateKeyFormat,
) -> Result(BitArray, Nil)

/// Imports an RSA public key from PEM-encoded data.
///
/// ## Parameters
/// - `pem`: PEM-encoded key string
/// - `format`: The key format (Spki or RsaPublicKey)
///
/// ## Returns
/// `Ok(public_key)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "rsa_import_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "rsaImportPublicKeyPem")
pub fn public_key_from_pem(
  pem: String,
  format: PublicKeyFormat,
) -> Result(PublicKey, Nil)

/// Imports an RSA public key from DER-encoded data.
///
/// ## Parameters
/// - `der`: DER-encoded key data
/// - `format`: The key format (Spki or RsaPublicKey)
///
/// ## Returns
/// `Ok(public_key)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "rsa_import_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "rsaImportPublicKeyDer")
pub fn public_key_from_der(
  der: BitArray,
  format: PublicKeyFormat,
) -> Result(PublicKey, Nil)

/// Exports an RSA public key to PEM format.
///
/// ## Parameters
/// - `key`: The public key to export
/// - `format`: The output format (Spki or RsaPublicKey)
///
/// ## Returns
/// `Ok(pem_string)` on success, `Error(Nil)` on failure.
pub fn public_key_to_pem(
  key: PublicKey,
  format: PublicKeyFormat,
) -> Result(String, Nil) {
  do_public_key_to_pem(key, format)
  |> result.map(fn(pem) { string.trim_end(pem) <> "\n" })
}

@external(erlang, "kryptos_ffi", "rsa_export_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "rsaExportPublicKeyPem")
fn do_public_key_to_pem(
  key: PublicKey,
  format: PublicKeyFormat,
) -> Result(String, Nil)

/// Exports an RSA public key to DER format.
///
/// ## Parameters
/// - `key`: The public key to export
/// - `format`: The output format (Spki or RsaPublicKey)
///
/// ## Returns
/// `Ok(der_data)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "rsa_export_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "rsaExportPublicKeyDer")
pub fn public_key_to_der(
  key: PublicKey,
  format: PublicKeyFormat,
) -> Result(BitArray, Nil)

/// Derives the public key from an RSA private key.
///
/// ## Parameters
/// - `key`: The private key
///
/// ## Returns
/// The corresponding public key.
@external(erlang, "kryptos_ffi", "rsa_public_key_from_private")
@external(javascript, "../kryptos_ffi.mjs", "rsaPublicKeyFromPrivate")
pub fn public_key_from_private_key(key: PrivateKey) -> PublicKey

/// Returns the modulus size in bits for an RSA private key.
///
/// ## Parameters
/// - `key`: The private key
///
/// ## Returns
/// The size of the modulus in bits (e.g., 2048, 4096).
@external(erlang, "kryptos_ffi", "rsa_private_key_modulus_bits")
@external(javascript, "../kryptos_ffi.mjs", "rsaPrivateKeyModulusBits")
pub fn modulus_bits(key: PrivateKey) -> Int

/// Returns the modulus size in bits for an RSA public key.
///
/// ## Parameters
/// - `key`: The public key
///
/// ## Returns
/// The size of the modulus in bits (e.g., 2048, 4096).
@external(erlang, "kryptos_ffi", "rsa_public_key_modulus_bits")
@external(javascript, "../kryptos_ffi.mjs", "rsaPublicKeyModulusBits")
pub fn public_key_modulus_bits(key: PublicKey) -> Int

/// Returns the public exponent for an RSA private key.
///
/// ## Parameters
/// - `key`: The private key
///
/// ## Returns
/// The public exponent (commonly 65537).
@external(erlang, "kryptos_ffi", "rsa_private_key_public_exponent")
@external(javascript, "../kryptos_ffi.mjs", "rsaPrivateKeyPublicExponent")
pub fn public_exponent(key: PrivateKey) -> Int

/// Returns the public exponent for an RSA public key.
///
/// ## Parameters
/// - `key`: The public key
///
/// ## Returns
/// The public exponent (commonly 65537).
@external(erlang, "kryptos_ffi", "rsa_public_key_public_exponent")
@external(javascript, "../kryptos_ffi.mjs", "rsaPublicKeyPublicExponent")
pub fn public_key_exponent(key: PublicKey) -> Int

/// Returns the modulus (n) as big-endian bytes for an RSA private key.
///
/// ## Parameters
/// - `key`: The private key
///
/// ## Returns
/// The modulus as raw bytes.
@external(erlang, "kryptos_ffi", "rsa_private_key_modulus")
@external(javascript, "../kryptos_ffi.mjs", "rsaPrivateKeyModulus")
pub fn modulus(key: PrivateKey) -> BitArray

/// Returns the modulus (n) as big-endian bytes for an RSA public key.
///
/// ## Parameters
/// - `key`: The public key
///
/// ## Returns
/// The modulus as raw bytes.
@external(erlang, "kryptos_ffi", "rsa_public_key_modulus")
@external(javascript, "../kryptos_ffi.mjs", "rsaPublicKeyModulus")
pub fn public_key_modulus(key: PublicKey) -> BitArray

/// Returns the public exponent (e) as big-endian bytes for an RSA private key.
///
/// ## Parameters
/// - `key`: The private key
///
/// ## Returns
/// The public exponent as raw bytes.
@external(erlang, "kryptos_ffi", "rsa_private_key_public_exponent_bytes")
@external(javascript, "../kryptos_ffi.mjs", "rsaPrivateKeyPublicExponentBytes")
pub fn public_exponent_bytes(key: PrivateKey) -> BitArray

/// Returns the public exponent (e) as big-endian bytes for an RSA public key.
///
/// ## Parameters
/// - `key`: The public key
///
/// ## Returns
/// The public exponent as raw bytes.
@external(erlang, "kryptos_ffi", "rsa_public_key_exponent_bytes")
@external(javascript, "../kryptos_ffi.mjs", "rsaPublicKeyExponentBytes")
pub fn public_key_exponent_bytes(key: PublicKey) -> BitArray

/// Returns the private exponent (d) as big-endian bytes for an RSA private key.
///
/// ## Parameters
/// - `key`: The private key
///
/// ## Returns
/// The private exponent as raw bytes.
@external(erlang, "kryptos_ffi", "rsa_private_key_private_exponent_bytes")
@external(javascript, "../kryptos_ffi.mjs", "rsaPrivateKeyPrivateExponentBytes")
pub fn private_exponent_bytes(key: PrivateKey) -> BitArray

/// Returns the first prime factor (p) as big-endian bytes.
///
/// This is part of the CRT (Chinese Remainder Theorem) parameters used
/// for efficient RSA operations.
@external(erlang, "kryptos_ffi", "rsa_private_key_prime1")
@external(javascript, "../kryptos_ffi.mjs", "rsaPrivateKeyPrime1")
pub fn prime1(key: PrivateKey) -> BitArray

/// Returns the second prime factor (q) as big-endian bytes.
///
/// This is part of the CRT (Chinese Remainder Theorem) parameters used
/// for efficient RSA operations.
@external(erlang, "kryptos_ffi", "rsa_private_key_prime2")
@external(javascript, "../kryptos_ffi.mjs", "rsaPrivateKeyPrime2")
pub fn prime2(key: PrivateKey) -> BitArray

/// Returns the first CRT exponent (dp = d mod (p-1)) as big-endian bytes.
///
/// This is part of the CRT (Chinese Remainder Theorem) parameters used
/// for efficient RSA operations.
@external(erlang, "kryptos_ffi", "rsa_private_key_exponent1")
@external(javascript, "../kryptos_ffi.mjs", "rsaPrivateKeyExponent1")
pub fn exponent1(key: PrivateKey) -> BitArray

/// Returns the second CRT exponent (dq = d mod (q-1)) as big-endian bytes.
///
/// This is part of the CRT (Chinese Remainder Theorem) parameters used
/// for efficient RSA operations.
@external(erlang, "kryptos_ffi", "rsa_private_key_exponent2")
@external(javascript, "../kryptos_ffi.mjs", "rsaPrivateKeyExponent2")
pub fn exponent2(key: PrivateKey) -> BitArray

/// Returns the CRT coefficient (qi = q^-1 mod p) as big-endian bytes.
///
/// This is part of the CRT (Chinese Remainder Theorem) parameters used
/// for efficient RSA operations.
@external(erlang, "kryptos_ffi", "rsa_private_key_coefficient")
@external(javascript, "../kryptos_ffi.mjs", "rsaPrivateKeyCoefficient")
pub fn coefficient(key: PrivateKey) -> BitArray

/// Constructs an RSA public key from its components.
///
/// ## Parameters
/// - `n`: The modulus as big-endian bytes
/// - `e`: The public exponent as big-endian bytes
///
/// ## Returns
/// `Ok(public_key)` on success, `Error(Nil)` if components are invalid.
@external(erlang, "kryptos_ffi", "rsa_public_key_from_components")
@external(javascript, "../kryptos_ffi.mjs", "rsaPublicKeyFromComponents")
pub fn public_key_from_components(
  n: BitArray,
  e: BitArray,
) -> Result(PublicKey, Nil)

/// Constructs an RSA private key from its components.
///
/// Creates a private key from the minimal set of components (n, e, d).
/// CRT parameters are computed automatically using Miller's algorithm.
///
/// Note: This function is not constant-time. The CRT parameter derivation
/// involves operations that may leak timing information. This is acceptable
/// for key import since the caller already possesses the secret material,
/// but avoid calling this in timing-sensitive contexts.
///
/// ## Parameters
/// - `n`: The modulus as big-endian bytes
/// - `e`: The public exponent as big-endian bytes
/// - `d`: The private exponent as big-endian bytes
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` if components are invalid.
pub fn from_components(
  n: BitArray,
  e: BitArray,
  d: BitArray,
) -> Result(#(PrivateKey, PublicKey), Nil) {
  use #(p, q, dp, dq, qi) <- result.try(rsa_crt.compute_crt_params(n, e, d))
  from_full_components(n, e, d, p, q, dp, dq, qi)
}

/// Constructs an RSA private key from all components including CRT parameters.
///
/// This function works on both Erlang and JavaScript targets.
///
/// ## Parameters
/// - `n`: The modulus as big-endian bytes
/// - `e`: The public exponent as big-endian bytes
/// - `d`: The private exponent as big-endian bytes
/// - `p`: The first prime factor as big-endian bytes
/// - `q`: The second prime factor as big-endian bytes
/// - `dp`: The first CRT exponent (d mod (p-1)) as big-endian bytes
/// - `dq`: The second CRT exponent (d mod (q-1)) as big-endian bytes
/// - `qi`: The CRT coefficient (q^-1 mod p) as big-endian bytes
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` if components are invalid.
@external(erlang, "kryptos_ffi", "rsa_private_key_from_full_components")
@external(javascript, "../kryptos_ffi.mjs", "rsaPrivateKeyFromFullComponents")
pub fn from_full_components(
  n: BitArray,
  e: BitArray,
  d: BitArray,
  p: BitArray,
  q: BitArray,
  dp: BitArray,
  dq: BitArray,
  qi: BitArray,
) -> Result(#(PrivateKey, PublicKey), Nil)
