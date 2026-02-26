//// Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
////
//// ML-DSA (formerly CRYSTALS-Dilithium) provides post-quantum digital
//// signatures based on lattice problems believed to resist both classical and
//// quantum attacks. Conventional schemes like ECDSA and Ed25519 rely on
//// elliptic-curve discrete logarithms, which a sufficiently powerful quantum
//// computer could break via Shor's algorithm. ML-DSA is designed for systems
//// that need long-term security guarantees.
////
//// ## Trade-offs
////
//// Post-quantum security comes at a cost. ML-DSA keys and signatures are
//// significantly larger than their classical counterparts:
////
//// | Algorithm   | Public Key | Private Key | Signature |
//// | ----------- | ---------- | ----------- | --------- |
//// | Ed25519     | 32 B       | 32 B        | 64 B      |
//// | ECDSA P-256 | 64 B       | 32 B        | 64 B      |
//// | ML-DSA-44   | 1,312 B    | 2,560 B     | 2,420 B   |
//// | ML-DSA-65   | 1,952 B    | 4,032 B     | 3,309 B   |
//// | ML-DSA-87   | 2,592 B    | 4,896 B     | 4,627 B   |
////
//// These larger sizes affect wire overhead, certificate sizes, handshake
//// latency, and storage. ML-DSA-44 targets roughly NIST Security Level 2
//// (comparable to AES-128), ML-DSA-65 targets Level 3, and ML-DSA-87 targets
//// Level 5. Choose the smallest parameter set that meets your security
//// requirements — ML-DSA-44 is appropriate for most applications.
////
//// ## Key representations
////
//// The ML-DSA specification defines two private key representations:
////
//// - **Seed form**: a compact 32-byte seed from which the full key material
////   can be derived. Storage-efficient but requires expansion before signing
////   on some platforms.
//// - **Expanded form**: the fully expanded key material, ready for immediate
////   use.
////
//// This module supports both forms. `generate_key_pair` returns expanded keys.
//// `from_seed` accepts a raw 32-byte seed. `from_pem` and `from_der` accept
//// PKCS#8 encodings in any of the three FIPS 204 variants (seed, expandedKey,
//// or both). Seed-based keys export in seed-only PKCS#8 format; expanded keys
//// export in expandedKey format.
////
//// ## Context strings
////
//// FIPS 204 defines an optional context string parameter for signing and
//// verification. Neither Erlang/OTP nor Node.js expose this parameter in
//// their crypto APIs, so this module always uses the default empty context
//// string.
////
//// ## Example
////
//// ```gleam
//// import kryptos/mldsa
////
//// let #(private_key, public_key) = mldsa.generate_key_pair(mldsa.Mldsa44)
//// let message = <<"hello world":utf8>>
//// let signature = mldsa.sign(private_key, message)
//// let valid = mldsa.verify(public_key, message, signature)
//// // valid == True
//// ```

import gleam/string

/// An ML-DSA private key.
pub type PrivateKey

/// An ML-DSA public key.
pub type PublicKey

/// ML-DSA parameter sets.
pub type ParameterSet {
  /// ML-DSA-44. 1312-byte public keys, 2560-byte private keys, 2420-byte signatures.
  Mldsa44
  /// ML-DSA-65. 1952-byte public keys, 4032-byte private keys, 3309-byte signatures.
  Mldsa65
  /// ML-DSA-87. 2592-byte public keys, 4896-byte private keys, 4627-byte signatures.
  Mldsa87
}

/// Returns the public key size in bytes for the given parameter set.
///
/// ## Parameters
/// - `param`: The ML-DSA parameter set
///
/// ## Returns
/// The public key size in bytes (1312 for ML-DSA-44, 1952 for ML-DSA-65,
/// 2592 for ML-DSA-87).
pub fn key_size(param: ParameterSet) -> Int {
  case param {
    Mldsa44 -> 1312
    Mldsa65 -> 1952
    Mldsa87 -> 2592
  }
}

/// Returns the private key size in bytes for the given parameter set.
///
/// ## Parameters
/// - `param`: The ML-DSA parameter set
///
/// ## Returns
/// The private key size in bytes (2560 for ML-DSA-44, 4032 for ML-DSA-65,
/// 4896 for ML-DSA-87).
pub fn private_key_size(param: ParameterSet) -> Int {
  case param {
    Mldsa44 -> 2560
    Mldsa65 -> 4032
    Mldsa87 -> 4896
  }
}

/// Returns the signature size in bytes for the given parameter set.
///
/// ## Parameters
/// - `param`: The ML-DSA parameter set
///
/// ## Returns
/// The signature size in bytes (2420 for ML-DSA-44, 3309 for ML-DSA-65,
/// 4627 for ML-DSA-87).
pub fn signature_size(param: ParameterSet) -> Int {
  case param {
    Mldsa44 -> 2420
    Mldsa65 -> 3309
    Mldsa87 -> 4627
  }
}

/// Generates a new ML-DSA key pair.
///
/// ## Parameters
/// - `param`: The parameter set to use for key generation
///
/// ## Returns
/// A tuple of `#(private_key, public_key)`.
@external(erlang, "kryptos_ffi", "mldsa_generate_key_pair")
@external(javascript, "../kryptos_ffi.mjs", "mldsaGenerateKeyPair")
pub fn generate_key_pair(param: ParameterSet) -> #(PrivateKey, PublicKey)

/// Signs a message using ML-DSA.
///
/// ML-DSA includes built-in hashing. No separate hash algorithm parameter
/// is needed.
///
/// ## Parameters
/// - `private_key`: An ML-DSA private key from `generate_key_pair`
/// - `message`: The message to sign (any length)
///
/// ## Returns
/// A signature (2420 bytes for ML-DSA-44, 3309 bytes for ML-DSA-65,
/// 4627 bytes for ML-DSA-87).
@external(erlang, "kryptos_ffi", "mldsa_sign")
@external(javascript, "../kryptos_ffi.mjs", "mldsaSign")
pub fn sign(private_key: PrivateKey, message: BitArray) -> BitArray

/// Verifies an ML-DSA signature against a message.
///
/// ## Parameters
/// - `public_key`: The ML-DSA public key corresponding to the signing key
/// - `message`: The original message that was signed
/// - `signature`: The signature to verify
///
/// ## Returns
/// `True` if the signature is valid, `False` otherwise.
@external(erlang, "kryptos_ffi", "mldsa_verify")
@external(javascript, "../kryptos_ffi.mjs", "mldsaVerify")
pub fn verify(
  public_key: PublicKey,
  message: BitArray,
  signature signature: BitArray,
) -> Bool

/// Exports a public key to its FIPS 204 raw byte encoding (`ρ || t1_packed`),
/// without any ASN.1 wrapping. Use `public_key_to_pem` or `public_key_to_der`
/// for SPKI-encoded output.
///
/// ## Parameters
/// - `key`: The ML-DSA public key to export
///
/// ## Returns
/// The raw public key bytes:
/// - ML-DSA-44: 1312 bytes
/// - ML-DSA-65: 1952 bytes
/// - ML-DSA-87: 2592 bytes
@external(erlang, "kryptos_ffi", "mldsa_public_key_to_bytes")
@external(javascript, "../kryptos_ffi.mjs", "mldsaPublicKeyToBytes")
pub fn public_key_to_bytes(key: PublicKey) -> BitArray

/// Imports a public key from its FIPS 204 raw byte encoding (`ρ || t1_packed`),
/// without any ASN.1 wrapping. Use `public_key_from_pem` or `public_key_from_der`
/// for SPKI-encoded input.
///
/// ## Parameters
/// - `param`: The ML-DSA parameter set
/// - `public_bytes`: Raw public key bytes (`ρ || t1_packed`)
///
/// ## Returns
/// `Ok(public_key)` on success, `Error(Nil)` if the bytes are the wrong size.
/// Expected sizes: 1312 bytes for ML-DSA-44, 1952 for ML-DSA-65, 2592 for ML-DSA-87.
@external(erlang, "kryptos_ffi", "mldsa_public_key_from_bytes")
@external(javascript, "../kryptos_ffi.mjs", "mldsaPublicKeyFromBytes")
pub fn public_key_from_bytes(
  param: ParameterSet,
  public_bytes: BitArray,
) -> Result(PublicKey, Nil)

/// Derives the public key from an ML-DSA private key.
///
/// ## Parameters
/// - `key`: The private key
///
/// ## Returns
/// The corresponding public key.
@external(erlang, "kryptos_ffi", "mldsa_public_key_from_private")
@external(javascript, "../kryptos_ffi.mjs", "mldsaPublicKeyFromPrivate")
pub fn public_key_from_private_key(key: PrivateKey) -> PublicKey

/// Returns the parameter set for an ML-DSA private key.
///
/// ## Parameters
/// - `key`: The private key
///
/// ## Returns
/// The parameter set used by this key.
@external(erlang, "kryptos_ffi", "mldsa_private_key_parameter_set")
@external(javascript, "../kryptos_ffi.mjs", "mldsaPrivateKeyParameterSet")
pub fn parameter_set(key: PrivateKey) -> ParameterSet

/// Returns the parameter set for an ML-DSA public key.
///
/// ## Parameters
/// - `key`: The public key
///
/// ## Returns
/// The parameter set used by this key.
@external(erlang, "kryptos_ffi", "mldsa_public_key_parameter_set")
@external(javascript, "../kryptos_ffi.mjs", "mldsaPublicKeyParameterSet")
pub fn public_key_parameter_set(key: PublicKey) -> ParameterSet

/// Creates an ML-DSA key pair from a 32-byte seed.
///
/// On Erlang, the public key is derived using a pure Gleam implementation
/// of FIPS 204 `KeyGen_internal`. On JavaScript, the native crypto module
/// handles seed expansion.
///
/// ## Parameters
/// - `param`: The ML-DSA parameter set
/// - `seed`: A 32-byte seed
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` if the seed
/// is not exactly 32 bytes.
@external(erlang, "kryptos_ffi", "mldsa_from_seed")
@external(javascript, "../kryptos_ffi.mjs", "mldsaFromSeed")
pub fn from_seed(
  param: ParameterSet,
  seed: BitArray,
) -> Result(#(PrivateKey, PublicKey), Nil)

/// Imports an ML-DSA private key from PEM-encoded data.
///
/// The key must be in PKCS#8 format.
///
/// ## Parameters
/// - `pem`: PEM-encoded key string
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "mldsa_import_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "mldsaImportPrivateKeyPem")
pub fn from_pem(pem: String) -> Result(#(PrivateKey, PublicKey), Nil)

/// Imports an ML-DSA private key from DER-encoded data.
///
/// The key must be in PKCS#8 format.
///
/// ## Parameters
/// - `der`: DER-encoded key data
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "mldsa_import_private_key_der")
@external(javascript, "../kryptos_ffi.mjs", "mldsaImportPrivateKeyDer")
pub fn from_der(der: BitArray) -> Result(#(PrivateKey, PublicKey), Nil)

/// Exports an ML-DSA private key to PEM format.
///
/// The key is exported in PKCS#8 format.
///
/// ## Parameters
/// - `key`: The private key to export
pub fn to_pem(key: PrivateKey) -> String {
  let assert Ok(pem) = do_to_pem(key)
  string.trim_end(pem) <> "\n"
}

@external(erlang, "kryptos_ffi", "mldsa_export_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "exportPrivateKeyPem")
fn do_to_pem(key: PrivateKey) -> Result(String, Nil)

/// Exports an ML-DSA private key to DER format.
///
/// The key is exported in PKCS#8 format.
///
/// ## Parameters
/// - `key`: The private key to export
pub fn to_der(key: PrivateKey) -> BitArray {
  let assert Ok(der) = do_to_der(key)
  der
}

@external(erlang, "kryptos_ffi", "mldsa_export_private_key_der")
@external(javascript, "../kryptos_ffi.mjs", "exportPrivateKeyDer")
fn do_to_der(key: PrivateKey) -> Result(BitArray, Nil)

/// Imports an ML-DSA public key from PEM-encoded data.
///
/// The key must be in SPKI format.
///
/// ## Parameters
/// - `pem`: PEM-encoded key string
///
/// ## Returns
/// `Ok(public_key)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "mldsa_import_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "mldsaImportPublicKeyPem")
pub fn public_key_from_pem(pem: String) -> Result(PublicKey, Nil)

/// Imports an ML-DSA public key from DER-encoded data.
///
/// The key must be in SPKI format.
///
/// ## Parameters
/// - `der`: DER-encoded key data
///
/// ## Returns
/// `Ok(public_key)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "mldsa_import_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "mldsaImportPublicKeyDer")
pub fn public_key_from_der(der: BitArray) -> Result(PublicKey, Nil)

/// Exports an ML-DSA public key to PEM format.
///
/// The key is exported in SPKI format.
///
/// ## Parameters
/// - `key`: The public key to export
pub fn public_key_to_pem(key: PublicKey) -> String {
  let assert Ok(pem) = do_public_key_to_pem(key)
  string.trim_end(pem) <> "\n"
}

@external(erlang, "kryptos_ffi", "mldsa_export_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "exportPublicKeyPem")
fn do_public_key_to_pem(key: PublicKey) -> Result(String, Nil)

/// Exports an ML-DSA public key to DER format.
///
/// The key is exported in SPKI format.
///
/// ## Parameters
/// - `key`: The public key to export
pub fn public_key_to_der(key: PublicKey) -> BitArray {
  let assert Ok(der) = do_public_key_to_der(key)
  der
}

@external(erlang, "kryptos_ffi", "mldsa_export_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "exportPublicKeyDer")
fn do_public_key_to_der(key: PublicKey) -> Result(BitArray, Nil)
