//// Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
////
//// ML-DSA (formerly CRYSTALS-Dilithium) provides post-quantum digital
//// signatures based on lattice problems believed to resist both classical and
//// quantum attacks. Conventional schemes like ECDSA and Ed25519 rely on
//// elliptic-curve discrete logarithms, which a sufficiently powerful quantum
//// computer could break via [Shor's algorithm](https://en.wikipedia.org/wiki/Shor's_algorithm).
//// ML-DSA is designed for systems that need long-term security guarantees.
////
//// ## Trade-offs
////
//// Post-quantum security comes at a cost. ML-DSA public keys and signatures
//// are significantly larger than their classical counterparts:
////
//// | Algorithm   | Public Key | Signature |
//// | ----------- | ---------- | --------- |
//// | Ed25519     | 32 B       | 64 B      |
//// | ECDSA P-256 | 64 B       | 64 B      |
//// | ML-DSA-44   | 1,312 B    | 2,420 B   |
//// | ML-DSA-65   | 1,952 B    | 3,309 B   |
//// | ML-DSA-87   | 2,592 B    | 4,627 B   |
////
//// All of these use a 32-byte private key. For ML-DSA that is the seed this
//// module stores and exports; the expanded signing key held in memory is
//// larger (2,560 to 4,896 B) but is never serialized.
////
//// These larger sizes affect wire overhead, certificate sizes, handshake
//// latency, and storage. ML-DSA-44 targets roughly NIST Security Level 2
//// (comparable to AES-128), ML-DSA-65 targets Level 3, and ML-DSA-87 targets
//// Level 5. Choose the smallest parameter set that meets your security
//// requirements. ML-DSA-44 is appropriate for most applications.
////
//// ## Key representations
////
//// FIPS 204 defines two private key representations: a compact 32-byte seed
//// and the fully expanded key material. Following the
//// [CFRG security considerations](https://datatracker.ietf.org/doc/draft-connolly-cfrg-ml-dsa-security-considerations/),
//// this module treats the seed as the canonical representation and never
//// exposes expanded keys. Seed generation guarantees well-formed key material,
//// whereas an externally supplied expanded key could be malformed. The
//// [pyca/cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mldsa/)
//// library takes the same seed-only approach.
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

import kryptos/internal/utils

/// An ML-DSA private key.
pub type PrivateKey

/// An ML-DSA public key.
pub type PublicKey

/// ML-DSA parameter sets.
pub type ParameterSet {
  /// ML-DSA-44. 1312-byte public keys, 2420-byte signatures.
  Mldsa44
  /// ML-DSA-65. 1952-byte public keys, 3309-byte signatures.
  Mldsa65
  /// ML-DSA-87. 2592-byte public keys, 4627-byte signatures.
  Mldsa87
}

/// Returns the public key size in bytes for the given parameter set.
pub fn key_size(param: ParameterSet) -> Int {
  case param {
    Mldsa44 -> 1312
    Mldsa65 -> 1952
    Mldsa87 -> 2592
  }
}

/// Returns the signature size in bytes for the given parameter set.
pub fn signature_size(param: ParameterSet) -> Int {
  case param {
    Mldsa44 -> 2420
    Mldsa65 -> 3309
    Mldsa87 -> 4627
  }
}

/// Returns whether the current runtime supports ML-DSA operations.
///
/// ML-DSA requires Erlang/OTP 28 or later, or Node.js 24 or later. On older
/// runtimes this returns `False` and ML-DSA operations are unavailable.
@external(erlang, "kryptos_ffi", "mldsa_supported")
@external(javascript, "../kryptos_ffi.mjs", "mldsaSupported")
pub fn supported() -> Bool

/// Generates a new ML-DSA key pair.
@external(erlang, "kryptos_ffi", "mldsa_generate_key_pair")
@external(javascript, "../kryptos_ffi.mjs", "mldsaGenerateKeyPair")
pub fn generate_key_pair(param: ParameterSet) -> #(PrivateKey, PublicKey)

/// Signs a message using ML-DSA.
///
/// ML-DSA includes built-in hashing. No separate hash algorithm parameter
/// is needed.
@external(erlang, "kryptos_ffi", "mldsa_sign")
@external(javascript, "../kryptos_ffi.mjs", "mldsaSign")
pub fn sign(private_key: PrivateKey, message: BitArray) -> BitArray

/// Verifies an ML-DSA signature against a message.
@external(erlang, "kryptos_ffi", "mldsa_verify")
@external(javascript, "../kryptos_ffi.mjs", "mldsaVerify")
pub fn verify(
  public_key: PublicKey,
  message: BitArray,
  signature signature: BitArray,
) -> Bool

/// Exports a public key to its FIPS 204 raw byte encoding (`rho || t1_packed`),
/// without any ASN.1 wrapping. Use `public_key_to_pem` or `public_key_to_der`
/// for SPKI-encoded output.
@external(erlang, "kryptos_ffi", "mldsa_public_key_to_bytes")
@external(javascript, "../kryptos_ffi.mjs", "mldsaPublicKeyToBytes")
pub fn public_key_to_bytes(key: PublicKey) -> BitArray

/// Imports a public key from its FIPS 204 raw byte encoding (`rho || t1_packed`),
/// without any ASN.1 wrapping. Use `public_key_from_pem` or `public_key_from_der`
/// for SPKI-encoded input.
///
/// Returns `Error(Nil)` if the bytes are the wrong size for the parameter set.
@external(erlang, "kryptos_ffi", "mldsa_public_key_from_bytes")
@external(javascript, "../kryptos_ffi.mjs", "mldsaPublicKeyFromBytes")
pub fn public_key_from_bytes(
  param: ParameterSet,
  public_bytes: BitArray,
) -> Result(PublicKey, Nil)

/// Derives the public key from an ML-DSA private key.
@external(erlang, "kryptos_ffi", "mldsa_public_key_from_private")
@external(javascript, "../kryptos_ffi.mjs", "mldsaPublicKeyFromPrivate")
pub fn public_key_from_private_key(key: PrivateKey) -> PublicKey

/// Returns the parameter set for an ML-DSA private key.
@external(erlang, "kryptos_ffi", "mldsa_private_key_parameter_set")
@external(javascript, "../kryptos_ffi.mjs", "mldsaPrivateKeyParameterSet")
pub fn parameter_set(key: PrivateKey) -> ParameterSet

/// Returns the parameter set for an ML-DSA public key.
@external(erlang, "kryptos_ffi", "mldsa_public_key_parameter_set")
@external(javascript, "../kryptos_ffi.mjs", "mldsaPublicKeyParameterSet")
pub fn public_key_parameter_set(key: PublicKey) -> ParameterSet

/// Creates an ML-DSA key pair from a 32-byte seed.
///
/// Returns `Error(Nil)` if the seed is not exactly 32 bytes.
@external(erlang, "kryptos_ffi", "mldsa_from_seed")
@external(javascript, "../kryptos_ffi.mjs", "mldsaFromSeed")
pub fn from_seed(
  param: ParameterSet,
  seed: BitArray,
) -> Result(#(PrivateKey, PublicKey), Nil)

/// Exports the 32-byte seed from an ML-DSA private key.
@external(erlang, "kryptos_ffi", "mldsa_private_key_to_seed")
@external(javascript, "../kryptos_ffi.mjs", "mldsaPrivateKeyToSeed")
pub fn private_key_to_seed(key: PrivateKey) -> Result(BitArray, Nil)

/// Imports an ML-DSA private key from PEM-encoded data.
///
/// The key must carry the 32-byte seed. ExpandedKey-only encodings, which
/// omit the seed, are rejected with `Error(Nil)`.
@external(erlang, "kryptos_ffi", "mldsa_import_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "mldsaImportPrivateKeyPem")
pub fn from_pem(pem: String) -> Result(#(PrivateKey, PublicKey), Nil)

/// Imports an ML-DSA private key from DER-encoded data.
///
/// The key must carry the 32-byte seed. ExpandedKey-only encodings, which
/// omit the seed, are rejected with `Error(Nil)`.
@external(erlang, "kryptos_ffi", "mldsa_import_private_key_der")
@external(javascript, "../kryptos_ffi.mjs", "mldsaImportPrivateKeyDer")
pub fn from_der(der: BitArray) -> Result(#(PrivateKey, PublicKey), Nil)

/// Exports an ML-DSA private key to PEM format.
///
/// The key is exported as seed-form PKCS#8.
pub fn to_pem(key: PrivateKey) -> String {
  let assert Ok(pem) = do_to_pem(key) |> utils.normalize_pem
  pem
}

@external(erlang, "kryptos_ffi", "mldsa_export_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "exportPrivateKeyPem")
fn do_to_pem(key: PrivateKey) -> Result(String, Nil)

/// Exports an ML-DSA private key to DER format.
///
/// The key is exported as seed-form PKCS#8.
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
@external(erlang, "kryptos_ffi", "mldsa_import_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "mldsaImportPublicKeyPem")
pub fn public_key_from_pem(pem: String) -> Result(PublicKey, Nil)

/// Imports an ML-DSA public key from DER-encoded data.
///
/// The key must be in SPKI format.
@external(erlang, "kryptos_ffi", "mldsa_import_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "mldsaImportPublicKeyDer")
pub fn public_key_from_der(der: BitArray) -> Result(PublicKey, Nil)

/// Exports an ML-DSA public key to PEM format.
///
/// The key is exported in SPKI format.
pub fn public_key_to_pem(key: PublicKey) -> String {
  let assert Ok(pem) = do_public_key_to_pem(key) |> utils.normalize_pem
  pem
}

@external(erlang, "kryptos_ffi", "export_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "exportPublicKeyPem")
fn do_public_key_to_pem(key: PublicKey) -> Result(String, Nil)

/// Exports an ML-DSA public key to DER format.
///
/// The key is exported in SPKI format.
pub fn public_key_to_der(key: PublicKey) -> BitArray {
  let assert Ok(der) = do_public_key_to_der(key)
  der
}

@external(erlang, "kryptos_ffi", "export_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "exportPublicKeyDer")
fn do_public_key_to_der(key: PublicKey) -> Result(BitArray, Nil)
