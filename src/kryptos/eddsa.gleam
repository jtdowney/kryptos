//// Edwards-curve Digital Signature Algorithm (EdDSA).
////
//// EdDSA provides digital signatures using Edwards curves Ed25519 and Ed448.
//// Unlike ECDSA, EdDSA has built-in hashing (SHA-512 for Ed25519, SHAKE256
//// for Ed448) and produces deterministic signatures.
////
//// ## Example
////
//// ```gleam
//// import kryptos/eddsa
////
//// let #(private_key, public_key) = eddsa.generate_key_pair(eddsa.Ed25519)
//// let message = <<"hello world":utf8>>
//// let signature = eddsa.sign(private_key, message)
//// let valid = eddsa.verify(public_key, message, signature)
//// // valid == True
//// ```

/// An EdDSA private key.
pub type PrivateKey

/// An EdDSA public key.
pub type PublicKey

/// Error when importing an EdDSA key.
pub type ImportError {
  InvalidKeyData
  UnsupportedCurve
}

/// Supported curves for EdDSA signatures.
pub type Curve {
  /// Ed25519 curve. 32-byte keys, 64-byte signatures.
  Ed25519
  /// Ed448 curve. 57-byte keys, 114-byte signatures.
  Ed448
}

/// Returns the key size in bytes for the given curve.
///
/// - Ed25519: 32 bytes
/// - Ed448: 57 bytes
pub fn key_size(curve: Curve) -> Int {
  case curve {
    Ed25519 -> 32
    Ed448 -> 57
  }
}

/// Generates a new EdDSA key pair.
///
/// ## Parameters
/// - `curve`: The curve to use for key generation (Ed25519 or Ed448)
///
/// ## Returns
/// A tuple of `#(private_key, public_key)`.
@external(erlang, "kryptos_ffi", "eddsa_generate_key_pair")
@external(javascript, "../kryptos_ffi.mjs", "eddsaGenerateKeyPair")
pub fn generate_key_pair(curve: Curve) -> #(PrivateKey, PublicKey)

/// Signs a message using EdDSA.
///
/// The message is hashed internally using the curve's built-in hash function
/// (SHA-512 for Ed25519, SHAKE256 for Ed448). Signatures are deterministic:
/// signing the same message with the same key always produces the same signature.
///
/// ## Parameters
/// - `private_key`: An EdDSA private key from `generate_key_pair`
/// - `message`: The message to sign (any length)
///
/// ## Returns
/// A signature (64 bytes for Ed25519, 114 bytes for Ed448).
@external(erlang, "kryptos_ffi", "eddsa_sign")
@external(javascript, "../kryptos_ffi.mjs", "eddsaSign")
pub fn sign(private_key: PrivateKey, message: BitArray) -> BitArray

/// Verifies an EdDSA signature against a message.
///
/// ## Parameters
/// - `public_key`: The EdDSA public key corresponding to the signing key
/// - `message`: The original message that was signed
/// - `signature`: The signature to verify
///
/// ## Returns
/// `True` if the signature is valid, `False` otherwise.
@external(erlang, "kryptos_ffi", "eddsa_verify")
@external(javascript, "../kryptos_ffi.mjs", "eddsaVerify")
pub fn verify(
  public_key: PublicKey,
  message: BitArray,
  signature signature: BitArray,
) -> Bool

/// Imports a private key from raw bytes.
///
/// The bytes should be the raw private key seed:
/// - Ed25519: 32 bytes
/// - Ed448: 57 bytes
///
/// Returns the private key and its corresponding public key, or `Error(Nil)`
/// if the bytes are invalid.
@external(erlang, "kryptos_ffi", "eddsa_private_key_from_bytes")
@external(javascript, "../kryptos_ffi.mjs", "eddsaPrivateKeyFromBytes")
pub fn from_bytes(
  curve: Curve,
  private_bytes: BitArray,
) -> Result(#(PrivateKey, PublicKey), Nil)

/// Imports a public key from raw bytes.
///
/// The bytes should be the raw public key point:
/// - Ed25519: 32 bytes
/// - Ed448: 57 bytes
///
/// Returns the public key or `Error(Nil)` if the bytes are invalid.
@external(erlang, "kryptos_ffi", "eddsa_public_key_from_bytes")
@external(javascript, "../kryptos_ffi.mjs", "eddsaPublicKeyFromBytes")
pub fn public_key_from_bytes(
  curve: Curve,
  public_bytes: BitArray,
) -> Result(PublicKey, Nil)

/// Imports a private key from PEM-encoded data.
///
/// Expects a PKCS#8 encoded EdDSA private key.
/// Returns the private key and derived public key, or an error if invalid.
@external(erlang, "kryptos_ffi", "eddsa_import_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "eddsaImportPrivateKeyPem")
pub fn from_pem(pem: String) -> Result(#(PrivateKey, PublicKey), ImportError)

/// Imports a private key from DER-encoded data.
///
/// Expects a PKCS#8 encoded EdDSA private key.
/// Returns the private key and derived public key, or an error if invalid.
@external(erlang, "kryptos_ffi", "eddsa_import_private_key_der")
@external(javascript, "../kryptos_ffi.mjs", "eddsaImportPrivateKeyDer")
pub fn from_der(der: BitArray) -> Result(#(PrivateKey, PublicKey), ImportError)

/// Exports a private key to PEM format (PKCS#8).
@external(erlang, "kryptos_ffi", "eddsa_export_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "eddsaExportPrivateKeyPem")
pub fn to_pem(key: PrivateKey) -> Result(String, Nil)

/// Exports a private key to DER format (PKCS#8).
@external(erlang, "kryptos_ffi", "eddsa_export_private_key_der")
@external(javascript, "../kryptos_ffi.mjs", "eddsaExportPrivateKeyDer")
pub fn to_der(key: PrivateKey) -> Result(BitArray, Nil)

/// Imports a public key from PEM-encoded data.
///
/// Expects an SPKI encoded EdDSA public key.
@external(erlang, "kryptos_ffi", "eddsa_import_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "eddsaImportPublicKeyPem")
pub fn public_key_from_pem(pem: String) -> Result(PublicKey, ImportError)

/// Imports a public key from DER-encoded data.
///
/// Expects an SPKI encoded EdDSA public key.
@external(erlang, "kryptos_ffi", "eddsa_import_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "eddsaImportPublicKeyDer")
pub fn public_key_from_der(der: BitArray) -> Result(PublicKey, ImportError)

/// Exports a public key to PEM format (SPKI).
@external(erlang, "kryptos_ffi", "eddsa_export_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "eddsaExportPublicKeyPem")
pub fn public_key_to_pem(key: PublicKey) -> Result(String, Nil)

/// Exports a public key to DER format (SPKI).
@external(erlang, "kryptos_ffi", "eddsa_export_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "eddsaExportPublicKeyDer")
pub fn public_key_to_der(key: PublicKey) -> Result(BitArray, Nil)

/// Derives the public key from a private key.
@external(erlang, "kryptos_ffi", "eddsa_public_key_from_private")
@external(javascript, "../kryptos_ffi.mjs", "eddsaPublicKeyFromPrivate")
pub fn public_key_from_private_key(key: PrivateKey) -> PublicKey
