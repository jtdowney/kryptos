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

import kryptos/public_key.{type EdDSA, type PrivateKey, type PublicKey}

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
pub fn generate_key_pair(
  curve: Curve,
) -> #(PrivateKey(EdDSA, Nil, Nil), PublicKey(EdDSA, Nil, Nil))

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
pub fn sign(
  private_key: PrivateKey(EdDSA, encrypting, key_agree),
  message: BitArray,
) -> BitArray

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
  public_key: PublicKey(EdDSA, encrypting, key_agree),
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
pub fn private_key_from_bytes(
  curve: Curve,
  private_bytes: BitArray,
) -> Result(#(PrivateKey(EdDSA, Nil, Nil), PublicKey(EdDSA, Nil, Nil)), Nil)

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
) -> Result(PublicKey(EdDSA, Nil, Nil), Nil)
