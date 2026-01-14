//// X25519 and X448 (XDH) key agreement.
////
//// XDH provides Diffie-Hellman key agreement using Montgomery curves X25519
//// and X448. These curves are designed specifically for key agreement and
//// offer excellent performance with strong security properties.
////
//// ## Example
////
//// ```gleam
//// import kryptos/xdh
////
//// // Alice generates a key pair
//// let #(alice_private, alice_public) = xdh.generate_key_pair(xdh.X25519)
////
//// // Bob generates a key pair
//// let #(bob_private, bob_public) = xdh.generate_key_pair(xdh.X25519)
////
//// // Both compute the same shared secret
//// let assert Ok(alice_shared) = xdh.compute_shared_secret(alice_private, bob_public)
//// let assert Ok(bob_shared) = xdh.compute_shared_secret(bob_private, alice_public)
//// // alice_shared == bob_shared
//// ```

import gleam/result
import gleam/string

/// An XDH private key.
pub type PrivateKey

/// An XDH public key.
pub type PublicKey

/// Supported curves for XDH key agreement.
pub type Curve {
  /// X25519 curve (Curve25519). 32-byte keys and shared secret.
  X25519
  /// X448 curve (Curve448). 56-byte keys and shared secret.
  X448
}

/// Returns the key size in bytes for the given curve.
///
/// - X25519: 32 bytes
/// - X448: 56 bytes
pub fn key_size(curve: Curve) -> Int {
  case curve {
    X25519 -> 32
    X448 -> 56
  }
}

/// Generates a new XDH key pair.
///
/// ## Parameters
/// - `curve`: The curve to use for key generation (X25519 or X448)
///
/// ## Returns
/// A tuple of `#(private_key, public_key)`.
@external(erlang, "kryptos_ffi", "xdh_generate_key_pair")
@external(javascript, "../kryptos_ffi.mjs", "xdhGenerateKeyPair")
pub fn generate_key_pair(curve: Curve) -> #(PrivateKey, PublicKey)

/// Computes a shared secret using XDH key agreement.
///
/// Both parties compute the same shared secret by combining their private key
/// with the other party's public key.
///
/// Returns `Error(Nil)` if the keys use different curves, the result is an
/// all-zero shared secret (low-order point attack), or another error occurs.
///
/// The raw shared secret should be passed through a KDF (like HKDF) before
/// use as a symmetric key.
pub fn compute_shared_secret(
  private_key: PrivateKey,
  peer_public_key: PublicKey,
) -> Result(BitArray, Nil) {
  use shared <- result.try(do_compute_shared_secret(
    private_key,
    peer_public_key,
  ))
  case is_all_zeros(shared) {
    True -> Error(Nil)
    False -> Ok(shared)
  }
}

fn is_all_zeros(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<0, rest:bytes>> -> is_all_zeros(rest)
    _ -> False
  }
}

@external(erlang, "kryptos_ffi", "xdh_compute_shared_secret")
@external(javascript, "../kryptos_ffi.mjs", "xdhComputeSharedSecret")
fn do_compute_shared_secret(
  private_key: PrivateKey,
  peer_public_key: PublicKey,
) -> Result(BitArray, Nil)

/// Imports a private key from raw bytes.
///
/// The bytes should be the raw private key scalar:
/// - X25519: 32 bytes
/// - X448: 56 bytes
///
/// Returns the private key and its corresponding public key, or `Error(Nil)`
/// if the bytes are invalid.
@external(erlang, "kryptos_ffi", "xdh_private_key_from_bytes")
@external(javascript, "../kryptos_ffi.mjs", "xdhPrivateKeyFromBytes")
pub fn from_bytes(
  curve: Curve,
  private_bytes: BitArray,
) -> Result(#(PrivateKey, PublicKey), Nil)

/// Exports a private key to raw bytes.
///
/// Returns the raw private key scalar:
/// - X25519: 32 bytes
/// - X448: 56 bytes
@external(erlang, "kryptos_ffi", "xdh_private_key_to_bytes")
@external(javascript, "../kryptos_ffi.mjs", "xdhPrivateKeyToBytes")
pub fn to_bytes(key: PrivateKey) -> BitArray

/// Imports a public key from raw bytes.
///
/// The bytes should be the raw public key point:
/// - X25519: 32 bytes
/// - X448: 56 bytes
///
/// Returns the public key or `Error(Nil)` if the bytes are invalid.
@external(erlang, "kryptos_ffi", "xdh_public_key_from_bytes")
@external(javascript, "../kryptos_ffi.mjs", "xdhPublicKeyFromBytes")
pub fn public_key_from_bytes(
  curve: Curve,
  public_bytes: BitArray,
) -> Result(PublicKey, Nil)

/// Exports a public key to raw bytes.
///
/// Returns the raw public key point:
/// - X25519: 32 bytes
/// - X448: 56 bytes
@external(erlang, "kryptos_ffi", "xdh_public_key_to_bytes")
@external(javascript, "../kryptos_ffi.mjs", "xdhPublicKeyToBytes")
pub fn public_key_to_bytes(key: PublicKey) -> BitArray

/// Imports an XDH private key from PEM-encoded data.
///
/// The key must be in PKCS#8 format.
///
/// ## Parameters
/// - `pem`: PEM-encoded key string
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "xdh_import_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "xdhImportPrivateKeyPem")
pub fn from_pem(pem: String) -> Result(#(PrivateKey, PublicKey), Nil)

/// Imports an XDH private key from DER-encoded data.
///
/// The key must be in PKCS#8 format.
///
/// ## Parameters
/// - `der`: DER-encoded key data
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "xdh_import_private_key_der")
@external(javascript, "../kryptos_ffi.mjs", "xdhImportPrivateKeyDer")
pub fn from_der(der: BitArray) -> Result(#(PrivateKey, PublicKey), Nil)

/// Exports an XDH private key to PEM format.
///
/// The key is exported in PKCS#8 format.
///
/// ## Parameters
/// - `key`: The private key to export
///
/// ## Returns
/// `Ok(pem_string)` on success, `Error(Nil)` on failure.
pub fn to_pem(key: PrivateKey) -> Result(String, Nil) {
  do_to_pem(key) |> result.map(fn(pem) { string.trim_end(pem) <> "\n" })
}

@external(erlang, "kryptos_ffi", "xdh_export_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "xdhExportPrivateKeyPem")
fn do_to_pem(key: PrivateKey) -> Result(String, Nil)

/// Exports an XDH private key to DER format.
///
/// The key is exported in PKCS#8 format.
///
/// ## Parameters
/// - `key`: The private key to export
///
/// ## Returns
/// `Ok(der_data)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "xdh_export_private_key_der")
@external(javascript, "../kryptos_ffi.mjs", "xdhExportPrivateKeyDer")
pub fn to_der(key: PrivateKey) -> Result(BitArray, Nil)

/// Imports an XDH public key from PEM-encoded data.
///
/// The key must be in SPKI format.
///
/// ## Parameters
/// - `pem`: PEM-encoded key string
///
/// ## Returns
/// `Ok(public_key)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "xdh_import_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "xdhImportPublicKeyPem")
pub fn public_key_from_pem(pem: String) -> Result(PublicKey, Nil)

/// Imports an XDH public key from DER-encoded data.
///
/// The key must be in SPKI format.
///
/// ## Parameters
/// - `der`: DER-encoded key data
///
/// ## Returns
/// `Ok(public_key)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "xdh_import_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "xdhImportPublicKeyDer")
pub fn public_key_from_der(der: BitArray) -> Result(PublicKey, Nil)

/// Exports an XDH public key to PEM format.
///
/// The key is exported in SPKI format.
///
/// ## Parameters
/// - `key`: The public key to export
///
/// ## Returns
/// `Ok(pem_string)` on success, `Error(Nil)` on failure.
pub fn public_key_to_pem(key: PublicKey) -> Result(String, Nil) {
  do_public_key_to_pem(key)
  |> result.map(fn(pem) { string.trim_end(pem) <> "\n" })
}

@external(erlang, "kryptos_ffi", "xdh_export_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "xdhExportPublicKeyPem")
fn do_public_key_to_pem(key: PublicKey) -> Result(String, Nil)

/// Exports an XDH public key to DER format.
///
/// The key is exported in SPKI format.
///
/// ## Parameters
/// - `key`: The public key to export
///
/// ## Returns
/// `Ok(der_data)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "xdh_export_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "xdhExportPublicKeyDer")
pub fn public_key_to_der(key: PublicKey) -> Result(BitArray, Nil)

/// Derives the public key from an XDH private key.
///
/// ## Parameters
/// - `key`: The private key
///
/// ## Returns
/// The corresponding public key.
@external(erlang, "kryptos_ffi", "xdh_public_key_from_private")
@external(javascript, "../kryptos_ffi.mjs", "xdhPublicKeyFromPrivate")
pub fn public_key_from_private_key(key: PrivateKey) -> PublicKey

/// Returns the curve for an XDH private key.
///
/// ## Parameters
/// - `key`: The private key
///
/// ## Returns
/// The curve used by this key.
@external(erlang, "kryptos_ffi", "xdh_private_key_curve")
@external(javascript, "../kryptos_ffi.mjs", "xdhPrivateKeyCurve")
pub fn curve(key: PrivateKey) -> Curve

/// Returns the curve for an XDH public key.
///
/// ## Parameters
/// - `key`: The public key
///
/// ## Returns
/// The curve used by this key.
@external(erlang, "kryptos_ffi", "xdh_public_key_curve")
@external(javascript, "../kryptos_ffi.mjs", "xdhPublicKeyCurve")
pub fn public_key_curve(key: PublicKey) -> Curve
