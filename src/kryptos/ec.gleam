//// Elliptic Curve Cryptography key generation and management.
////
//// This module provides key pair generation for elliptic curve cryptography,
//// supporting standard NIST curves and secp256k1. EC keys can be used for
//// both ECDSA signatures and ECDH key agreement.
////
//// ## Key Generation
////
//// ```gleam
//// import kryptos/ec
////
//// let #(private_key, public_key) = ec.generate_key_pair(ec.P256)
//// ```
////
//// ## Import/Export
////
//// ```gleam
//// import kryptos/ec
////
//// let #(private_key, _public_key) = ec.generate_key_pair(ec.P256)
//// let assert Ok(pem) = ec.to_pem(private_key)
//// let assert Ok(#(imported_private, _)) = ec.from_pem(pem)
//// ```

import gleam/result
import gleam/string

/// An elliptic curve private key.
pub type PrivateKey

/// An elliptic curve public key.
pub type PublicKey

/// Supported elliptic curves for key generation.
pub type Curve {
  /// NIST P-256 curve (secp256r1, prime256v1). 256-bit key size.
  P256
  /// NIST P-384 curve (secp384r1). 384-bit key size.
  P384
  /// NIST P-521 curve (secp521r1). 521-bit key size.
  P521
  /// Koblitz curve used by Bitcoin and Ethereum. 256-bit key size.
  Secp256k1
}

/// Returns the coordinate size in bytes for the given curve.
///
/// This is the size of each coordinate (x or y) in an EC point.
/// An uncompressed point is 1 + 2 * coordinate_size bytes.
pub fn coordinate_size(curve: Curve) -> Int {
  case curve {
    P256 | Secp256k1 -> 32
    P384 -> 48
    P521 -> 66
  }
}

/// Generates a new elliptic curve key pair.
///
/// The private key should be kept secret and used for signing.
/// The public key can be shared and is used for signature verification.
///
/// ## Parameters
/// - `curve`: The elliptic curve to use for key generation
///
/// ## Returns
/// A tuple of `#(private_key, public_key)`.
@external(erlang, "kryptos_ffi", "ec_generate_key_pair")
@external(javascript, "../kryptos_ffi.mjs", "ecGenerateKeyPair")
pub fn generate_key_pair(curve: Curve) -> #(PrivateKey, PublicKey)

/// Imports an EC private key from PEM-encoded data.
///
/// The key must be in PKCS#8 format.
///
/// ## Parameters
/// - `pem`: PEM-encoded key string
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "ec_import_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "ecImportPrivateKeyPem")
pub fn from_pem(pem: String) -> Result(#(PrivateKey, PublicKey), Nil)

/// Imports an EC private key from DER-encoded data.
///
/// The key must be in PKCS#8 format.
///
/// ## Parameters
/// - `der`: DER-encoded key data
///
/// ## Returns
/// `Ok(#(private_key, public_key))` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "ec_import_private_key_der")
@external(javascript, "../kryptos_ffi.mjs", "ecImportPrivateKeyDer")
pub fn from_der(der: BitArray) -> Result(#(PrivateKey, PublicKey), Nil)

/// Exports an EC private key to PEM format.
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

@external(erlang, "kryptos_ffi", "ec_export_private_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "ecExportPrivateKeyPem")
fn do_to_pem(key: PrivateKey) -> Result(String, Nil)

/// Exports an EC private key to DER format.
///
/// The key is exported in PKCS#8 format.
///
/// ## Parameters
/// - `key`: The private key to export
///
/// ## Returns
/// `Ok(der_data)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "ec_export_private_key_der")
@external(javascript, "../kryptos_ffi.mjs", "ecExportPrivateKeyDer")
pub fn to_der(key: PrivateKey) -> Result(BitArray, Nil)

/// Imports an EC public key from PEM-encoded data.
///
/// The key must be in SPKI format.
///
/// ## Parameters
/// - `pem`: PEM-encoded key string
///
/// ## Returns
/// `Ok(public_key)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "ec_import_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "ecImportPublicKeyPem")
pub fn public_key_from_pem(pem: String) -> Result(PublicKey, Nil)

/// Imports an EC public key from DER-encoded data.
///
/// The key must be in SPKI format.
///
/// ## Parameters
/// - `der`: DER-encoded key data
///
/// ## Returns
/// `Ok(public_key)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "ec_import_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "ecImportPublicKeyDer")
pub fn public_key_from_der(der: BitArray) -> Result(PublicKey, Nil)

/// Imports an EC public key from an uncompressed SEC1 point.
///
/// The point must be in uncompressed format: `0x04 || x || y`
/// where x and y are the coordinates padded to the curve's coordinate size.
///
/// ## Parameters
/// - `curve`: The elliptic curve (P256, P384, P521, or Secp256k1)
/// - `point`: The uncompressed point bytes (1 + 2 * coordinate_size bytes)
///
/// ## Returns
/// `Ok(public_key)` on success, `Error(Nil)` if the format is invalid
/// or the point is not on the curve.
@external(erlang, "kryptos_ffi", "ec_public_key_from_raw_point")
@external(javascript, "../kryptos_ffi.mjs", "ecPublicKeyFromRawPoint")
pub fn public_key_from_raw_point(
  curve: Curve,
  point: BitArray,
) -> Result(PublicKey, Nil)

/// Exports a public key to uncompressed SEC1 point format.
///
/// Returns a BitArray in the format: `0x04 || X || Y` where X and Y are
/// the coordinates of the public key point, each padded to the curve's
/// coordinate size.
///
/// On Erlang, returns `Error(Nil)` if the key was imported with a compressed
/// point format since decompression is not supported. On JavaScript, compressed
/// points are automatically decompressed during import, so this always succeeds.
///
/// This is the inverse of `public_key_from_raw_point`.
@external(erlang, "kryptos_ffi", "ec_public_key_to_raw_point")
@external(javascript, "../kryptos_ffi.mjs", "ecPublicKeyToRawPoint")
pub fn public_key_to_raw_point(key: PublicKey) -> Result(BitArray, Nil)

/// Exports an EC public key to PEM format.
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

@external(erlang, "kryptos_ffi", "ec_export_public_key_pem")
@external(javascript, "../kryptos_ffi.mjs", "ecExportPublicKeyPem")
fn do_public_key_to_pem(key: PublicKey) -> Result(String, Nil)

/// Exports an EC public key to DER format.
///
/// The key is exported in SPKI format.
///
/// ## Parameters
/// - `key`: The public key to export
///
/// ## Returns
/// `Ok(der_data)` on success, `Error(Nil)` on failure.
@external(erlang, "kryptos_ffi", "ec_export_public_key_der")
@external(javascript, "../kryptos_ffi.mjs", "ecExportPublicKeyDer")
pub fn public_key_to_der(key: PublicKey) -> Result(BitArray, Nil)

/// Derives the public key from an EC private key.
///
/// ## Parameters
/// - `key`: The private key
///
/// ## Returns
/// The corresponding public key.
@external(erlang, "kryptos_ffi", "ec_public_key_from_private")
@external(javascript, "../kryptos_ffi.mjs", "ecPublicKeyFromPrivate")
pub fn public_key_from_private_key(key: PrivateKey) -> PublicKey
