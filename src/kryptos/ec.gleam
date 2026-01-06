//// Elliptic Curve Cryptography key generation.
////
//// This module provides key pair generation for elliptic curve cryptography,
//// supporting standard NIST curves and secp256k1.
////
//// ## Example
////
//// ```gleam
//// import kryptos/ec
////
//// let #(private_key, public_key) = ec.generate_key_pair(ec.P256)
//// ```

import kryptos/public_key.{type EllipticCurve, type PrivateKey, type PublicKey}

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
pub fn generate_key_pair(
  curve: Curve,
) -> #(PrivateKey(EllipticCurve), PublicKey(EllipticCurve))
