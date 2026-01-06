//// Public key cryptography types.
////
//// This module provides opaque types for asymmetric cryptography keys.
//// Keys are parameterized by their algorithm type to prevent misuse
//// (e.g., using an RSA key where an EC key is expected).

/// An opaque private key for asymmetric cryptography.
///
/// Private keys should be kept secret and are used for signing operations.
/// The type parameter indicates the key algorithm (e.g., `EllipticCurve`).
pub type PrivateKey(key_type)

/// An opaque public key for asymmetric cryptography.
///
/// Public keys can be freely shared and are used for signature verification.
/// The type parameter indicates the key algorithm (e.g., `EllipticCurve`).
pub type PublicKey(key_type)

/// Marker type for elliptic curve keys.
///
/// Used as a type parameter for `PrivateKey` and `PublicKey` to indicate
/// the key is for elliptic curve cryptography (ECDSA, ECDH).
pub type EllipticCurve
