//// Public key cryptography types.
////
//// This module provides opaque types for asymmetric cryptography keys.
//// Keys are parameterized by three capability markers that indicate which
//// operations they support:
////
//// - `signing`: Digital signature capability (e.g., `ECDSA`)
//// - `encrypting`: Encryption capability (e.g., `Nil` for EC keys)
//// - `key_agreement`: Key agreement capability (e.g., `ECDH`)
////
//// This phantom type system prevents misuse at compile time. For example,
//// an EC key with type `PrivateKey(ECDSA, Nil, ECDH)` can be used for both
//// signing and key agreement, but not for encryption.

/// An opaque private key for asymmetric cryptography.
///
/// Private keys should be kept secret. The type parameters indicate which
/// operations this key supports:
///
/// - `signing`: The signing algorithm (e.g., `ECDSA`) or `Nil` if unsupported
/// - `encrypting`: The encryption algorithm or `Nil` if unsupported
/// - `key_agreement`: The key agreement protocol (e.g., `ECDH`) or `Nil` if unsupported
pub type PrivateKey(signing, encrypting, key_agreement)

/// An opaque public key for asymmetric cryptography.
///
/// Public keys can be freely shared. The type parameters indicate which
/// operations this key supports:
///
/// - `signing`: The signing algorithm (e.g., `ECDSA`) or `Nil` if unsupported
/// - `encrypting`: The encryption algorithm or `Nil` if unsupported
/// - `key_agreement`: The key agreement protocol (e.g., `ECDH`) or `Nil` if unsupported
pub type PublicKey(signing, encrypting, key_agreement)

/// Marker type for ECDSA (Elliptic Curve Digital Signature Algorithm) capability.
///
/// Used as the `signing` type parameter to indicate a key supports ECDSA signatures.
pub type ECDSA

/// Marker type for ECDH (Elliptic Curve Diffie-Hellman) capability.
///
/// Used as the `key_agreement` type parameter to indicate a key supports ECDH
/// key agreement.
pub type ECDH

/// Marker type for XDH (X25519/X448 Diffie-Hellman) capability.
///
/// Used as the `key_agreement` type parameter to indicate a key supports XDH
/// key agreement using Montgomery curves (X25519 or X448).
pub type XDH
