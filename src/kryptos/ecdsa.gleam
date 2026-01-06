//// Elliptic Curve Digital Signature Algorithm (ECDSA).
////
//// ECDSA provides digital signatures using elliptic curve cryptography,
//// offering strong security with smaller key sizes compared to RSA.
////
//// ## Example
////
//// ```gleam
//// import kryptos/ec
//// import kryptos/ecdsa
//// import kryptos/hash
////
//// let #(private_key, public_key) = ec.generate_key_pair(ec.P256)
//// let message = <<"hello world":utf8>>
//// let signature = ecdsa.sign(private_key, message, hash.Sha256)
//// let valid = ecdsa.verify(public_key, message, signature, hash.Sha256)
//// // valid == True
//// ```

import kryptos/hash.{type HashAlgorithm}
import kryptos/public_key.{type ECDSA, type PrivateKey, type PublicKey}

/// Signs a message using ECDSA with the specified hash algorithm.
///
/// The message is hashed internally using the provided algorithm before signing.
/// Signatures may be non-deterministic depending on platform (Erlang uses random
/// nonces, some platforms may use deterministic RFC 6979 nonces).
///
/// ## Parameters
/// - `private_key`: An elliptic curve private key from `ec.generate_key_pair`
/// - `message`: The message to sign (any length)
/// - `hash`: The hash algorithm to use (e.g., `Sha256`, `Sha384`, `Sha512`)
///
/// ## Returns
/// A DER-encoded ECDSA signature.
@external(erlang, "kryptos_ffi", "ecdsa_sign")
@external(javascript, "../kryptos_ffi.mjs", "ecdsaSign")
pub fn sign(
  private_key: PrivateKey(ECDSA, encrypting, key_agree),
  message: BitArray,
  hash: HashAlgorithm,
) -> BitArray

/// Verifies an ECDSA signature against a message.
///
/// The message is hashed internally using the provided algorithm before
/// verification. The same hash algorithm used during signing must be used
/// for verification.
///
/// ## Parameters
/// - `public_key`: The elliptic curve public key corresponding to the signing key
/// - `message`: The original message that was signed
/// - `signature`: The DER-encoded signature to verify
/// - `hash`: The hash algorithm used during signing
///
/// ## Returns
/// `True` if the signature is valid, `False` otherwise.
@external(erlang, "kryptos_ffi", "ecdsa_verify")
@external(javascript, "../kryptos_ffi.mjs", "ecdsaVerify")
pub fn verify(
  public_key: PublicKey(ECDSA, encrypting, key_agree),
  message: BitArray,
  signature signature: BitArray,
  hash hash: HashAlgorithm,
) -> Bool
