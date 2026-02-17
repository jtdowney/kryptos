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

import bitty as p
import gleam/bit_array
import gleam/bool
import gleam/result
import kryptos/ec.{type Curve, type PrivateKey, type PublicKey}
import kryptos/hash.{type HashAlgorithm}
import kryptos/internal/der
import kryptos/internal/utils

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
  private_key: PrivateKey,
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
  public_key: PublicKey,
  message: BitArray,
  signature signature: BitArray,
  hash hash: HashAlgorithm,
) -> Bool

/// Signs a message and returns the signature in R||S format (IEEE P1363).
///
/// In R||S format, the signature is the concatenation of r and s values,
/// each padded to the curve's coordinate size.
///
/// ## Parameters
/// - `private_key`: An elliptic curve private key
/// - `message`: The message to sign
/// - `hash`: The hash algorithm to use
///
/// ## Returns
/// An R||S format signature (2 * coordinate_size bytes).
///
/// ## Example
///
/// ```gleam
/// import kryptos/ec
/// import kryptos/ecdsa
/// import kryptos/hash
///
/// let #(private_key, _public_key) = ec.generate_key_pair(ec.P256)
/// let signature = ecdsa.sign_rs(private_key, <<"hello":utf8>>, hash.Sha256)
/// ```
pub fn sign_rs(
  private_key: PrivateKey,
  message: BitArray,
  hash: HashAlgorithm,
) -> BitArray {
  let der_sig = sign(private_key, message, hash)
  let curve = ec.curve(private_key)
  let assert Ok(rs_sig) = der_to_rs(der_sig, curve)
  rs_sig
}

/// Verifies an R||S format signature against a message.
///
/// The R||S format is the concatenation of r and s values, each padded
/// to the curve's coordinate size.
///
/// ## Parameters
/// - `public_key`: The public key corresponding to the signing key
/// - `message`: The original message that was signed
/// - `signature`: The R||S format signature to verify
/// - `hash`: The hash algorithm used during signing
///
/// ## Returns
/// `True` if the signature is valid, `False` otherwise.
///
/// ## Example
///
/// ```gleam
/// import kryptos/ec
/// import kryptos/ecdsa
/// import kryptos/hash
///
/// let #(private_key, public_key) = ec.generate_key_pair(ec.P256)
/// let message = <<"hello":utf8>>
/// let signature = ecdsa.sign_rs(private_key, message, hash.Sha256)
/// let valid = ecdsa.verify_rs(public_key, message, signature, hash.Sha256)
/// // valid == True
/// ```
pub fn verify_rs(
  public_key: PublicKey,
  message: BitArray,
  signature: BitArray,
  hash: HashAlgorithm,
) -> Bool {
  let curve = ec.public_key_curve(public_key)
  case rs_to_der(signature, curve) {
    Ok(der_sig) -> verify(public_key, message, der_sig, hash)
    Error(Nil) -> False
  }
}

/// Converts a DER-encoded ECDSA signature to R||S format.
///
/// R||S format concatenates the r and s integer values, each padded
/// to the curve's coordinate size with leading zeros.
///
/// ## Parameters
/// - `der`: A DER-encoded ECDSA signature
/// - `curve`: The elliptic curve used for the signature
///
/// ## Returns
/// `Ok(rs_signature)` on success, `Error(Nil)` if the DER is malformed
/// or contains trailing garbage.
///
/// ## Example
///
/// ```gleam
/// import kryptos/ec
/// import kryptos/ecdsa
/// import kryptos/hash
///
/// let #(private_key, _public_key) = ec.generate_key_pair(ec.P256)
/// let der_sig = ecdsa.sign(private_key, <<"hello":utf8>>, hash.Sha256)
/// let assert Ok(rs_sig) = ecdsa.der_to_rs(der_sig, ec.P256)
/// ```
pub fn der_to_rs(der_sig: BitArray, curve: Curve) -> Result(BitArray, Nil) {
  let coord_size = ec.coordinate_size(curve)

  let parser = der.sequence(p.pair(der.integer(), der.integer()))
  use #(r_bytes, s_bytes) <- result.try(
    p.run(parser, on: der_sig)
    |> result.replace_error(Nil),
  )

  let r = utils.strip_leading_zeros(r_bytes)
  let s = utils.strip_leading_zeros(s_bytes)
  let r_ok = bit_array.byte_size(r) <= coord_size
  let s_ok = bit_array.byte_size(s) <= coord_size
  use <- bool.guard(when: !r_ok || !s_ok, return: Error(Nil))

  Ok(
    bit_array.concat([
      utils.pad_left(r, coord_size),
      utils.pad_left(s, coord_size),
    ]),
  )
}

/// Converts an R||S format signature to DER encoding.
///
/// ## Parameters
/// - `rs`: An R||S format signature (2 * coordinate_size bytes)
/// - `curve`: The elliptic curve used for the signature
///
/// ## Returns
/// `Ok(der_signature)` on success, `Error(Nil)` if input length is invalid.
///
/// ## Example
///
/// ```gleam
/// import kryptos/ec
/// import kryptos/ecdsa
/// import kryptos/hash
///
/// let #(private_key, _public_key) = ec.generate_key_pair(ec.P256)
/// let rs_sig = ecdsa.sign_rs(private_key, <<"hello":utf8>>, hash.Sha256)
/// let assert Ok(der_sig) = ecdsa.rs_to_der(rs_sig, ec.P256)
/// ```
pub fn rs_to_der(rs: BitArray, curve: Curve) -> Result(BitArray, Nil) {
  let coord_size = ec.coordinate_size(curve)

  use <- bool.guard(
    when: bit_array.byte_size(rs) != coord_size * 2,
    return: Error(Nil),
  )

  let assert Ok(r) = bit_array.slice(rs, 0, coord_size)
  let assert Ok(s) = bit_array.slice(rs, coord_size, coord_size)

  use r_encoded <- result.try(der.encode_integer(r))
  use s_encoded <- result.try(der.encode_integer(s))
  der.encode_sequence(bit_array.concat([r_encoded, s_encoded]))
}
