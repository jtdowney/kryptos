//// The crypto module provides cryptographic primitives.
////
//// ## Example
////
//// ```gleam
//// import kryptos/crypto
////
//// // Generate 32 random bytes (suitable for a 256-bit key)
//// let key = crypto.random_bytes(32)
//// ```

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string
import kryptos/hash.{type HashAlgorithm}
import kryptos/hmac
import kryptos/internal/hkdf
import kryptos/internal/pbkdf2
import kryptos/internal/subtle

/// Computes the hash digest of input data in one call.
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to use
/// - `data`: The data to hash
///
/// ## Returns
/// A `BitArray` containing the computed hash digest.
pub fn hash(algorithm: HashAlgorithm, data: BitArray) -> BitArray {
  hash.new(algorithm)
  |> hash.update(data)
  |> hash.final()
}

/// Computes the HMAC of input data in one call.
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to use for the HMAC
/// - `key`: The secret key for authentication
/// - `data`: The data to authenticate
///
/// ## Returns
/// - `Ok(BitArray)` - The computed message authentication code
/// - `Error(Nil)` - If the hash algorithm is not supported
pub fn hmac(
  algorithm: HashAlgorithm,
  key key: BitArray,
  data data: BitArray,
) -> Result(BitArray, Nil) {
  use hmac <- result.try(hmac.new(algorithm, key))

  hmac
  |> hmac.update(data)
  |> hmac.final()
  |> Ok
}

/// Derives key material using HKDF (RFC 5869).
///
/// HKDF combines an extract-then-expand approach to derive cryptographically
/// strong key material from input key material.
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to use (must be HMAC-compatible)
/// - `input`: Input key material (IKM) - the source keying material
/// - `salt`: Optional salt value (None uses hash-length zeros per RFC 5869)
/// - `info`: Context and application specific information
/// - `length`: Desired output length in bytes (max: 255 * hash_length)
///
/// ## Returns
/// - `Ok(BitArray)` - The derived key material of the requested length
/// - `Error(Nil)` - If the algorithm is not supported or length exceeds maximum
pub fn hkdf(
  algorithm: HashAlgorithm,
  input ikm: BitArray,
  salt salt: Option(BitArray),
  info info: BitArray,
  length length: Int,
) -> Result(BitArray, Nil) {
  let hash_len = hash.byte_size(algorithm)
  let max_length = 255 * hash_len
  let salt_bytes =
    option.lazy_unwrap(salt, fn() {
      list.repeat(<<0>>, hash_len) |> bit_array.concat
    })

  case hmac.supported_hash(algorithm), length > 0, length <= max_length {
    True, True, True -> hkdf.do_derive(algorithm, ikm, salt_bytes, info, length)
    _, _, _ -> Error(Nil)
  }
}

/// Derives key material from a password using PBKDF2 (RFC 8018).
///
/// PBKDF2 applies a pseudorandom function (HMAC) to derive keys from passwords.
/// It is designed to be computationally expensive to resist brute-force attacks.
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to use for HMAC (must be HMAC-compatible).
///   SHA-256 or stronger is recommended; MD5 and SHA-1 are weak for password hashing.
/// - `password`: The password to derive the key from
/// - `salt`: A random salt value (should be unique per password)
/// - `iterations`: Number of iterations (higher = slower but more secure)
/// - `length`: Desired output length in bytes
///
/// ## Returns
/// - `Ok(BitArray)` - The derived key material of the requested length
/// - `Error(Nil)` - If the algorithm is not supported, iterations <= 0, or length <= 0
pub fn pbkdf2(
  algorithm: HashAlgorithm,
  password password: BitArray,
  salt salt: BitArray,
  iterations iterations: Int,
  length length: Int,
) -> Result(BitArray, Nil) {
  case hmac.supported_hash(algorithm), iterations > 0, length > 0 {
    True, True, True ->
      pbkdf2.do_derive(algorithm, password, salt, iterations, length)
    _, _, _ -> Error(Nil)
  }
}

/// Generates cryptographically secure random bytes using the platform's
/// cryptographically secure random number generator.
///
/// ## Parameters
/// - `length`: The number of random bytes to generate. If negative, returns
///   an empty `BitArray`.
///
/// ## Returns
/// A `BitArray` containing the generated random bytes.
@external(erlang, "kryptos_ffi", "random_bytes")
@external(javascript, "../kryptos_ffi.mjs", "randomBytes")
pub fn random_bytes(length: Int) -> BitArray

/// Generates a cryptographically secure random UUID v4.
///
/// ## Returns
/// A `String` containing a UUID v4.
@external(javascript, "../kryptos_ffi.mjs", "randomUuid")
pub fn random_uuid() -> String {
  let assert <<a:32, b:16, c_raw:16, d_raw:16, e:48>> = random_bytes(16)
  let c = int.bitwise_or(int.bitwise_and(c_raw, 0x0FFF), 0x4000)
  let d = int.bitwise_or(int.bitwise_and(d_raw, 0x3FFF), 0x8000)

  let uuid =
    string.pad_start(int.to_base16(a), 8, "0")
    <> "-"
    <> string.pad_start(int.to_base16(b), 4, "0")
    <> "-"
    <> string.pad_start(int.to_base16(c), 4, "0")
    <> "-"
    <> string.pad_start(int.to_base16(d), 4, "0")
    <> "-"
    <> string.pad_start(int.to_base16(e), 12, "0")

  string.lowercase(uuid)
}

/// Compares two `BitArray` in constant time.
///
/// Use this function when comparing secrets like MACs, password hashes,
/// API tokens, or any other security-sensitive data.
///
/// ## Parameters
/// - `a`: The first bit array to compare
/// - `b`: The second bit array to compare
///
/// ## Returns
/// `True` if `a` and `b` are equal, `False` otherwise. The comparison
/// takes the same amount of time regardless of where the arrays differ,
/// preventing timing attacks.
///
/// ## Example
///
/// ```gleam
/// let expected_mac = compute_mac(message, key)
/// let received_mac = get_mac_from_request()
///
/// // Safe: constant-time comparison prevents timing attacks
/// case crypto.constant_time_equal(expected_mac, received_mac) {
///   True -> accept_message()
///   False -> reject_message()
/// }
/// ```
pub const constant_time_equal = subtle.constant_time_equal
