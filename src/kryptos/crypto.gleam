//// Convenience wrappers for hashing, key derivation, random bytes, and constant-time comparison.
////
//// - One-shot hashing via `hash()` and HMAC via `hmac()`
//// - Key derivation: HKDF (RFC 5869), PBKDF2 (RFC 8018), Concat KDF (NIST SP 800-56A)
//// - Random bytes via `random_bytes()` and UUID v4 via `random_uuid()`
//// - Constant-time comparison via `constant_time_equal()`
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
import gleam/bytes_tree
import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string
import kryptos/hash.{type HashAlgorithm}
import kryptos/hmac
import kryptos/internal/concat_kdf
import kryptos/internal/hkdf
import kryptos/internal/pbkdf2
import kryptos/internal/subtle

/// Computes the hash digest of input data in one call.
///
/// ## Example
///
/// ```gleam
/// import kryptos/crypto
/// import kryptos/hash
///
/// let assert Ok(digest) = crypto.hash(hash.Sha256, <<"hello":utf8>>)
/// ```
pub fn hash(algorithm: HashAlgorithm, data: BitArray) -> Result(BitArray, Nil) {
  use hasher <- result.try(hash.new(algorithm))
  hasher
  |> hash.update(data)
  |> hash.final()
  |> Ok
}

/// Computes the HMAC of input data in one call.
///
/// ## Example
///
/// ```gleam
/// import kryptos/crypto
/// import kryptos/hash
///
/// let assert Ok(mac) = crypto.hmac(hash.Sha256, key: <<"secret":utf8>>, data: <<"hello":utf8>>)
/// ```
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
/// strong key material from input key material. The algorithm must be
/// HMAC-compatible. Maximum output length is 255 * hash_length bytes.
/// A `None` salt uses hash-length zeros per RFC 5869.
///
/// ## Example
///
/// ```gleam
/// import gleam/option
/// import kryptos/crypto
/// import kryptos/hash
///
/// let ikm = crypto.random_bytes(32)
/// let salt = option.Some(crypto.random_bytes(16))
/// let assert Ok(derived) =
///   crypto.hkdf(hash.Sha256, input: ikm, salt:, info: <<"app":utf8>>, length: 32)
/// ```
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

/// Derives key material using Concat KDF (NIST SP 800-56A). Also called the
/// single-step or one-step key derivation function.
///
/// Concat KDF uses a hash function to derive key material from a shared secret
/// and context-specific information. Supports SHA-1, SHA-2, and SHA-3 family
/// algorithms. Maximum output length is 255 * hash_length bytes.
///
/// ## Example
///
/// ```gleam
/// import kryptos/crypto
/// import kryptos/hash
///
/// let secret = crypto.random_bytes(32)
/// let assert Ok(derived) =
///   crypto.concat_kdf(hash.Sha256, secret:, info: <<"context":utf8>>, length: 32)
/// ```
pub fn concat_kdf(
  algorithm: HashAlgorithm,
  secret secret: BitArray,
  info info: BitArray,
  length length: Int,
) -> Result(BitArray, Nil) {
  let max_length = 255 * hash.byte_size(algorithm)

  case concat_kdf_supported_hash(algorithm), length > 0, length <= max_length {
    True, True, True ->
      concat_kdf.derive_loop(
        algorithm,
        secret,
        info,
        length,
        1,
        bytes_tree.new(),
      )
    _, _, _ -> Error(Nil)
  }
}

fn concat_kdf_supported_hash(algorithm: HashAlgorithm) -> Bool {
  case algorithm {
    hash.Sha1 -> True
    hash.Sha256 -> True
    hash.Sha384 -> True
    hash.Sha512 -> True
    hash.Sha512x224 -> True
    hash.Sha512x256 -> True
    hash.Sha3x224 -> True
    hash.Sha3x256 -> True
    hash.Sha3x384 -> True
    hash.Sha3x512 -> True
    hash.Blake2b -> False
    hash.Blake2s -> False
    hash.Md5 -> False
    hash.Shake128(_) -> False
    hash.Shake256(_) -> False
  }
}

/// Derives key material from a password using PBKDF2 (RFC 8018).
///
/// PBKDF2 applies a pseudorandom function (HMAC) to derive keys from passwords.
/// It is designed to be computationally expensive to resist brute-force attacks.
///
/// **Note:** For password hashing in production applications, consider using
/// [Argus](https://github.com/Pevensie/argus) which provides Argon2 an
/// algorithm specifically designed for password storage. PBKDF2 is primarily
/// useful for interoperability with systems that require it.
///
/// The algorithm must be HMAC-compatible. SHA-256 or stronger is recommended;
/// MD5 and SHA-1 are weak for password hashing.
///
/// ## Example
///
/// ```gleam
/// import kryptos/crypto
/// import kryptos/hash
///
/// let salt = crypto.random_bytes(16)
/// let assert Ok(derived) =
///   crypto.pbkdf2(
///     hash.Sha256,
///     password: <<"hunter2":utf8>>,
///     salt:,
///     iterations: 100_000,
///     length: 32,
///   )
/// ```
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
/// A negative length returns an empty `BitArray`.
@external(erlang, "kryptos_ffi", "random_bytes")
@external(javascript, "../kryptos_ffi.mjs", "randomBytes")
pub fn random_bytes(length: Int) -> BitArray

/// Generates a cryptographically secure random UUID v4.
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
/// API tokens, or any other security-sensitive data. The comparison takes
/// the same amount of time regardless of where the arrays differ, preventing
/// timing attacks.
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
