//// HKDF (HMAC-based Key Derivation Function) as defined in RFC 5869.
////
//// HKDF is a simple key derivation function based on HMAC. It takes input
//// key material (IKM), an optional salt, and optional context info to derive
//// cryptographically strong output key material.
////
//// ## Example
////
//// ```gleam
//// import kryptos/hkdf
//// import kryptos/hash
////
//// let input = <<0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
////               0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
////               0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b>>
//// let info = <<"application context":utf8>>
//// let length = 32
////
//// let assert Ok(key) = hkdf.compute(hash.Sha256, input:, salt: None, info:, length:)
//// ```

import gleam/bit_array
import gleam/option.{type Option}
import gleam/result
import kryptos/hash.{type HashAlgorithm}
import kryptos/hmac

/// Checks if a hash algorithm is supported for HKDF operations.
///
/// HKDF supports the same hash algorithms as HMAC.
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to check
///
/// ## Returns
/// `True` if the algorithm is supported, `False` otherwise.
pub fn supported_hash(algorithm: HashAlgorithm) -> Bool {
  hmac.supported_hash(algorithm)
}

/// Returns the output length in bytes for a hash algorithm.
fn hash_length(algorithm: HashAlgorithm) -> Int {
  case algorithm {
    hash.Md5 -> 16
    hash.Sha1 -> 20
    hash.Sha256 -> 32
    hash.Sha384 -> 48
    hash.Sha512 -> 64
    hash.Sha512x224 -> 28
    hash.Sha512x256 -> 32
    _ -> 0
  }
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
pub fn compute(
  algorithm: HashAlgorithm,
  input ikm: BitArray,
  salt salt: Option(BitArray),
  info info: BitArray,
  length length: Int,
) -> Result(BitArray, Nil) {
  let hash_len = hash_length(algorithm)
  let max_length = 255 * hash_len
  let salt_bytes = option.lazy_unwrap(salt, fn() { zero_bytes(hash_len) })

  case supported_hash(algorithm), length > 0, length <= max_length {
    True, True, True -> do_derive(algorithm, ikm, salt_bytes, info, length)
    _, _, _ -> Error(Nil)
  }
}

@external(javascript, "../kryptos_ffi.mjs", "hkdfDerive")
fn do_derive(
  algorithm: HashAlgorithm,
  ikm: BitArray,
  salt: BitArray,
  info: BitArray,
  length: Int,
) -> Result(BitArray, Nil) {
  // Step 1: Extract
  // PRK = HMAC-Hash(salt, IKM)
  use prk <- result.try(hmac.compute(algorithm, salt, ikm))

  // Step 2: Expand
  // T = T(1) || T(2) || ... || T(N)
  // T(0) = empty
  // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
  // OKM = first length octets of T
  expand(algorithm, prk, info, length, <<>>, 1)
}

fn expand(
  algorithm: HashAlgorithm,
  prk: BitArray,
  info: BitArray,
  remaining: Int,
  prev: BitArray,
  counter: Int,
) -> Result(BitArray, Nil) {
  case remaining <= 0 {
    True -> Ok(<<>>)
    False -> {
      // T(i) = HMAC-Hash(PRK, T(i-1) || info || counter)
      let input = bit_array.concat([prev, info, <<counter>>])
      use t <- result.try(hmac.compute(algorithm, prk, input))

      let t_len = bit_array.byte_size(t)
      case remaining <= t_len {
        True -> {
          // We have enough, take what we need
          let assert Ok(result) = bit_array.slice(t, 0, remaining)
          Ok(result)
        }
        False -> {
          // Need more, recurse
          use rest <- result.try(expand(
            algorithm,
            prk,
            info,
            remaining - t_len,
            t,
            counter + 1,
          ))
          Ok(bit_array.concat([t, rest]))
        }
      }
    }
  }
}

fn zero_bytes(length: Int) -> BitArray {
  zero_bytes_loop(length, <<>>)
}

fn zero_bytes_loop(remaining: Int, acc: BitArray) -> BitArray {
  case remaining <= 0 {
    True -> acc
    False -> zero_bytes_loop(remaining - 1, <<acc:bits, 0>>)
  }
}
