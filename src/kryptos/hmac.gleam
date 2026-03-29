//// Hash-based Message Authentication Code (HMAC).
////
//// HMAC provides message authentication using a cryptographic hash function
//// combined with a secret key. Use it to verify both data integrity and
//// authenticity.
////
//// ## Example
////
//// ```gleam
//// import kryptos/hmac
//// import kryptos/hash
////
//// let assert Ok(h) = hmac.new(hash.Sha256, <<"secret key":utf8>>)
//// let mac = h |> hmac.update(<<"hello":utf8>>) |> hmac.final()
//// ```

import gleam/result
import kryptos/hash.{type HashAlgorithm}
import kryptos/internal/subtle

/// Checks if a hash algorithm is supported for HMAC operations.
pub fn supported_hash(algorithm: HashAlgorithm) -> Bool {
  case algorithm {
    hash.Md5 -> True
    hash.Sha1 -> True
    hash.Sha256 -> True
    hash.Sha384 -> True
    hash.Sha512 -> True
    hash.Sha512x224 -> True
    hash.Sha512x256 -> True
    hash.Blake2b -> False
    hash.Blake2s -> False
    hash.Sha3x224 -> False
    hash.Sha3x256 -> False
    hash.Sha3x384 -> False
    hash.Sha3x512 -> False
    hash.Shake128(_) -> False
    hash.Shake256(_) -> False
  }
}

/// Represents an in-progress HMAC computation.
///
/// Use `new` to create an HMAC, `update` to add data, and `final` to get the MAC.
pub type Hmac

/// Creates a new HMAC for incremental authentication.
///
/// Use this when you need to authenticate data in chunks, such as when streaming
/// or when the full input isn't available at once.
pub fn new(algorithm: HashAlgorithm, key: BitArray) -> Result(Hmac, Nil) {
  case supported_hash(algorithm) {
    True -> do_new(algorithm, key)
    False -> Error(Nil)
  }
}

@external(erlang, "kryptos_ffi", "hmac_new")
@external(javascript, "../kryptos_ffi.mjs", "hmacNew")
fn do_new(algorithm: HashAlgorithm, key: BitArray) -> Result(Hmac, Nil)

/// Adds data to an in-progress HMAC computation.
///
/// Can be called multiple times to incrementally authenticate data.
@external(erlang, "crypto", "mac_update")
@external(javascript, "../kryptos_ffi.mjs", "hmacUpdate")
pub fn update(hmac: Hmac, data: BitArray) -> Hmac

/// Finalizes the HMAC computation and returns the authentication code.
///
/// After calling this function, the HMAC should not be reused.
@external(erlang, "crypto", "mac_final")
@external(javascript, "../kryptos_ffi.mjs", "hmacFinal")
pub fn final(hmac: Hmac) -> BitArray

/// Verifies that a MAC matches the expected value using constant-time comparison.
///
/// Computes the HMAC and compares it to the expected value in constant time
/// to prevent timing attacks.
pub fn verify(
  algorithm: HashAlgorithm,
  key key: BitArray,
  data data: BitArray,
  expected expected: BitArray,
) -> Result(Bool, Nil) {
  use hmac_state <- result.try(new(algorithm, key))

  let actual =
    hmac_state
    |> update(data)
    |> final()

  Ok(subtle.constant_time_equal(actual, expected))
}
