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
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to check
///
/// ## Returns
/// `True` if the algorithm is supported, `False` otherwise.
pub fn supported_hash(algorithm: HashAlgorithm) -> Bool {
  case algorithm {
    hash.Md5 -> True
    hash.Sha1 -> True
    hash.Sha256 -> True
    hash.Sha384 -> True
    hash.Sha512 -> True
    hash.Sha512x224 -> True
    hash.Sha512x256 -> True
    _ -> False
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
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to use for the HMAC
/// - `key`: The secret key for authentication
///
/// ## Returns
/// - `Ok(Hmac)` - A new HMAC ready to accept input data
/// - `Error(Nil)` - If the hash algorithm is not supported
pub fn new(algorithm: HashAlgorithm, key: BitArray) -> Result(Hmac, Nil) {
  case supported_hash(algorithm) {
    True -> Ok(do_new(algorithm, key))
    False -> Error(Nil)
  }
}

@external(erlang, "kryptos_ffi", "hmac_new")
@external(javascript, "../kryptos_ffi.mjs", "hmacNew")
fn do_new(algorithm: HashAlgorithm, key: BitArray) -> Hmac

/// Adds data to an in-progress HMAC computation.
///
/// Can be called multiple times to incrementally authenticate data.
///
/// ## Parameters
/// - `hmac`: The HMAC to update
/// - `data`: The data to add to the authentication
///
/// ## Returns
/// The updated HMAC.
@external(erlang, "crypto", "mac_update")
@external(javascript, "../kryptos_ffi.mjs", "hmacUpdate")
pub fn update(hmac: Hmac, data: BitArray) -> Hmac

/// Finalizes the HMAC computation and returns the authentication code.
///
/// After calling this function, the HMAC should not be reused.
///
/// ## Parameters
/// - `hmac`: The HMAC to finalize
///
/// ## Returns
/// A `BitArray` containing the computed message authentication code.
@external(erlang, "crypto", "mac_final")
@external(javascript, "../kryptos_ffi.mjs", "hmacFinal")
pub fn final(hmac: Hmac) -> BitArray

/// Verifies that a MAC matches the expected value using constant-time comparison.
///
/// This function computes the HMAC and compares it to the expected value in
/// constant time to prevent timing attacks.
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to use for the HMAC
/// - `key`: The secret key for authentication
/// - `data`: The data to authenticate
/// - `expected`: The expected MAC value to compare against
///
/// ## Returns
/// - `Ok(True)` - If the computed HMAC matches the expected value
/// - `Ok(False)` - If the computed HMAC does not match
/// - `Error(Nil)` - If the hash algorithm is not supported
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
