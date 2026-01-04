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

/// Generates cryptographically secure random bytes using the platform's
/// cryptographically secure random number generator.
///
/// ## Arguments
///
/// - `length`: The number of random bytes to generate. If negative, returns
///   an empty `BitArray`.
///
/// ## Returns
/// A `BitArray` containing the generated random bytes.
@external(erlang, "kryptos_ffi", "random_bytes")
@external(javascript, "../kryptos_ffi.mjs", "randomBytes")
pub fn random_bytes(length: Int) -> BitArray

/// Compares two `BitArray` in constant time.
///
/// Use this function when comparing secrets like MACs, password hashes,
/// API tokens, or any other security-sensitive data.
///
/// ## Arguments
///
/// - `a`: The first bit array to compare.
/// - `b`: The second bit array to compare.
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
@external(erlang, "kryptos_ffi", "constant_time_equal")
@external(javascript, "../kryptos_ffi.mjs", "constantTimeEqual")
pub fn constant_time_equal(a: BitArray, b: BitArray) -> Bool
