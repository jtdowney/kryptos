//// Internal PBKDF2 (Password-Based Key Derivation Function 2) implementation.
////
//// Implements RFC 2898/8018 password-based key derivation. Used internally
//// by the crypto module for deriving keys from passwords with configurable iterations.

import kryptos/hash.{type HashAlgorithm}

@external(erlang, "kryptos_ffi", "pbkdf2_derive")
@external(javascript, "../../kryptos_ffi.mjs", "pbkdf2Derive")
pub fn do_derive(
  algorithm: HashAlgorithm,
  password: BitArray,
  salt: BitArray,
  iterations: Int,
  length: Int,
) -> Result(BitArray, Nil)
