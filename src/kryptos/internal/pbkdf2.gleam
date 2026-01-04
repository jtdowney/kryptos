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
