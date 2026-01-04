/// Supported cryptographic hash algorithms.
pub type HashAlgorithm {
  /// BLAKE2b (512-bit output)
  Blake2b
  /// BLAKE2s (256-bit output)
  Blake2s
  /// MD5 (128-bit output), cryptographically broken - use only for legacy compatibility.
  Md5
  /// SHA-1 (160-bit output)
  Sha1
  /// SHA-256 (256-bit output)
  Sha256
  /// SHA-384 (384-bit output)
  Sha384
  /// SHA-512 (512-bit output)
  Sha512
  /// SHA-512/224 (224-bit output), truncated SHA-512.
  Sha512x224
  /// SHA-512/256 (256-bit output), truncated SHA-512.
  Sha512x256
  /// SHA3-224 (224-bit output)
  Sha3x224
  /// SHA3-256 (256-bit output)
  Sha3x256
  /// SHA3-384 (384-bit output)
  Sha3x384
  /// SHA3-512 (512-bit output)
  Sha3x512
}

/// Returns the canonical string name of a hash algorithm.
///
/// ## Arguments
/// - `algorithm`: The hash algorithm to get the name for
///
/// ## Returns
/// A string containing the algorithm's canonical name (e.g., "sha256", "blake2b").
pub fn algorithm_name(algorithm: HashAlgorithm) -> String {
  case algorithm {
    Blake2b -> "blake2b512"
    Blake2s -> "blake2s256"
    Md5 -> "md5"
    Sha1 -> "sha1"
    Sha256 -> "sha256"
    Sha384 -> "sha384"
    Sha512 -> "sha512"
    Sha512x224 -> "sha512-224"
    Sha512x256 -> "sha512-256"
    Sha3x224 -> "sha3-224"
    Sha3x256 -> "sha3-256"
    Sha3x384 -> "sha3-384"
    Sha3x512 -> "sha3-512"
  }
}

/// Represents an in-progress hash computation.
///
/// Use `new` to create a hasher, `update` to add data, and `final` to get the digest.
pub type Hasher

/// Creates a new hasher for incremental hashing.
///
/// Use this when you need to hash data in chunks, such as when streaming
/// or when the full input isn't available at once.
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to use
///
/// ## Returns
/// A new `Hasher` ready to accept input data.
@external(erlang, "kryptos_ffi", "hash_new")
@external(javascript, "../kryptos_ffi.mjs", "hashNew")
pub fn new(algorithm: HashAlgorithm) -> Hasher

/// Adds data to an in-progress hash computation.
///
/// Can be called multiple times to incrementally hash data.
///
/// ## Parameters
/// - `hasher`: The hasher to update
/// - `input`: The data to add to the hash
///
/// ## Returns
/// The updated hasher.
@external(erlang, "crypto", "hash_update")
@external(javascript, "../kryptos_ffi.mjs", "hashUpdate")
pub fn update(hasher: Hasher, data: BitArray) -> Hasher

/// Finalizes the hash computation and returns the digest.
///
/// After calling this function, the hasher should not be reused.
///
/// ## Parameters
/// - `hasher`: The hasher to finalize
///
/// ## Returns
/// A `BitArray` containing the computed hash digest.
@external(erlang, "crypto", "hash_final")
@external(javascript, "../kryptos_ffi.mjs", "hashFinal")
pub fn final(hasher: Hasher) -> BitArray

/// Computes the hash digest of input data in one call.
///
/// This is a convenience function that combines `new`, `update`, and `finish`.
/// Use this when you have all the data available at once.
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to use
/// - `input`: The data to hash
///
/// ## Returns
/// A `BitArray` containing the computed hash digest.
pub fn digest(algorithm: HashAlgorithm, data: BitArray) -> BitArray {
  new(algorithm)
  |> update(data)
  |> final()
}
