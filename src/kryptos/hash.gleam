//// Cryptographic hash functions.
////
//// Hash functions take arbitrary input data and produce a fixed-size digest.
//// Use these for data integrity verification, fingerprinting, and as building
//// blocks for other cryptographic constructs like HMAC.
////
//// ## Example
////
//// ```gleam
//// import kryptos/hash
////
//// let assert Ok(h) = hash.new(hash.Sha256)
//// let digest = h |> hash.update(<<"hello":utf8>>) |> hash.final()
//// ```

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
  /// SHAKE128 extendable-output function (128-bit security).
  /// The output_length parameter specifies the desired digest length in bytes.
  /// Prefer using the `shake_128` smart constructor to validate the output length.
  Shake128(output_length: Int)
  /// SHAKE256 extendable-output function (256-bit security).
  /// The output_length parameter specifies the desired digest length in bytes.
  /// Prefer using the `shake_256` smart constructor to validate the output length.
  Shake256(output_length: Int)
}

/// Creates a SHAKE128 hash algorithm with the given output length in bytes.
///
/// ## Parameters
/// - `output_length`: The desired digest length in bytes (must be > 0)
///
/// ## Returns
/// `Ok(HashAlgorithm)` on success, `Error(Nil)` if the output length is invalid.
pub fn shake_128(output_length length: Int) -> Result(HashAlgorithm, Nil) {
  case length > 0 {
    True -> Ok(Shake128(length))
    False -> Error(Nil)
  }
}

/// Creates a SHAKE256 hash algorithm with the given output length in bytes.
///
/// ## Parameters
/// - `output_length`: The desired digest length in bytes (must be > 0)
///
/// ## Returns
/// `Ok(HashAlgorithm)` on success, `Error(Nil)` if the output length is invalid.
pub fn shake_256(output_length length: Int) -> Result(HashAlgorithm, Nil) {
  case length > 0 {
    True -> Ok(Shake256(length))
    False -> Error(Nil)
  }
}

@internal
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
    Shake128(_) -> "shake128"
    Shake256(_) -> "shake256"
  }
}

/// Returns the output size in bytes for a hash algorithm.
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to get the size for
///
/// ## Returns
/// The digest size in bytes.
pub fn byte_size(algorithm: HashAlgorithm) -> Int {
  case algorithm {
    Blake2b -> 64
    Blake2s -> 32
    Md5 -> 16
    Sha1 -> 20
    Sha256 -> 32
    Sha384 -> 48
    Sha512 -> 64
    Sha512x224 -> 28
    Sha512x256 -> 32
    Sha3x224 -> 28
    Sha3x256 -> 32
    Sha3x384 -> 48
    Sha3x512 -> 64
    Shake128(len) -> len
    Shake256(len) -> len
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
/// `Ok(Hasher)` on success, `Error(Nil)` if the hash algorithm is not
/// supported by the runtime.
pub fn new(algorithm: HashAlgorithm) -> Result(Hasher, Nil) {
  case algorithm {
    Shake128(len) | Shake256(len) if len <= 0 -> Error(Nil)
    _ -> do_new(algorithm)
  }
}

@external(erlang, "kryptos_ffi", "hash_new")
@external(javascript, "../kryptos_ffi.mjs", "hashNew")
fn do_new(algorithm: HashAlgorithm) -> Result(Hasher, Nil)

/// Adds data to an in-progress hash computation.
///
/// Can be called multiple times to incrementally hash data.
///
/// ## Parameters
/// - `hasher`: The hasher to update
/// - `data`: The data to add to the hash
///
/// ## Returns
/// The updated hasher.
@external(erlang, "kryptos_ffi", "hash_update")
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
@external(erlang, "kryptos_ffi", "hash_final")
@external(javascript, "../kryptos_ffi.mjs", "hashFinal")
pub fn final(hasher: Hasher) -> BitArray

/// Checks if a hash algorithm is supported by the current runtime.
///
/// Some algorithms may not be available depending on the platform or
/// OpenSSL/crypto library version.
///
/// ## Parameters
/// - `algorithm`: The hash algorithm to check
///
/// ## Returns
/// `True` if the algorithm is supported, `False` otherwise.
pub fn is_supported(algorithm: HashAlgorithm) -> Bool {
  case new(algorithm) {
    Ok(_) -> True
    Error(_) -> False
  }
}
