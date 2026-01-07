//// Authenticated Encryption with Associated Data (AEAD).
////
//// AEAD provides both confidentiality and integrity for data, with optional
//// authenticated additional data (AAD) that is integrity-protected but not
//// encrypted.
////
//// ## Example
////
//// ```gleam
//// import kryptos/aead
//// import kryptos/block
//// import kryptos/crypto
////
//// let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
//// let ctx = aead.gcm(cipher)
//// let nonce = crypto.random_bytes(aead.nonce_size(ctx))
//// let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext: <<"secret":utf8>>)
//// ```

import gleam/bit_array
import gleam/list
import kryptos/block.{type BlockCipher}

/// AEAD context with its configuration.
pub type AeadContext {
  /// AES-GCM with the specified cipher and nonce size.
  Gcm(cipher: BlockCipher, nonce_size: Int)
  /// AES-CCM with configurable nonce and tag sizes (RFC 3610).
  Ccm(cipher: BlockCipher, nonce_size: Int, tag_size: Int)
  /// ChaCha20-Poly1305 with a 256-bit key (RFC 8439).
  ChaCha20Poly1305(key: BitArray)
}

/// Creates an AES-GCM context with the given block cipher.
///
/// Uses standard parameters: 16-byte (128-bit) authentication tag and
/// 12-byte (96-bit) nonce.
///
/// **Note:** This library only supports the full 16-byte authentication tag.
/// Truncated tags (as permitted by NIST SP 800-38D) are not supported due to
/// their reduced security guarantees.
///
/// ## Parameters
/// - `cipher`: The AES block cipher (128, 192, or 256 bit)
///
/// ## Returns
/// An AES-GCM context ready for encryption or decryption.
pub fn gcm(cipher: BlockCipher) -> AeadContext {
  Gcm(cipher:, nonce_size: 12)
}

/// Creates an AES-CCM context with the given block cipher.
///
/// Uses standard parameters: 16-byte (128-bit) authentication tag and
/// 13-byte (104-bit) nonce, which allows messages up to 64KB.
///
/// ## Parameters
/// - `cipher`: The AES block cipher (128, 192, or 256 bit)
///
/// ## Returns
/// An AES-CCM context ready for encryption or decryption.
pub fn ccm(cipher: BlockCipher) -> AeadContext {
  Ccm(cipher:, nonce_size: 13, tag_size: 16)
}

/// Creates an AES-CCM context with custom nonce and tag sizes.
///
/// CCM allows flexible nonce and tag sizes per RFC 3610:
/// - Nonce size affects maximum message length (larger nonce = smaller max message)
/// - Tag size affects authentication strength (larger tag = stronger)
///
/// ## Parameters
/// - `cipher`: The AES block cipher (128, 192, or 256 bit)
/// - `nonce_size`: Nonce size in bytes (7-13)
/// - `tag_size`: Authentication tag size in bytes (4, 6, 8, 10, 12, 14, or 16)
///
/// ## Returns
/// - `Ok(AeadContext)` if the sizes are valid
/// - `Error(Nil)` if any size is out of range
pub fn ccm_with_sizes(
  cipher: BlockCipher,
  nonce_size nonce_size: Int,
  tag_size tag_size: Int,
) -> Result(AeadContext, Nil) {
  let valid_nonce = nonce_size >= 7 && nonce_size <= 13
  let valid_tag = list.contains([4, 6, 8, 10, 12, 14, 16], tag_size)
  case valid_nonce && valid_tag {
    True -> Ok(Ccm(cipher:, nonce_size:, tag_size:))
    False -> Error(Nil)
  }
}

/// Creates a ChaCha20-Poly1305 AEAD context with the given key.
///
/// Uses standard parameters per RFC 8439: 12-byte (96-bit) nonce and
/// 16-byte (128-bit) authentication tag.
///
/// ## Parameters
/// - `key`: A 32-byte (256-bit) key
///
/// ## Returns
/// - `Ok(AeadContext)` if the key is exactly 32 bytes
/// - `Error(Nil)` if the key size is incorrect
pub fn chacha20_poly1305(key: BitArray) -> Result(AeadContext, Nil) {
  case bit_array.byte_size(key) == 32 {
    True -> Ok(ChaCha20Poly1305(key))
    False -> Error(Nil)
  }
}

/// Returns the required nonce size in bytes for an AEAD context.
///
/// ## Parameters
/// - `ctx`: The AEAD context
///
/// ## Returns
/// The nonce size in bytes (12 for AES-GCM).
pub fn nonce_size(ctx: AeadContext) -> Int {
  case ctx {
    Gcm(nonce_size:, ..) -> nonce_size
    Ccm(nonce_size:, ..) -> nonce_size
    ChaCha20Poly1305(..) -> 12
  }
}

/// Returns the authentication tag size in bytes for an AEAD context.
///
/// ## Parameters
/// - `ctx`: The AEAD context
///
/// ## Returns
/// The tag size in bytes (16 for AES-GCM)
pub fn tag_size(ctx: AeadContext) -> Int {
  case ctx {
    Gcm(..) -> 16
    Ccm(tag_size:, ..) -> tag_size
    ChaCha20Poly1305(..) -> 16
  }
}

/// Encrypts and authenticates plaintext using AEAD.
///
/// ## Parameters
/// - `ctx`: The AEAD context to use
/// - `nonce`: A unique nonce (must be exactly `nonce_size` bytes).
///   Never reuse a nonce with the same key.
/// - `plaintext`: The data to encrypt
///
/// ## Returns
/// - `Ok(#(ciphertext, tag))` with the encrypted data and authentication tag
/// - `Error(Nil)` if the nonce size is incorrect
pub fn seal(
  ctx: AeadContext,
  nonce nonce: BitArray,
  plaintext plaintext: BitArray,
) -> Result(#(BitArray, BitArray), Nil) {
  seal_with_aad(ctx, nonce, plaintext, <<>>)
}

/// Encrypts and authenticates plaintext with additional authenticated data.
///
/// The AAD is authenticated but not encrypted. It can be used for headers,
/// metadata, or context that should be tamper-proof but remain readable.
///
/// ## Parameters
/// - `ctx`: The AEAD context to use
/// - `nonce`: A unique nonce (must be exactly `nonce_size` bytes and non-empty)
/// - `plaintext`: The data to encrypt
/// - `additional_data`: Data to authenticate but not encrypt
///
/// ## Returns
/// - `Ok(#(ciphertext, tag))` with the encrypted data and authentication tag
/// - `Error(Nil)` if the nonce size is incorrect or empty
pub fn seal_with_aad(
  ctx: AeadContext,
  nonce nonce: BitArray,
  plaintext plaintext: BitArray,
  additional_data aad: BitArray,
) -> Result(#(BitArray, BitArray), Nil) {
  let nonce_len = bit_array.byte_size(nonce)
  case nonce_len > 0 && nonce_len == nonce_size(ctx) {
    True -> do_seal(ctx, nonce, plaintext, aad)
    False -> Error(Nil)
  }
}

@external(erlang, "kryptos_ffi", "aead_seal")
@external(javascript, "../kryptos_ffi.mjs", "aeadSeal")
fn do_seal(
  ctx: AeadContext,
  nonce: BitArray,
  plaintext: BitArray,
  aad: BitArray,
) -> Result(#(BitArray, BitArray), Nil)

/// Decrypts and verifies AEAD-encrypted data.
///
/// ## Parameters
/// - `ctx`: The AEAD context to use
/// - `nonce`: The nonce used during encryption
/// - `tag`: The authentication tag from encryption
/// - `ciphertext`: The encrypted data
///
/// ## Returns
/// - `Ok(plaintext)` if authentication succeeds
/// - `Error(Nil)` if authentication fails or nonce size is incorrect
pub fn open(
  ctx: AeadContext,
  nonce nonce: BitArray,
  tag tag: BitArray,
  ciphertext ciphertext: BitArray,
) -> Result(BitArray, Nil) {
  open_with_aad(ctx, nonce, tag, ciphertext, <<>>)
}

/// Decrypts and verifies AEAD-encrypted data with additional authenticated data.
///
/// The AAD must match exactly what was provided during encryption.
///
/// ## Parameters
/// - `ctx`: The AEAD context to use
/// - `nonce`: The nonce used during encryption (must be non-empty)
/// - `tag`: The authentication tag from encryption
/// - `ciphertext`: The encrypted data
/// - `additional_data`: The same AAD used during encryption
///
/// ## Returns
/// - `Ok(plaintext)` if authentication succeeds
/// - `Error(Nil)` if authentication fails, AAD mismatch, or nonce size is incorrect/empty
pub fn open_with_aad(
  ctx: AeadContext,
  nonce nonce: BitArray,
  tag tag: BitArray,
  ciphertext ciphertext: BitArray,
  additional_data aad: BitArray,
) -> Result(BitArray, Nil) {
  let nonce_len = bit_array.byte_size(nonce)
  let tag_len = bit_array.byte_size(tag)
  case
    nonce_len > 0 && nonce_len == nonce_size(ctx) && tag_len == tag_size(ctx)
  {
    True -> do_open(ctx, nonce, tag, ciphertext, aad)
    False -> Error(Nil)
  }
}

@external(erlang, "kryptos_ffi", "aead_open")
@external(javascript, "../kryptos_ffi.mjs", "aeadOpen")
fn do_open(
  ctx: AeadContext,
  nonce: BitArray,
  tag: BitArray,
  ciphertext: BitArray,
  aad: BitArray,
) -> Result(BitArray, Nil)
