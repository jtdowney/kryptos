//// Block cipher implementations and modes of operation.
////
//// This module provides AES block ciphers and modes of operation (ECB, CBC, CTR).
////
//// **IMPORTANT SECURITY WARNING:**
//// ECB, CBC, and CTR modes do NOT provide authentication. An attacker can modify
//// ciphertext without detection. For most applications, you should use
//// authenticated encryption modes like AES-GCM or ChaCha20-Poly1305
//// from the `kryptos/aead` module instead.
////
//// Use these modes only when:
//// - Interoperating with legacy systems that require them
//// - Implementing higher-level protocols that provide their own authentication
//// - You fully understand the security implications
////
//// ## Modes Overview
////
//// - **ECB (Electronic Codebook):** Encrypts each block independently.
////   INSECURE for most uses - reveals patterns in data. Only use for
////   single-block encryption or specific legacy requirements.
//// - **CBC (Cipher Block Chaining):** Each block XORed with previous ciphertext.
////   Requires random IV per encryption. Uses PKCS7 padding automatically.
//// - **CTR (Counter):** Converts block cipher to stream cipher.
////   Nonce reuse is catastrophic - NEVER reuse a nonce with the same key.
////
//// ## Example
////
//// ```gleam
//// import kryptos/block
//// import kryptos/crypto
////
//// // CBC encryption with random IV
//// let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
//// let assert Ok(ctx) = block.cbc(cipher, iv: crypto.random_bytes(16))
//// let assert Ok(ciphertext) = block.encrypt(ctx, <<"secret":utf8>>)
//// let assert Ok(decrypted) = block.decrypt(ctx, ciphertext)
//// // decrypted == <<"secret":utf8>>
//// ```

import gleam/bit_array
import gleam/int
@target(erlang)
import gleam/list
@target(erlang)
import kryptos/crypto

@target(erlang)
const aes_key_wrap_iv = <<0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6>>

/// A block cipher with its associated key material.
pub type BlockCipher {
  /// AES block cipher with the specified key size and key.
  Aes(key_size: Int, key: BitArray)
}

/// Context for block cipher modes of operation.
///
/// **Note:** While the variants are public for pattern matching, direct
/// construction is not recommended. Use the provided constructor functions
/// which validate parameters:
///
/// - `ecb()` for ECB mode
/// - `cbc()` for CBC mode
/// - `ctr()` for CTR mode
pub type CipherContext {
  /// Electronic Codebook mode.
  Ecb(cipher: BlockCipher)

  /// Cipher Block Chaining mode with PKCS7 padding.
  Cbc(cipher: BlockCipher, iv: BitArray)

  /// Counter mode (streaming cipher).
  Ctr(cipher: BlockCipher, nonce: BitArray)
}

/// Returns the key size in bytes for a block cipher.
///
/// ## Parameters
/// - `cipher`: The block cipher to get the key size for
///
/// ## Returns
/// The key size in bytes (16, 24, or 32 for AES).
pub fn key_size(cipher: BlockCipher) -> Int {
  case cipher {
    Aes(key_size:, ..) -> key_size
  }
}

/// Returns the block size in bytes for a block cipher.
///
/// ## Parameters
/// - `cipher`: The block cipher to get the block size for
///
/// ## Returns
/// The block size in bytes (16 for AES).
pub fn block_size(cipher: BlockCipher) -> Int {
  case cipher {
    Aes(..) -> 16
  }
}

/// Creates a new AES-128 block cipher with the given key.
///
/// ## Parameters
/// - `key`: A 16-byte key for AES-128
///
/// ## Returns
/// - `Ok(BlockCipher)` if the key is exactly 16 bytes
/// - `Error(Nil)` if the key size is incorrect
pub fn aes_128(key: BitArray) -> Result(BlockCipher, Nil) {
  case bit_array.byte_size(key) == 16 {
    True -> Ok(Aes(128, key))
    False -> Error(Nil)
  }
}

/// Creates a new AES-192 block cipher with the given key.
///
/// ## Parameters
/// - `key`: A 24-byte key for AES-192
///
/// ## Returns
/// - `Ok(BlockCipher)` if the key is exactly 24 bytes
/// - `Error(Nil)` if the key size is incorrect
pub fn aes_192(key: BitArray) -> Result(BlockCipher, Nil) {
  case bit_array.byte_size(key) == 24 {
    True -> Ok(Aes(192, key))
    False -> Error(Nil)
  }
}

/// Creates a new AES-256 block cipher with the given key.
///
/// ## Parameters
/// - `key`: A 32-byte key for AES-256
///
/// ## Returns
/// - `Ok(BlockCipher)` if the key is exactly 32 bytes
/// - `Error(Nil)` if the key size is incorrect
pub fn aes_256(key: BitArray) -> Result(BlockCipher, Nil) {
  case bit_array.byte_size(key) == 32 {
    True -> Ok(Aes(256, key))
    False -> Error(Nil)
  }
}

/// Creates an ECB mode context for the given cipher.
///
/// **SECURITY WARNING:** ECB mode is insecure for most use cases.
/// Identical plaintext blocks produce identical ciphertext blocks,
/// revealing patterns in the data.
///
/// ## Parameters
/// - `cipher`: The block cipher to use
///
/// ## Returns
/// An ECB cipher context.
pub fn ecb(cipher: BlockCipher) -> CipherContext {
  Ecb(cipher)
}

/// Creates a CBC mode context with the given cipher and IV.
///
/// ## Parameters
/// - `cipher`: The block cipher to use
/// - `iv`: A 16-byte initialization vector (must be random and unique per encryption)
///
/// ## Returns
/// - `Ok(CipherContext)` if the IV is exactly 16 bytes
/// - `Error(Nil)` if the IV size is incorrect
pub fn cbc(cipher: BlockCipher, iv iv: BitArray) -> Result(CipherContext, Nil) {
  case bit_array.byte_size(iv) == 16 {
    True -> Ok(Cbc(cipher, iv))
    False -> Error(Nil)
  }
}

/// Creates a CTR mode context with the given cipher and nonce.
///
/// **SECURITY WARNING:** Nonce reuse is catastrophic in CTR mode.
/// NEVER reuse a nonce with the same key.
///
/// ## Parameters
/// - `cipher`: The block cipher to use
/// - `nonce`: A 16-byte nonce (must be unique per encryption with the same key)
///
/// ## Returns
/// - `Ok(CipherContext)` if the nonce is exactly 16 bytes
/// - `Error(Nil)` if the nonce size is incorrect
pub fn ctr(
  cipher: BlockCipher,
  nonce nonce: BitArray,
) -> Result(CipherContext, Nil) {
  case bit_array.byte_size(nonce) == 16 {
    True -> Ok(Ctr(cipher, nonce))
    False -> Error(Nil)
  }
}

/// Encrypts plaintext using the cipher mode.
///
/// ## Parameters
/// - `ctx`: The cipher context (includes IV/nonce for CBC/CTR)
/// - `plaintext`: The data to encrypt
///
/// ## Returns
/// - `Ok(ciphertext)` on success
/// - `Error(Nil)` if IV/nonce size is incorrect
///
/// ## Notes
/// - ECB: No IV required
/// - CBC: Automatically applies PKCS7 padding; ciphertext may be larger than plaintext
/// - CTR: No padding needed; ciphertext is same size as plaintext
pub fn encrypt(ctx: CipherContext, plaintext: BitArray) -> Result(BitArray, Nil) {
  case validate_iv(ctx) {
    True -> do_encrypt(ctx, plaintext)
    False -> Error(Nil)
  }
}

fn validate_iv(ctx: CipherContext) -> Bool {
  case ctx {
    Ecb(..) -> True
    Cbc(iv:, ..) -> bit_array.byte_size(iv) == 16
    Ctr(nonce:, ..) -> bit_array.byte_size(nonce) == 16
  }
}

@external(erlang, "kryptos_ffi", "block_cipher_encrypt")
@external(javascript, "../kryptos_ffi.mjs", "blockCipherEncrypt")
fn do_encrypt(ctx: CipherContext, plaintext: BitArray) -> Result(BitArray, Nil)

/// Decrypts ciphertext using the cipher mode.
///
/// ## Parameters
/// - `ctx`: The cipher context (includes IV/nonce for CBC/CTR)
/// - `ciphertext`: The encrypted data
///
/// ## Returns
/// - `Ok(plaintext)` on success
/// - `Error(Nil)` if IV/nonce size is incorrect, ciphertext size is invalid, or padding is invalid
///
/// ## Notes
/// - ECB: No IV required
/// - CBC: Automatically removes PKCS7 padding; returns error if padding is invalid
/// - CTR: No padding; ciphertext size equals plaintext size
pub fn decrypt(
  ctx: CipherContext,
  ciphertext: BitArray,
) -> Result(BitArray, Nil) {
  case validate_iv(ctx) {
    True -> do_decrypt(ctx, ciphertext)
    False -> Error(Nil)
  }
}

@external(erlang, "kryptos_ffi", "block_cipher_decrypt")
@external(javascript, "../kryptos_ffi.mjs", "blockCipherDecrypt")
fn do_decrypt(ctx: CipherContext, ciphertext: BitArray) -> Result(BitArray, Nil)

@internal
pub fn cipher_name(ctx: CipherContext) -> String {
  case ctx {
    Ecb(cipher:) ->
      case cipher {
        Aes(key_size:, ..) -> "aes-" <> int.to_string(key_size) <> "-ecb"
      }
    Cbc(cipher:, ..) ->
      case cipher {
        Aes(key_size:, ..) -> "aes-" <> int.to_string(key_size) <> "-cbc"
      }
    Ctr(cipher:, ..) ->
      case cipher {
        Aes(key_size:, ..) -> "aes-" <> int.to_string(key_size) <> "-ctr"
      }
  }
}

@internal
pub fn cipher_key(ctx: CipherContext) -> BitArray {
  case ctx {
    Ecb(cipher:) | Cbc(cipher:, ..) | Ctr(cipher:, ..) ->
      case cipher {
        Aes(key:, ..) -> key
      }
  }
}

@internal
pub fn cipher_iv(ctx: CipherContext) -> BitArray {
  case ctx {
    Ecb(..) -> <<>>
    Cbc(iv:, ..) -> iv
    Ctr(nonce:, ..) -> nonce
  }
}

/// Wraps key material using AES Key Wrap (RFC 3394).
///
/// Key wrapping is used to protect cryptographic keys when they need to be
/// transported or stored. Unlike general encryption, key wrapping:
/// - Does not require an IV (uses a default IV internally)
/// - Provides integrity protection
/// - Output is always 8 bytes larger than input
///
/// ## Parameters
/// - `cipher`: The AES block cipher used as the key-encryption key (KEK)
/// - `plaintext`: The key material to wrap (must be a multiple of 8 bytes, minimum 16 bytes)
///
/// ## Returns
/// - `Ok(ciphertext)` where ciphertext is plaintext.size + 8 bytes
/// - `Error(Nil)` if plaintext size is invalid
///
/// ## Example
///
/// ```gleam
/// import kryptos/block
/// import kryptos/crypto
///
/// let assert Ok(kek) = block.aes_256(crypto.random_bytes(32))
/// let key_to_wrap = crypto.random_bytes(32)
/// let assert Ok(wrapped) = block.wrap(kek, key_to_wrap)
/// ```
pub fn wrap(cipher: BlockCipher, plaintext: BitArray) -> Result(BitArray, Nil) {
  let size = bit_array.byte_size(plaintext)
  case size >= 16 && size % 8 == 0 {
    True -> do_wrap(cipher, plaintext)
    False -> Error(Nil)
  }
}

@target(javascript)
@external(javascript, "../kryptos_ffi.mjs", "blockCipherWrap")
fn do_wrap(cipher: BlockCipher, plaintext: BitArray) -> Result(BitArray, Nil)

@target(erlang)
fn do_wrap(cipher: BlockCipher, plaintext: BitArray) -> Result(BitArray, Nil) {
  let n = bit_array.byte_size(plaintext) / 8
  let r = split_into_blocks(plaintext, [])

  let #(a, r_final) = wrap_rounds(cipher, aes_key_wrap_iv, r, n, 0)
  Ok(bit_array.concat([a, ..r_final]))
}

@target(erlang)
fn wrap_rounds(
  cipher: BlockCipher,
  a: BitArray,
  r: List(BitArray),
  n: Int,
  j: Int,
) -> #(BitArray, List(BitArray)) {
  case j < 6 {
    False -> #(a, r)
    True -> {
      let #(a_new, r_new) = wrap_inner(cipher, a, r, n, j, 1, [])
      wrap_rounds(cipher, a_new, r_new, n, j + 1)
    }
  }
}

@target(erlang)
fn wrap_inner(
  cipher: BlockCipher,
  a: BitArray,
  r: List(BitArray),
  n: Int,
  j: Int,
  i: Int,
  acc: List(BitArray),
) -> #(BitArray, List(BitArray)) {
  case r {
    [] -> #(a, list.reverse(acc))
    [ri, ..rest] -> {
      let b = aes_encrypt_block(cipher, <<a:bits, ri:bits>>)
      let assert <<a_new:bytes-size(8), ri_new:bytes-size(8)>> = b
      let t = n * j + i
      let a_xored = xor_with_counter(a_new, t)
      wrap_inner(cipher, a_xored, rest, n, j, i + 1, [ri_new, ..acc])
    }
  }
}

/// Unwraps key material using AES Key Wrap (RFC 3394).
///
/// ## Parameters
/// - `cipher`: The AES block cipher used as the key-encryption key (KEK)
/// - `ciphertext`: The wrapped key material (must be a multiple of 8 bytes, minimum 24 bytes)
///
/// ## Returns
/// - `Ok(plaintext)` where plaintext is ciphertext.size - 8 bytes
/// - `Error(Nil)` if ciphertext size is invalid or integrity check fails
///
/// ## Example
///
/// ```gleam
/// import kryptos/block
///
/// let assert Ok(kek) = block.aes_256(kek_bytes)
/// let assert Ok(unwrapped) = block.unwrap(kek, wrapped_key)
/// ```
pub fn unwrap(
  cipher: BlockCipher,
  ciphertext: BitArray,
) -> Result(BitArray, Nil) {
  let size = bit_array.byte_size(ciphertext)
  case size >= 24 && size % 8 == 0 {
    True -> do_unwrap(cipher, ciphertext)
    False -> Error(Nil)
  }
}

@target(javascript)
@external(javascript, "../kryptos_ffi.mjs", "blockCipherUnwrap")
fn do_unwrap(cipher: BlockCipher, ciphertext: BitArray) -> Result(BitArray, Nil)

@target(erlang)
fn do_unwrap(cipher: BlockCipher, ciphertext: BitArray) -> Result(BitArray, Nil) {
  let assert <<a:bytes-size(8), rest:bytes>> = ciphertext
  let n = bit_array.byte_size(rest) / 8
  let r = split_into_blocks(rest, [])

  let #(a_final, r_final) = unwrap_rounds(cipher, a, r, n, 5)
  case crypto.constant_time_equal(a_final, aes_key_wrap_iv) {
    True -> Ok(bit_array.concat(r_final))
    False -> Error(Nil)
  }
}

@target(erlang)
fn unwrap_rounds(
  cipher: BlockCipher,
  a: BitArray,
  r: List(BitArray),
  n: Int,
  j: Int,
) -> #(BitArray, List(BitArray)) {
  case j >= 0 {
    False -> #(a, r)
    True -> {
      let #(a_new, r_new) =
        unwrap_inner(cipher, a, list.reverse(r), n, j, n, [])
      unwrap_rounds(cipher, a_new, r_new, n, j - 1)
    }
  }
}

@target(erlang)
fn unwrap_inner(
  cipher: BlockCipher,
  a: BitArray,
  r: List(BitArray),
  n: Int,
  j: Int,
  i: Int,
  acc: List(BitArray),
) -> #(BitArray, List(BitArray)) {
  case r {
    [] -> #(a, acc)
    [ri, ..rest] -> {
      let t = n * j + i
      let a_xored = xor_with_counter(a, t)
      let b = aes_decrypt_block(cipher, <<a_xored:bits, ri:bits>>)
      let assert <<a_new:bytes-size(8), ri_new:bytes-size(8)>> = b
      unwrap_inner(cipher, a_new, rest, n, j, i - 1, [ri_new, ..acc])
    }
  }
}

@target(erlang)
fn split_into_blocks(data: BitArray, acc: List(BitArray)) -> List(BitArray) {
  case data {
    <<block:bytes-size(8), rest:bytes>> ->
      split_into_blocks(rest, [block, ..acc])
    _ -> list.reverse(acc)
  }
}

@target(erlang)
@external(erlang, "kryptos_ffi", "aes_encrypt_block")
fn aes_encrypt_block(cipher: BlockCipher, block: BitArray) -> BitArray

@target(erlang)
@external(erlang, "kryptos_ffi", "aes_decrypt_block")
fn aes_decrypt_block(cipher: BlockCipher, block: BitArray) -> BitArray

@target(erlang)
fn xor_with_counter(a: BitArray, t: Int) -> BitArray {
  let assert <<a_int:unsigned-size(64)>> = a
  let result = int.bitwise_exclusive_or(a_int, t)
  <<result:size(64)>>
}
