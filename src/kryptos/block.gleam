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
//// let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
//// let assert Ok(ctx) = block.cbc(cipher, iv: crypto.random_bytes(16))
//// let assert Ok(ciphertext) = block.encrypt(ctx, <<"secret":utf8>>)
//// let assert Ok(decrypted) = block.decrypt(ctx, ciphertext)
//// // decrypted == <<"secret":utf8>>
//// ```

import gleam/bit_array

/// Supported AES key sizes.
pub type AesKeySize {
  /// AES with 128-bit key (16 bytes)
  Aes128
  /// AES with 192-bit key (24 bytes)
  Aes192
  /// AES with 256-bit key (32 bytes)
  Aes256
}

/// A block cipher with its associated key material.
pub opaque type BlockCipher {
  /// AES block cipher with the specified key size and key.
  Aes(key_size: AesKeySize, key: BitArray)
}

/// Context for block cipher modes of operation.
pub opaque type CipherContext {
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
    Aes(key_size:, ..) ->
      case key_size {
        Aes128 -> 16
        Aes192 -> 24
        Aes256 -> 32
      }
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
pub fn new_aes_128(key: BitArray) -> Result(BlockCipher, Nil) {
  case bit_array.byte_size(key) == 16 {
    True -> Ok(Aes(Aes128, key))
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
pub fn new_aes_192(key: BitArray) -> Result(BlockCipher, Nil) {
  case bit_array.byte_size(key) == 24 {
    True -> Ok(Aes(Aes192, key))
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
pub fn new_aes_256(key: BitArray) -> Result(BlockCipher, Nil) {
  case bit_array.byte_size(key) == 32 {
    True -> Ok(Aes(Aes256, key))
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

@external(erlang, "kryptos_ffi", "cipher_encrypt")
@external(javascript, "../kryptos_ffi.mjs", "cipherEncrypt")
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

@external(erlang, "kryptos_ffi", "cipher_decrypt")
@external(javascript, "../kryptos_ffi.mjs", "cipherDecrypt")
fn do_decrypt(ctx: CipherContext, ciphertext: BitArray) -> Result(BitArray, Nil)

@internal
pub fn cipher_name(ctx: CipherContext) -> String {
  case ctx {
    Ecb(cipher:) ->
      case cipher {
        Aes(key_size:, ..) ->
          case key_size {
            Aes128 -> "aes-128-ecb"
            Aes192 -> "aes-192-ecb"
            Aes256 -> "aes-256-ecb"
          }
      }
    Cbc(cipher:, ..) ->
      case cipher {
        Aes(key_size:, ..) ->
          case key_size {
            Aes128 -> "aes-128-cbc"
            Aes192 -> "aes-192-cbc"
            Aes256 -> "aes-256-cbc"
          }
      }
    Ctr(cipher:, ..) ->
      case cipher {
        Aes(key_size:, ..) ->
          case key_size {
            Aes128 -> "aes-128-ctr"
            Aes192 -> "aes-192-ctr"
            Aes256 -> "aes-256-ctr"
          }
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
