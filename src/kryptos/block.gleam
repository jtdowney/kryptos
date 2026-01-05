//// Block cipher implementations for use with authenticated encryption modes.
////
//// This module provides AES block ciphers that can be used with AEAD modes
//// like GCM. The block cipher holds the key material and key size.

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
pub type BlockCipher {
  /// AES block cipher with the specified key size and key.
  Aes(key_size: AesKeySize, key: BitArray)
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
