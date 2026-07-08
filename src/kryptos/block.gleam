//// Block cipher implementations and modes of operation.
////
//// AES block ciphers and modes of operation (ECB, CBC, CTR).
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
//// - ECB (Electronic Codebook): Encrypts each block independently.
////   INSECURE for most uses - reveals patterns in data. Only use for
////   single-block encryption or specific legacy requirements.
//// - CBC (Cipher Block Chaining): Each block XORed with previous ciphertext.
////   Requires random IV per encryption. Uses PKCS7 padding automatically.
//// - CTR (Counter): Converts block cipher to stream cipher.
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

/// A block cipher with its associated key material.
pub opaque type BlockCipher {
  Aes(key_size: Int, key: BitArray)
}

/// Context for block cipher modes of operation.
///
/// Use the provided constructor functions to create contexts:
///
/// - `ecb()` for ECB mode
/// - `cbc()` for CBC mode
/// - `ctr()` for CTR mode
pub opaque type CipherContext {
  /// Electronic Codebook mode.
  Ecb(cipher: BlockCipher)

  /// Cipher Block Chaining mode with PKCS7 padding.
  Cbc(cipher: BlockCipher, iv: BitArray)

  /// Counter mode (streaming cipher).
  Ctr(cipher: BlockCipher, nonce: BitArray)
}

/// Returns the key size in bits for a block cipher.
pub fn key_size(cipher: BlockCipher) -> Int {
  case cipher {
    Aes(key_size:, ..) -> key_size
  }
}

/// Returns the block size in bytes for a block cipher.
pub fn block_size(cipher: BlockCipher) -> Int {
  case cipher {
    Aes(..) -> 16
  }
}

/// Creates a new AES-128 block cipher with the given key.
///
/// The key must be exactly 16 bytes.
pub fn aes_128(key: BitArray) -> Result(BlockCipher, Nil) {
  case bit_array.byte_size(key) == 16 {
    True -> Ok(Aes(128, key))
    False -> Error(Nil)
  }
}

/// Creates a new AES-192 block cipher with the given key.
///
/// The key must be exactly 24 bytes.
pub fn aes_192(key: BitArray) -> Result(BlockCipher, Nil) {
  case bit_array.byte_size(key) == 24 {
    True -> Ok(Aes(192, key))
    False -> Error(Nil)
  }
}

/// Creates a new AES-256 block cipher with the given key.
///
/// The key must be exactly 32 bytes.
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
pub fn ecb(cipher: BlockCipher) -> CipherContext {
  Ecb(cipher)
}

/// Creates a CBC mode context with the given cipher and IV.
///
/// The IV must be exactly 16 bytes, random, and unique per encryption.
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
/// The nonce must be exactly 16 bytes.
///
/// ## Example
///
/// ```gleam
/// import kryptos/block
/// import kryptos/crypto
///
/// let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
/// let assert Ok(ctx) = block.ctr(cipher, nonce: crypto.random_bytes(16))
/// let assert Ok(ciphertext) = block.encrypt(ctx, <<"secret":utf8>>)
/// let assert Ok(plaintext) = block.decrypt(ctx, ciphertext)
/// ```
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
/// ## Notes
/// - ECB: No IV required
/// - CBC: Automatically applies PKCS7 padding; ciphertext may be larger than plaintext
/// - CTR: No padding needed; ciphertext is same size as plaintext
pub fn encrypt(
  ctx: CipherContext,
  plaintext: BitArray,
) -> Result(BitArray, Nil) {
  do_encrypt(ctx, plaintext)
}

@external(erlang, "kryptos_ffi", "block_cipher_encrypt")
@external(javascript, "../kryptos_ffi.mjs", "blockCipherEncrypt")
fn do_encrypt(ctx: CipherContext, plaintext: BitArray) -> Result(BitArray, Nil)

/// Decrypts ciphertext using the cipher mode.
pub fn decrypt(
  ctx: CipherContext,
  ciphertext: BitArray,
) -> Result(BitArray, Nil) {
  do_decrypt(ctx, ciphertext)
}

@external(erlang, "kryptos_ffi", "block_cipher_decrypt")
@external(javascript, "../kryptos_ffi.mjs", "blockCipherDecrypt")
fn do_decrypt(ctx: CipherContext, ciphertext: BitArray) -> Result(BitArray, Nil)

@internal
pub fn cipher_name(ctx: CipherContext) -> String {
  case ctx {
    Ecb(cipher: Aes(key_size:, ..)) ->
      "aes-" <> int.to_string(key_size) <> "-ecb"
    Cbc(cipher: Aes(key_size:, ..), ..) ->
      "aes-" <> int.to_string(key_size) <> "-cbc"
    Ctr(cipher: Aes(key_size:, ..), ..) ->
      "aes-" <> int.to_string(key_size) <> "-ctr"
  }
}

@internal
pub fn cipher_key(ctx: CipherContext) -> BitArray {
  case ctx {
    Ecb(cipher: Aes(key:, ..))
    | Cbc(cipher: Aes(key:, ..), ..)
    | Ctr(cipher: Aes(key:, ..), ..) -> key
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
/// The plaintext must be a multiple of 8 bytes, minimum 16 bytes.
pub fn wrap(cipher: BlockCipher, plaintext: BitArray) -> Result(BitArray, Nil) {
  let size = bit_array.byte_size(plaintext)
  case size >= 16 && size % 8 == 0 {
    True -> do_wrap(cipher, plaintext)
    False -> Error(Nil)
  }
}

@external(erlang, "kryptos_ffi", "block_cipher_wrap")
@external(javascript, "../kryptos_ffi.mjs", "blockCipherWrap")
fn do_wrap(cipher: BlockCipher, plaintext: BitArray) -> Result(BitArray, Nil)

/// Unwraps key material using AES Key Wrap (RFC 3394).
///
/// The ciphertext must be a multiple of 8 bytes, minimum 24 bytes.
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

@external(erlang, "kryptos_ffi", "block_cipher_unwrap")
@external(javascript, "../kryptos_ffi.mjs", "blockCipherUnwrap")
fn do_unwrap(cipher: BlockCipher, ciphertext: BitArray) -> Result(BitArray, Nil)

@internal
pub fn aes_key(cipher: BlockCipher) -> BitArray {
  case cipher {
    Aes(key:, ..) -> key
  }
}

@internal
pub fn is_ctr(ctx: CipherContext) -> Bool {
  case ctx {
    Ctr(..) -> True
    Ecb(..) | Cbc(..) -> False
  }
}
