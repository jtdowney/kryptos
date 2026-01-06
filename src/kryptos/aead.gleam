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
//// let mode = aead.gcm(cipher)
//// let nonce = crypto.random_bytes(aead.nonce_size(mode))
//// let assert Ok(#(ciphertext, tag)) = aead.seal(mode, nonce:, plaintext: <<"secret":utf8>>)
//// ```

import gleam/bit_array
import kryptos/block.{type BlockCipher, Aes}

/// AEAD mode with its configuration.
pub type AeadMode {
  /// AES-GCM with the specified cipher and nonce size.
  Gcm(cipher: BlockCipher, nonce_size: Int)
  /// ChaCha20-Poly1305 with a 256-bit key (RFC 8439).
  ChaCha20Poly1305(key: BitArray)
}

/// Creates an AES-GCM mode with the given block cipher.
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
/// An AES-GCM mode ready for encryption or decryption.
pub fn gcm(cipher: BlockCipher) -> AeadMode {
  Gcm(cipher:, nonce_size: 12)
}

/// Creates a ChaCha20-Poly1305 AEAD mode with the given key.
///
/// Uses standard parameters per RFC 8439: 12-byte (96-bit) nonce and
/// 16-byte (128-bit) authentication tag.
///
/// ## Parameters
/// - `key`: A 32-byte (256-bit) key
///
/// ## Returns
/// - `Ok(AeadMode)` if the key is exactly 32 bytes
/// - `Error(Nil)` if the key size is incorrect
pub fn chacha20_poly1305(key: BitArray) -> Result(AeadMode, Nil) {
  case bit_array.byte_size(key) == 32 {
    True -> Ok(ChaCha20Poly1305(key))
    False -> Error(Nil)
  }
}

/// Returns the required nonce size in bytes for an AEAD mode.
///
/// ## Parameters
/// - `mode`: The AEAD mode
///
/// ## Returns
/// The nonce size in bytes (12 for AES-GCM).
pub fn nonce_size(mode: AeadMode) -> Int {
  case mode {
    Gcm(nonce_size:, ..) -> nonce_size
    ChaCha20Poly1305(..) -> 12
  }
}

/// Returns the authentication tag size in bytes for an AEAD mode.
///
/// ## Parameters
/// - `mode`: The AEAD mode
///
/// ## Returns
/// The tag size in bytes (16 for AES-GCM)
pub fn tag_size(mode: AeadMode) -> Int {
  case mode {
    Gcm(..) -> 16
    ChaCha20Poly1305(..) -> 16
  }
}

/// Encrypts and authenticates plaintext using AEAD.
///
/// ## Parameters
/// - `mode`: The AEAD mode to use
/// - `nonce`: A unique nonce (must be exactly `nonce_size` bytes).
///   Never reuse a nonce with the same key.
/// - `plaintext`: The data to encrypt
///
/// ## Returns
/// - `Ok(#(ciphertext, tag))` with the encrypted data and authentication tag
/// - `Error(Nil)` if the nonce size is incorrect
pub fn seal(
  mode: AeadMode,
  nonce nonce: BitArray,
  plaintext plaintext: BitArray,
) -> Result(#(BitArray, BitArray), Nil) {
  seal_with_aad(mode, nonce, plaintext, <<>>)
}

/// Encrypts and authenticates plaintext with additional authenticated data.
///
/// The AAD is authenticated but not encrypted. It can be used for headers,
/// metadata, or context that should be tamper-proof but remain readable.
///
/// ## Parameters
/// - `mode`: The AEAD mode to use
/// - `nonce`: A unique nonce (must be exactly `nonce_size` bytes and non-empty)
/// - `plaintext`: The data to encrypt
/// - `additional_data`: Data to authenticate but not encrypt
///
/// ## Returns
/// - `Ok(#(ciphertext, tag))` with the encrypted data and authentication tag
/// - `Error(Nil)` if the nonce size is incorrect or empty
pub fn seal_with_aad(
  mode: AeadMode,
  nonce nonce: BitArray,
  plaintext plaintext: BitArray,
  additional_data aad: BitArray,
) -> Result(#(BitArray, BitArray), Nil) {
  let nonce_len = bit_array.byte_size(nonce)
  case nonce_len > 0 && nonce_len == nonce_size(mode) {
    True -> do_seal(mode, nonce, plaintext, aad)
    False -> Error(Nil)
  }
}

@external(erlang, "kryptos_ffi", "aead_seal")
@external(javascript, "../kryptos_ffi.mjs", "aeadSeal")
fn do_seal(
  mode: AeadMode,
  nonce: BitArray,
  plaintext: BitArray,
  aad: BitArray,
) -> Result(#(BitArray, BitArray), Nil)

/// Decrypts and verifies AEAD-encrypted data.
///
/// ## Parameters
/// - `mode`: The AEAD mode to use
/// - `nonce`: The nonce used during encryption
/// - `tag`: The authentication tag from encryption
/// - `ciphertext`: The encrypted data
///
/// ## Returns
/// - `Ok(plaintext)` if authentication succeeds
/// - `Error(Nil)` if authentication fails or nonce size is incorrect
pub fn open(
  mode: AeadMode,
  nonce nonce: BitArray,
  tag tag: BitArray,
  ciphertext ciphertext: BitArray,
) -> Result(BitArray, Nil) {
  open_with_aad(mode, nonce, tag, ciphertext, <<>>)
}

/// Decrypts and verifies AEAD-encrypted data with additional authenticated data.
///
/// The AAD must match exactly what was provided during encryption.
///
/// ## Parameters
/// - `mode`: The AEAD mode to use
/// - `nonce`: The nonce used during encryption (must be non-empty)
/// - `tag`: The authentication tag from encryption
/// - `ciphertext`: The encrypted data
/// - `additional_data`: The same AAD used during encryption
///
/// ## Returns
/// - `Ok(plaintext)` if authentication succeeds
/// - `Error(Nil)` if authentication fails, AAD mismatch, or nonce size is incorrect/empty
pub fn open_with_aad(
  mode: AeadMode,
  nonce nonce: BitArray,
  tag tag: BitArray,
  ciphertext ciphertext: BitArray,
  additional_data aad: BitArray,
) -> Result(BitArray, Nil) {
  let nonce_len = bit_array.byte_size(nonce)
  let tag_len = bit_array.byte_size(tag)
  case
    nonce_len > 0 && nonce_len == nonce_size(mode) && tag_len == tag_size(mode)
  {
    True -> do_open(mode, nonce, tag, ciphertext, aad)
    False -> Error(Nil)
  }
}

@external(erlang, "kryptos_ffi", "aead_open")
@external(javascript, "../kryptos_ffi.mjs", "aeadOpen")
fn do_open(
  mode: AeadMode,
  nonce: BitArray,
  tag: BitArray,
  ciphertext: BitArray,
  aad: BitArray,
) -> Result(BitArray, Nil)

@internal
pub fn aead_cipher_name(mode: AeadMode) -> String {
  case mode {
    Gcm(cipher:, ..) ->
      case cipher {
        Aes(key_size:, ..) ->
          case key_size {
            block.Aes128 -> "aes-128-gcm"
            block.Aes192 -> "aes-192-gcm"
            block.Aes256 -> "aes-256-gcm"
          }
      }
    ChaCha20Poly1305(..) -> "chacha20-poly1305"
  }
}

@internal
pub fn aead_cipher_key(mode: AeadMode) -> BitArray {
  case mode {
    Gcm(cipher:, ..) ->
      case cipher {
        Aes(key:, ..) -> key
      }
    ChaCha20Poly1305(key:) -> key
  }
}
