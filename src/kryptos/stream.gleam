//// Stream cipher implementations.
////
//// ChaCha20 (RFC 8439) and XChaCha20 (draft-irtf-cfrg-xchacha) with a
//// caller-chosen starting block counter.
////
//// **IMPORTANT SECURITY WARNING:**
//// These ciphers do NOT provide authentication. An attacker can modify
//// ciphertext without detection. For most applications, you should use
//// ChaCha20-Poly1305 or XChaCha20-Poly1305 from the `kryptos/aead` module
//// instead.
////
//// Use these ciphers only when:
//// - Implementing higher-level protocols that provide their own authentication
//// - You fully understand the security implications
////
//// Nonce reuse is catastrophic - NEVER reuse a nonce with the same key.
////
//// ## Example
////
//// ```gleam
//// import kryptos/crypto
//// import kryptos/stream
////
//// let key = crypto.random_bytes(32)
//// let nonce = crypto.random_bytes(24)
//// let assert Ok(cipher) = stream.xchacha20(key, nonce:, counter: 0)
//// let assert Ok(ciphertext) = stream.xor(cipher, <<"secret":utf8>>)
//// let assert Ok(plaintext) = stream.xor(cipher, ciphertext)
//// // plaintext == <<"secret":utf8>>
//// ```

import gleam/bit_array
import kryptos/internal/hchacha20

const counter_limit = 0x100000000

/// A stream cipher with its key, nonce, and starting block counter.
pub opaque type StreamCipher {
  ChaCha20(key: BitArray, nonce: BitArray, counter: Int)
}

/// Creates a ChaCha20 cipher (RFC 8439).
///
/// The key must be exactly 32 bytes, the nonce exactly 12 bytes, and the
/// counter between 0 and 2^32 - 1.
pub fn chacha20(
  key: BitArray,
  nonce nonce: BitArray,
  counter counter: Int,
) -> Result(StreamCipher, Nil) {
  case
    bit_array.byte_size(key) == 32,
    bit_array.byte_size(nonce) == 12,
    counter >= 0 && counter < counter_limit
  {
    True, True, True -> Ok(ChaCha20(key, nonce, counter))
    _, _, _ -> Error(Nil)
  }
}

/// Creates an XChaCha20 cipher (draft-irtf-cfrg-xchacha).
///
/// The key must be exactly 32 bytes, the nonce exactly 24 bytes, and the
/// counter between 0 and 2^32 - 1. The extended nonce is large enough to be
/// generated randomly.
pub fn xchacha20(
  key: BitArray,
  nonce nonce: BitArray,
  counter counter: Int,
) -> Result(StreamCipher, Nil) {
  case hchacha20.xchacha20_derive(key, nonce) {
    Ok(#(subkey, chacha_nonce)) ->
      chacha20(subkey, nonce: chacha_nonce, counter:)
    Error(Nil) -> Error(Nil)
  }
}

/// XORs data with the keystream. The same call encrypts plaintext and
/// decrypts ciphertext, and the output is the same size as the input.
///
/// Every call starts at the cipher's counter, so XORing two messages with the
/// same cipher reuses the keystream. To continue a stream, create a new cipher
/// with the counter advanced by the number of 64-byte blocks already used.
///
/// Returns an error if the data would need a block counter above 2^32 - 1.
pub fn xor(cipher: StreamCipher, data: BitArray) -> Result(BitArray, Nil) {
  let ChaCha20(key:, nonce:, counter:) = cipher
  let blocks = { bit_array.byte_size(data) + 63 } / 64
  case counter + blocks <= counter_limit {
    True -> do_xor(key, <<counter:32-little, nonce:bits>>, data)
    False -> Error(Nil)
  }
}

@external(erlang, "kryptos_ffi", "chacha20_xor")
@external(javascript, "../kryptos_ffi.mjs", "chacha20Xor")
fn do_xor(key: BitArray, iv: BitArray, data: BitArray) -> Result(BitArray, Nil)
