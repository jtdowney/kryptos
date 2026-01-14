import gleam/bit_array
import gleam/int
import kryptos/block
import kryptos/crypto

pub fn ecb_aes_128_roundtrip_test() {
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  let ctx = block.ecb(cipher)
  let plaintext = <<"attack at dawn!!":utf8>>
  let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
  let assert Ok(output) = block.decrypt(ctx, ciphertext)

  assert output == plaintext
}

pub fn ecb_aes_192_roundtrip_test() {
  let assert Ok(cipher) = block.aes_192(crypto.random_bytes(24))
  let ctx = block.ecb(cipher)
  let plaintext = <<"attack at dawn!!":utf8>>
  let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
  let assert Ok(output) = block.decrypt(ctx, ciphertext)

  assert output == plaintext
}

pub fn ecb_aes_256_roundtrip_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let ctx = block.ecb(cipher)
  let plaintext = <<"attack at dawn!!":utf8>>
  let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
  let assert Ok(output) = block.decrypt(ctx, ciphertext)

  assert output == plaintext
}

pub fn ecb_pattern_visibility_test() {
  // ECB encrypts identical blocks to identical ciphertext
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  let ctx = block.ecb(cipher)
  // Two identical 16-byte blocks
  let plaintext = <<"AAAAAAAAAAAAAAAA":utf8>>
  let two_blocks = <<plaintext:bits, plaintext:bits>>
  let assert Ok(ciphertext) = block.encrypt(ctx, two_blocks)
  // Ciphertext should have identical first and second blocks (32 bytes total + 16 padding = 48)
  let assert <<block1:bytes-size(16), block2:bytes-size(16), _rest:bytes>> =
    ciphertext
  assert block1 == block2
}

pub fn cbc_aes_128_roundtrip_test() {
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  let assert Ok(ctx) = block.cbc(cipher, crypto.random_bytes(16))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
  let assert Ok(output) = block.decrypt(ctx, ciphertext)

  assert output == plaintext
}

pub fn cbc_aes_192_roundtrip_test() {
  let assert Ok(cipher) = block.aes_192(crypto.random_bytes(24))
  let assert Ok(ctx) = block.cbc(cipher, crypto.random_bytes(16))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
  let assert Ok(output) = block.decrypt(ctx, ciphertext)

  assert output == plaintext
}

pub fn cbc_aes_256_roundtrip_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let assert Ok(ctx) = block.cbc(cipher, crypto.random_bytes(16))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
  let assert Ok(output) = block.decrypt(ctx, ciphertext)

  assert output == plaintext
}

pub fn cbc_pkcs7_padding_test() {
  // CBC with PKCS7 padding should handle various plaintext sizes
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let assert Ok(ctx) = block.cbc(cipher, crypto.random_bytes(16))

  // Test various sizes that need different padding amounts
  let short = <<"short":utf8>>
  let assert Ok(ct1) = block.encrypt(ctx, short)
  let assert Ok(out1) = block.decrypt(ctx, ct1)
  assert out1 == short

  // Exactly one block (16 bytes) - needs full block of padding
  let one_block = <<"exactly16bytes!!":utf8>>
  let assert Ok(ct2) = block.encrypt(ctx, one_block)
  let assert Ok(out2) = block.decrypt(ctx, ct2)
  assert out2 == one_block

  // 17 bytes - needs 15 bytes padding
  let seventeen = <<"17bytesofdata!!!!":utf8>>
  let assert Ok(ct3) = block.encrypt(ctx, seventeen)
  let assert Ok(out3) = block.decrypt(ctx, ct3)
  assert out3 == seventeen
}

pub fn cbc_empty_plaintext_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let assert Ok(ctx) = block.cbc(cipher, crypto.random_bytes(16))
  let plaintext = <<>>

  let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
  let assert Ok(output) = block.decrypt(ctx, ciphertext)

  assert output == plaintext
}

pub fn cbc_wrong_iv_size_test() {
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  let wrong_iv = crypto.random_bytes(8)

  assert block.cbc(cipher, wrong_iv) == Error(Nil)
}

pub fn cbc_different_iv_different_ciphertext_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let plaintext = <<"same plaintext":utf8>>

  let assert Ok(ctx1) = block.cbc(cipher, crypto.random_bytes(16))
  let assert Ok(ctx2) = block.cbc(cipher, crypto.random_bytes(16))

  let assert Ok(ct1) = block.encrypt(ctx1, plaintext)
  let assert Ok(ct2) = block.encrypt(ctx2, plaintext)

  // Different IVs should produce different ciphertext
  assert ct1 != ct2
}

pub fn cbc_wrong_key_test() {
  let assert Ok(cipher1) = block.aes_256(crypto.random_bytes(32))
  let assert Ok(cipher2) = block.aes_256(crypto.random_bytes(32))
  let iv = crypto.random_bytes(16)
  let plaintext = <<"secret":utf8>>

  let assert Ok(ctx1) = block.cbc(cipher1, iv)
  let assert Ok(ciphertext) = block.encrypt(ctx1, plaintext)

  // Decrypting with wrong key should produce garbage (won't error due to padding luck sometimes)
  // So we just verify we get a different result
  let assert Ok(ctx2) = block.cbc(cipher2, iv)
  let result = block.decrypt(ctx2, ciphertext)

  case result {
    Ok(decrypted) -> {
      assert decrypted != plaintext
    }
    Error(Nil) -> Nil
  }
}

pub fn ctr_aes_128_roundtrip_test() {
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  let assert Ok(ctx) = block.ctr(cipher, crypto.random_bytes(16))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
  let assert Ok(output) = block.decrypt(ctx, ciphertext)

  assert output == plaintext
}

pub fn ctr_aes_192_roundtrip_test() {
  let assert Ok(cipher) = block.aes_192(crypto.random_bytes(24))
  let assert Ok(ctx) = block.ctr(cipher, crypto.random_bytes(16))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
  let assert Ok(output) = block.decrypt(ctx, ciphertext)

  assert output == plaintext
}

pub fn ctr_aes_256_roundtrip_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let assert Ok(ctx) = block.ctr(cipher, crypto.random_bytes(16))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
  let assert Ok(output) = block.decrypt(ctx, ciphertext)

  assert output == plaintext
}

pub fn ctr_empty_plaintext_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let assert Ok(ctx) = block.ctr(cipher, crypto.random_bytes(16))
  let plaintext = <<>>

  let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
  let assert Ok(output) = block.decrypt(ctx, ciphertext)

  assert output == plaintext
  assert bit_array.byte_size(ciphertext) == 0
}

pub fn ctr_wrong_nonce_size_test() {
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  let wrong_nonce = crypto.random_bytes(8)

  assert block.ctr(cipher, wrong_nonce) == Error(Nil)
}

pub fn ctr_different_nonce_different_ciphertext_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let plaintext = <<"same plaintext":utf8>>

  let assert Ok(ctx1) = block.ctr(cipher, crypto.random_bytes(16))
  let assert Ok(ctx2) = block.ctr(cipher, crypto.random_bytes(16))

  let assert Ok(ct1) = block.encrypt(ctx1, plaintext)
  let assert Ok(ct2) = block.encrypt(ctx2, plaintext)

  // Different nonces should produce different ciphertext
  assert ct1 != ct2
}

pub fn wrap_unwrap_aes_128_roundtrip_test() {
  let assert Ok(kek) = block.aes_128(crypto.random_bytes(16))
  let key_to_wrap = crypto.random_bytes(16)
  let assert Ok(wrapped) = block.wrap(kek, key_to_wrap)
  let assert Ok(unwrapped) = block.unwrap(kek, wrapped)

  assert unwrapped == key_to_wrap
  assert bit_array.byte_size(wrapped) == 24
}

pub fn wrap_unwrap_aes_192_roundtrip_test() {
  let assert Ok(kek) = block.aes_192(crypto.random_bytes(24))
  let key_to_wrap = crypto.random_bytes(24)
  let assert Ok(wrapped) = block.wrap(kek, key_to_wrap)
  let assert Ok(unwrapped) = block.unwrap(kek, wrapped)

  assert unwrapped == key_to_wrap
  assert bit_array.byte_size(wrapped) == 32
}

pub fn wrap_unwrap_aes_256_roundtrip_test() {
  let assert Ok(kek) = block.aes_256(crypto.random_bytes(32))
  let key_to_wrap = crypto.random_bytes(32)
  let assert Ok(wrapped) = block.wrap(kek, key_to_wrap)
  let assert Ok(unwrapped) = block.unwrap(kek, wrapped)

  assert unwrapped == key_to_wrap
  assert bit_array.byte_size(wrapped) == 40
}

pub fn wrap_longer_key_than_kek_test() {
  let assert Ok(kek) = block.aes_128(crypto.random_bytes(16))
  let key_to_wrap = crypto.random_bytes(32)
  let assert Ok(wrapped) = block.wrap(kek, key_to_wrap)
  let assert Ok(unwrapped) = block.unwrap(kek, wrapped)

  assert unwrapped == key_to_wrap
}

pub fn wrap_plaintext_too_short_test() {
  let assert Ok(kek) = block.aes_128(crypto.random_bytes(16))
  let too_short = crypto.random_bytes(8)

  assert block.wrap(kek, too_short) == Error(Nil)
}

pub fn wrap_plaintext_not_multiple_of_8_test() {
  let assert Ok(kek) = block.aes_128(crypto.random_bytes(16))
  let wrong_size = crypto.random_bytes(17)

  assert block.wrap(kek, wrong_size) == Error(Nil)
}

pub fn unwrap_ciphertext_too_short_test() {
  let assert Ok(kek) = block.aes_128(crypto.random_bytes(16))
  let too_short = crypto.random_bytes(16)

  assert block.unwrap(kek, too_short) == Error(Nil)
}

pub fn unwrap_wrong_key_test() {
  let assert Ok(kek1) = block.aes_256(crypto.random_bytes(32))
  let assert Ok(kek2) = block.aes_256(crypto.random_bytes(32))
  let key_to_wrap = crypto.random_bytes(32)

  let assert Ok(wrapped) = block.wrap(kek1, key_to_wrap)
  assert block.unwrap(kek2, wrapped) == Error(Nil)
}

pub fn unwrap_tampered_ciphertext_test() {
  let assert Ok(kek) = block.aes_256(crypto.random_bytes(32))
  let key_to_wrap = crypto.random_bytes(32)
  let assert Ok(wrapped) = block.wrap(kek, key_to_wrap)

  let assert <<first:int, rest:bits>> = wrapped
  let tampered = <<{ int.bitwise_exclusive_or(first, 1) }:int, rest:bits>>

  assert block.unwrap(kek, tampered) == Error(Nil)
}
