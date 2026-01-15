import gleam/bit_array
import gleam/int
import kryptos/block
import kryptos/crypto
import qcheck

// Property: ECB encrypt then decrypt returns original plaintext
pub fn ecb_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(16), [
        qcheck.return(24),
        qcheck.return(32),
      ]),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(key_size, plaintext) = input
    let key = crypto.random_bytes(key_size)
    let assert Ok(cipher) = case key_size {
      16 -> block.aes_128(key)
      24 -> block.aes_192(key)
      _ -> block.aes_256(key)
    }
    let ctx = block.ecb(cipher)
    let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
    let assert Ok(output) = block.decrypt(ctx, ciphertext)
    assert output == plaintext
  })
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

// Property: CBC encrypt then decrypt returns original plaintext
pub fn cbc_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(16), [
        qcheck.return(24),
        qcheck.return(32),
      ]),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(key_size, plaintext) = input
    let key = crypto.random_bytes(key_size)
    let assert Ok(cipher) = case key_size {
      16 -> block.aes_128(key)
      24 -> block.aes_192(key)
      _ -> block.aes_256(key)
    }
    let assert Ok(ctx) = block.cbc(cipher, crypto.random_bytes(16))
    let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
    let assert Ok(output) = block.decrypt(ctx, ciphertext)
    assert output == plaintext
  })
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

// Property: CTR encrypt then decrypt returns original plaintext
pub fn ctr_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(16), [
        qcheck.return(24),
        qcheck.return(32),
      ]),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(key_size, plaintext) = input
    let key = crypto.random_bytes(key_size)
    let assert Ok(cipher) = case key_size {
      16 -> block.aes_128(key)
      24 -> block.aes_192(key)
      _ -> block.aes_256(key)
    }
    let assert Ok(ctx) = block.ctr(cipher, crypto.random_bytes(16))
    let assert Ok(ciphertext) = block.encrypt(ctx, plaintext)
    let assert Ok(output) = block.decrypt(ctx, ciphertext)
    assert output == plaintext
    // CTR mode: ciphertext length equals plaintext length
    assert bit_array.byte_size(ciphertext) == bit_array.byte_size(plaintext)
  })
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

// Property: key wrap then unwrap returns original key
pub fn key_wrap_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(16), [
        qcheck.return(24),
        qcheck.return(32),
      ]),
      // Key to wrap must be multiple of 8 bytes and >= 16 bytes
      qcheck.bounded_int(2, 8),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(kek_size, key_blocks) = input
    let key_size = key_blocks * 8
    let kek = crypto.random_bytes(kek_size)
    let key_to_wrap = crypto.random_bytes(key_size)

    let assert Ok(cipher) = case kek_size {
      16 -> block.aes_128(kek)
      24 -> block.aes_192(kek)
      _ -> block.aes_256(kek)
    }

    let assert Ok(wrapped) = block.wrap(cipher, key_to_wrap)
    let assert Ok(unwrapped) = block.unwrap(cipher, wrapped)

    assert unwrapped == key_to_wrap
    // Wrapped key is 8 bytes longer than original
    assert bit_array.byte_size(wrapped) == key_size + 8
  })
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
