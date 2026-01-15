import gleam/bit_array
import kryptos/aead
import kryptos/block
import kryptos/crypto
import qcheck

// Property: AES-GCM seal then open returns original plaintext
pub fn aes_gcm_roundtrip_property_test() {
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
    let assert Ok(cipher) = case key_size {
      16 -> block.aes_128(crypto.random_bytes(16))
      24 -> block.aes_192(crypto.random_bytes(24))
      _ -> block.aes_256(crypto.random_bytes(32))
    }
    let ctx = aead.gcm(cipher)
    let nonce = crypto.random_bytes(aead.nonce_size(ctx))
    let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
    let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)
    assert output == plaintext
  })
}

// Property: AES-GCM with AAD seal then open returns original plaintext
pub fn aes_gcm_with_aad_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.byte_aligned_bit_array(),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(plaintext, aad) = input
    let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
    let ctx = aead.gcm(cipher)
    let nonce = crypto.random_bytes(aead.nonce_size(ctx))
    let assert Ok(#(ciphertext, tag)) =
      aead.seal_with_aad(ctx, nonce, plaintext, aad)
    let assert Ok(output) = aead.open_with_aad(ctx, nonce, tag, ciphertext, aad)
    assert output == plaintext
  })
}

pub fn wrong_nonce_size_seal_test() {
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  let ctx = aead.gcm(cipher)
  let wrong_nonce = crypto.random_bytes(8)
  let plaintext = <<"test":utf8>>

  assert aead.seal(ctx, nonce: wrong_nonce, plaintext:) == Error(Nil)
}

pub fn wrong_nonce_size_open_test() {
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  let ctx = aead.gcm(cipher)
  let wrong_nonce = crypto.random_bytes(8)
  let tag = crypto.random_bytes(16)
  let ciphertext = <<"test":utf8>>

  assert aead.open(ctx, nonce: wrong_nonce, tag:, ciphertext:) == Error(Nil)
}

pub fn tampered_ciphertext_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let ctx = aead.gcm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered = <<0xFF, ciphertext:bits>>

  assert aead.open(ctx, nonce:, tag:, ciphertext: tampered) == Error(Nil)
}

pub fn tampered_tag_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let ctx = aead.gcm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, _tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered_tag = crypto.random_bytes(16)

  assert aead.open(ctx, nonce:, tag: tampered_tag, ciphertext:) == Error(Nil)
}

pub fn wrong_aad_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let ctx = aead.gcm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>
  let aad = <<"correct aad":utf8>>

  let assert Ok(#(ciphertext, tag)) =
    aead.seal_with_aad(ctx, nonce, plaintext, aad)
  let wrong_aad = <<"wrong aad":utf8>>

  assert aead.open_with_aad(ctx, nonce, tag, ciphertext, wrong_aad)
    == Error(Nil)
}

pub fn wrong_key_test() {
  let assert Ok(cipher1) = block.aes_256(crypto.random_bytes(32))
  let assert Ok(cipher2) = block.aes_256(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(12)
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) =
    aead.seal(aead.gcm(cipher1), nonce:, plaintext:)

  assert aead.open(aead.gcm(cipher2), nonce:, tag:, ciphertext:) == Error(Nil)
}

pub fn aes_128_wrong_key_size_test() {
  assert block.aes_128(crypto.random_bytes(15)) == Error(Nil)
  assert block.aes_128(crypto.random_bytes(17)) == Error(Nil)
}

pub fn aes_192_wrong_key_size_test() {
  assert block.aes_192(crypto.random_bytes(23)) == Error(Nil)
  assert block.aes_192(crypto.random_bytes(25)) == Error(Nil)
}

pub fn aes_256_wrong_key_size_test() {
  assert block.aes_256(crypto.random_bytes(31)) == Error(Nil)
  assert block.aes_256(crypto.random_bytes(33)) == Error(Nil)
}

pub fn wrong_tag_size_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let ctx = aead.gcm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)

  let assert <<truncated_tag:bytes-size(15), _:bytes>> = tag
  assert aead.open(ctx, nonce:, tag: truncated_tag, ciphertext:) == Error(Nil)

  let extended_tag = <<tag:bits, 0xFF>>
  assert aead.open(ctx, nonce:, tag: extended_tag, ciphertext:) == Error(Nil)

  assert aead.open(ctx, nonce:, tag: <<>>, ciphertext:) == Error(Nil)
}

// Property: ChaCha20-Poly1305 seal then open returns original plaintext
pub fn chacha20_poly1305_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.byte_aligned_bit_array(),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(plaintext, aad) = input
    let assert Ok(ctx) = aead.chacha20_poly1305(crypto.random_bytes(32))
    let nonce = crypto.random_bytes(aead.nonce_size(ctx))

    // Test without AAD
    let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
    let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)
    assert output == plaintext

    // Test with AAD
    let assert Ok(#(ciphertext2, tag2)) =
      aead.seal_with_aad(ctx, nonce, plaintext, aad)
    let assert Ok(output2) =
      aead.open_with_aad(ctx, nonce, tag2, ciphertext2, aad)
    assert output2 == plaintext
  })
}

pub fn chacha20_poly1305_wrong_nonce_size_seal_test() {
  let assert Ok(ctx) = aead.chacha20_poly1305(crypto.random_bytes(32))
  let wrong_nonce = crypto.random_bytes(8)
  let plaintext = <<"test":utf8>>

  assert aead.seal(ctx, nonce: wrong_nonce, plaintext:) == Error(Nil)
}

pub fn chacha20_poly1305_wrong_nonce_size_open_test() {
  let assert Ok(ctx) = aead.chacha20_poly1305(crypto.random_bytes(32))
  let wrong_nonce = crypto.random_bytes(8)
  let tag = crypto.random_bytes(16)
  let ciphertext = <<"test":utf8>>

  assert aead.open(ctx, nonce: wrong_nonce, tag:, ciphertext:) == Error(Nil)
}

pub fn chacha20_poly1305_tampered_ciphertext_test() {
  let assert Ok(ctx) = aead.chacha20_poly1305(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered = <<0xFF, ciphertext:bits>>

  assert aead.open(ctx, nonce:, tag:, ciphertext: tampered) == Error(Nil)
}

pub fn chacha20_poly1305_tampered_tag_test() {
  let assert Ok(ctx) = aead.chacha20_poly1305(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, _tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered_tag = crypto.random_bytes(16)

  assert aead.open(ctx, nonce:, tag: tampered_tag, ciphertext:) == Error(Nil)
}

pub fn chacha20_poly1305_wrong_aad_test() {
  let assert Ok(ctx) = aead.chacha20_poly1305(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>
  let aad = <<"correct aad":utf8>>

  let assert Ok(#(ciphertext, tag)) =
    aead.seal_with_aad(ctx, nonce, plaintext, aad)
  let wrong_aad = <<"wrong aad":utf8>>

  assert aead.open_with_aad(ctx, nonce, tag, ciphertext, wrong_aad)
    == Error(Nil)
}

pub fn chacha20_poly1305_wrong_key_test() {
  let assert Ok(ctx1) = aead.chacha20_poly1305(crypto.random_bytes(32))
  let assert Ok(ctx2) = aead.chacha20_poly1305(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(12)
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx1, nonce:, plaintext:)

  assert aead.open(ctx2, nonce:, tag:, ciphertext:) == Error(Nil)
}

pub fn chacha20_poly1305_wrong_key_size_test() {
  assert aead.chacha20_poly1305(crypto.random_bytes(31)) == Error(Nil)
  assert aead.chacha20_poly1305(crypto.random_bytes(33)) == Error(Nil)
}

// Property: XChaCha20-Poly1305 seal then open returns original plaintext
pub fn xchacha20_poly1305_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.byte_aligned_bit_array(),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(plaintext, aad) = input
    let assert Ok(ctx) = aead.xchacha20_poly1305(crypto.random_bytes(32))
    let nonce = crypto.random_bytes(aead.nonce_size(ctx))

    // Test without AAD
    let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
    let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)
    assert output == plaintext

    // Test with AAD
    let assert Ok(#(ciphertext2, tag2)) =
      aead.seal_with_aad(ctx, nonce, plaintext, aad)
    let assert Ok(output2) =
      aead.open_with_aad(ctx, nonce, tag2, ciphertext2, aad)
    assert output2 == plaintext
  })
}

pub fn xchacha20_poly1305_wrong_nonce_size_seal_test() {
  let assert Ok(ctx) = aead.xchacha20_poly1305(crypto.random_bytes(32))
  let wrong_nonce = crypto.random_bytes(12)
  let plaintext = <<"test":utf8>>

  assert aead.seal(ctx, nonce: wrong_nonce, plaintext:) == Error(Nil)
}

pub fn xchacha20_poly1305_wrong_nonce_size_open_test() {
  let assert Ok(ctx) = aead.xchacha20_poly1305(crypto.random_bytes(32))
  let wrong_nonce = crypto.random_bytes(12)
  let tag = crypto.random_bytes(16)
  let ciphertext = <<"test":utf8>>

  assert aead.open(ctx, nonce: wrong_nonce, tag:, ciphertext:) == Error(Nil)
}

pub fn xchacha20_poly1305_tampered_ciphertext_test() {
  let assert Ok(ctx) = aead.xchacha20_poly1305(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered = <<0xFF, ciphertext:bits>>

  assert aead.open(ctx, nonce:, tag:, ciphertext: tampered) == Error(Nil)
}

pub fn xchacha20_poly1305_tampered_tag_test() {
  let assert Ok(ctx) = aead.xchacha20_poly1305(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, _tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered_tag = crypto.random_bytes(16)

  assert aead.open(ctx, nonce:, tag: tampered_tag, ciphertext:) == Error(Nil)
}

pub fn xchacha20_poly1305_wrong_aad_test() {
  let assert Ok(ctx) = aead.xchacha20_poly1305(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>
  let aad = <<"correct aad":utf8>>

  let assert Ok(#(ciphertext, tag)) =
    aead.seal_with_aad(ctx, nonce, plaintext, aad)
  let wrong_aad = <<"wrong aad":utf8>>

  assert aead.open_with_aad(ctx, nonce, tag, ciphertext, wrong_aad)
    == Error(Nil)
}

pub fn xchacha20_poly1305_wrong_key_test() {
  let assert Ok(ctx1) = aead.xchacha20_poly1305(crypto.random_bytes(32))
  let assert Ok(ctx2) = aead.xchacha20_poly1305(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(24)
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx1, nonce:, plaintext:)

  assert aead.open(ctx2, nonce:, tag:, ciphertext:) == Error(Nil)
}

pub fn xchacha20_poly1305_wrong_key_size_test() {
  assert aead.xchacha20_poly1305(crypto.random_bytes(31)) == Error(Nil)
  assert aead.xchacha20_poly1305(crypto.random_bytes(33)) == Error(Nil)
}

/// Test vector from draft-irtf-cfrg-xchacha-03 Appendix A.3.1
pub fn xchacha20_poly1305_ietf_test_vector_test() {
  let assert Ok(key) =
    bit_array.base16_decode(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    )
  let assert Ok(nonce) =
    bit_array.base16_decode("404142434445464748494a4b4c4d4e4f5051525354555657")
  let assert Ok(aad) = bit_array.base16_decode("50515253c0c1c2c3c4c5c6c7")
  let assert Ok(plaintext) =
    bit_array.base16_decode(
      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    )
  let assert Ok(expected_ciphertext) =
    bit_array.base16_decode(
      "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e",
    )
  let assert Ok(expected_tag) =
    bit_array.base16_decode("c0875924c1c7987947deafd8780acf49")

  let assert Ok(ctx) = aead.xchacha20_poly1305(key)

  let assert Ok(#(ciphertext, tag)) =
    aead.seal_with_aad(ctx, nonce, plaintext, aad)
  assert ciphertext == expected_ciphertext
  assert tag == expected_tag

  let assert Ok(decrypted) =
    aead.open_with_aad(ctx, nonce, expected_tag, expected_ciphertext, aad)
  assert decrypted == plaintext
}

// Property: AES-CCM seal then open returns original plaintext
pub fn aes_ccm_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(16), [
        qcheck.return(24),
        qcheck.return(32),
      ]),
      qcheck.tuple2(
        qcheck.byte_aligned_bit_array(),
        qcheck.byte_aligned_bit_array(),
      ),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(key_size, #(plaintext, aad)) = input
    let assert Ok(cipher) = case key_size {
      16 -> block.aes_128(crypto.random_bytes(16))
      24 -> block.aes_192(crypto.random_bytes(24))
      _ -> block.aes_256(crypto.random_bytes(32))
    }
    let ctx = aead.ccm(cipher)
    let nonce = crypto.random_bytes(aead.nonce_size(ctx))

    // Test without AAD
    let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
    let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)
    assert output == plaintext

    // Test with AAD
    let assert Ok(#(ciphertext2, tag2)) =
      aead.seal_with_aad(ctx, nonce, plaintext, aad)
    let assert Ok(output2) =
      aead.open_with_aad(ctx, nonce, tag2, ciphertext2, aad)
    assert output2 == plaintext
  })
}

pub fn aes_ccm_with_custom_sizes_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let assert Ok(ctx) = aead.ccm_with_sizes(cipher, nonce_size: 12, tag_size: 8)
  assert aead.nonce_size(ctx) == 12
  assert aead.tag_size(ctx) == 8
  let nonce = crypto.random_bytes(12)
  let plaintext = <<"test message":utf8>>
  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  assert bit_array.byte_size(tag) == 8
  let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)

  assert output == plaintext
}

pub fn ccm_invalid_nonce_size_config_test() {
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  assert aead.ccm_with_sizes(cipher, nonce_size: 6, tag_size: 16) == Error(Nil)
  assert aead.ccm_with_sizes(cipher, nonce_size: 14, tag_size: 16) == Error(Nil)
}

pub fn ccm_invalid_tag_size_config_test() {
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  assert aead.ccm_with_sizes(cipher, nonce_size: 13, tag_size: 5) == Error(Nil)
  assert aead.ccm_with_sizes(cipher, nonce_size: 13, tag_size: 17) == Error(Nil)
  assert aead.ccm_with_sizes(cipher, nonce_size: 13, tag_size: 3) == Error(Nil)
}

pub fn ccm_wrong_nonce_size_seal_test() {
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  let ctx = aead.ccm(cipher)
  let wrong_nonce = crypto.random_bytes(8)
  let plaintext = <<"test":utf8>>

  assert aead.seal(ctx, nonce: wrong_nonce, plaintext:) == Error(Nil)
}

pub fn ccm_wrong_nonce_size_open_test() {
  let assert Ok(cipher) = block.aes_128(crypto.random_bytes(16))
  let ctx = aead.ccm(cipher)
  let wrong_nonce = crypto.random_bytes(8)
  let tag = crypto.random_bytes(16)
  let ciphertext = <<"test":utf8>>

  assert aead.open(ctx, nonce: wrong_nonce, tag:, ciphertext:) == Error(Nil)
}

pub fn ccm_tampered_ciphertext_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let ctx = aead.ccm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered = <<0xFF, ciphertext:bits>>

  assert aead.open(ctx, nonce:, tag:, ciphertext: tampered) == Error(Nil)
}

pub fn ccm_tampered_tag_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let ctx = aead.ccm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, _tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered_tag = crypto.random_bytes(16)

  assert aead.open(ctx, nonce:, tag: tampered_tag, ciphertext:) == Error(Nil)
}

pub fn ccm_wrong_aad_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let ctx = aead.ccm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>
  let aad = <<"correct aad":utf8>>

  let assert Ok(#(ciphertext, tag)) =
    aead.seal_with_aad(ctx, nonce, plaintext, aad)
  let wrong_aad = <<"wrong aad":utf8>>

  assert aead.open_with_aad(ctx, nonce, tag, ciphertext, wrong_aad)
    == Error(Nil)
}

pub fn ccm_wrong_key_test() {
  let assert Ok(cipher1) = block.aes_256(crypto.random_bytes(32))
  let assert Ok(cipher2) = block.aes_256(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(13)
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) =
    aead.seal(aead.ccm(cipher1), nonce:, plaintext:)

  assert aead.open(aead.ccm(cipher2), nonce:, tag:, ciphertext:) == Error(Nil)
}

pub fn ccm_wrong_tag_size_test() {
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let ctx = aead.ccm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)

  let assert <<truncated_tag:bytes-size(15), _:bytes>> = tag
  assert aead.open(ctx, nonce:, tag: truncated_tag, ciphertext:) == Error(Nil)

  let extended_tag = <<tag:bits, 0xFF>>
  assert aead.open(ctx, nonce:, tag: extended_tag, ciphertext:) == Error(Nil)

  assert aead.open(ctx, nonce:, tag: <<>>, ciphertext:) == Error(Nil)
}
