import gleam/bit_array
import kryptos/aead
import kryptos/block
import kryptos/crypto

pub fn aes_128_gcm_test() {
  let assert Ok(cipher) = block.new_aes_128(crypto.random_bytes(16))
  let ctx = aead.gcm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)

  assert output == plaintext
}

pub fn aes_192_gcm_test() {
  let assert Ok(cipher) = block.new_aes_192(crypto.random_bytes(24))
  let ctx = aead.gcm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)

  assert output == plaintext
}

pub fn aes_256_gcm_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
  let ctx = aead.gcm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)

  assert output == plaintext
}

pub fn aes_gcm_with_aad_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
  let ctx = aead.gcm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret message":utf8>>
  let aad = <<"header data":utf8>>

  let assert Ok(#(ciphertext, tag)) =
    aead.seal_with_aad(ctx, nonce, plaintext, aad)
  let assert Ok(output) = aead.open_with_aad(ctx, nonce, tag, ciphertext, aad)

  assert output == plaintext
}

pub fn wrong_nonce_size_seal_test() {
  let assert Ok(cipher) = block.new_aes_128(crypto.random_bytes(16))
  let ctx = aead.gcm(cipher)
  let wrong_nonce = crypto.random_bytes(8)
  let plaintext = <<"test":utf8>>

  assert aead.seal(ctx, nonce: wrong_nonce, plaintext:) == Error(Nil)
}

pub fn wrong_nonce_size_open_test() {
  let assert Ok(cipher) = block.new_aes_128(crypto.random_bytes(16))
  let ctx = aead.gcm(cipher)
  let wrong_nonce = crypto.random_bytes(8)
  let tag = crypto.random_bytes(16)
  let ciphertext = <<"test":utf8>>

  assert aead.open(ctx, nonce: wrong_nonce, tag:, ciphertext:) == Error(Nil)
}

pub fn tampered_ciphertext_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
  let ctx = aead.gcm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered = <<0xFF, ciphertext:bits>>

  assert aead.open(ctx, nonce:, tag:, ciphertext: tampered) == Error(Nil)
}

pub fn tampered_tag_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
  let ctx = aead.gcm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, _tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered_tag = crypto.random_bytes(16)

  assert aead.open(ctx, nonce:, tag: tampered_tag, ciphertext:) == Error(Nil)
}

pub fn wrong_aad_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
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

pub fn empty_plaintext_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
  let ctx = aead.gcm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)

  assert output == plaintext
}

pub fn wrong_key_test() {
  let assert Ok(cipher1) = block.new_aes_256(crypto.random_bytes(32))
  let assert Ok(cipher2) = block.new_aes_256(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(12)
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) =
    aead.seal(aead.gcm(cipher1), nonce:, plaintext:)

  assert aead.open(aead.gcm(cipher2), nonce:, tag:, ciphertext:) == Error(Nil)
}

pub fn aes_128_wrong_key_size_test() {
  assert block.new_aes_128(crypto.random_bytes(15)) == Error(Nil)
  assert block.new_aes_128(crypto.random_bytes(17)) == Error(Nil)
}

pub fn aes_192_wrong_key_size_test() {
  assert block.new_aes_192(crypto.random_bytes(23)) == Error(Nil)
  assert block.new_aes_192(crypto.random_bytes(25)) == Error(Nil)
}

pub fn aes_256_wrong_key_size_test() {
  assert block.new_aes_256(crypto.random_bytes(31)) == Error(Nil)
  assert block.new_aes_256(crypto.random_bytes(33)) == Error(Nil)
}

pub fn wrong_tag_size_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
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

pub fn chacha20_poly1305_test() {
  let assert Ok(ctx) = aead.chacha20_poly1305(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)

  assert output == plaintext
}

pub fn chacha20_poly1305_with_aad_test() {
  let assert Ok(ctx) = aead.chacha20_poly1305(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret message":utf8>>
  let aad = <<"header data":utf8>>

  let assert Ok(#(ciphertext, tag)) =
    aead.seal_with_aad(ctx, nonce, plaintext, aad)
  let assert Ok(output) = aead.open_with_aad(ctx, nonce, tag, ciphertext, aad)

  assert output == plaintext
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

pub fn chacha20_poly1305_empty_plaintext_test() {
  let assert Ok(ctx) = aead.chacha20_poly1305(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)

  assert output == plaintext
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

pub fn aes_128_ccm_test() {
  let assert Ok(cipher) = block.new_aes_128(crypto.random_bytes(16))
  let ctx = aead.ccm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)

  assert output == plaintext
}

pub fn aes_192_ccm_test() {
  let assert Ok(cipher) = block.new_aes_192(crypto.random_bytes(24))
  let ctx = aead.ccm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)

  assert output == plaintext
}

pub fn aes_256_ccm_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
  let ctx = aead.ccm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"attack at dawn":utf8>>
  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)

  assert output == plaintext
}

pub fn aes_ccm_with_aad_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
  let ctx = aead.ccm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret message":utf8>>
  let aad = <<"header data":utf8>>

  let assert Ok(#(ciphertext, tag)) =
    aead.seal_with_aad(ctx, nonce, plaintext, aad)
  let assert Ok(output) = aead.open_with_aad(ctx, nonce, tag, ciphertext, aad)

  assert output == plaintext
}

pub fn aes_ccm_with_custom_sizes_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
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
  let assert Ok(cipher) = block.new_aes_128(crypto.random_bytes(16))
  assert aead.ccm_with_sizes(cipher, nonce_size: 6, tag_size: 16) == Error(Nil)
  assert aead.ccm_with_sizes(cipher, nonce_size: 14, tag_size: 16) == Error(Nil)
}

pub fn ccm_invalid_tag_size_config_test() {
  let assert Ok(cipher) = block.new_aes_128(crypto.random_bytes(16))
  assert aead.ccm_with_sizes(cipher, nonce_size: 13, tag_size: 5) == Error(Nil)
  assert aead.ccm_with_sizes(cipher, nonce_size: 13, tag_size: 17) == Error(Nil)
  assert aead.ccm_with_sizes(cipher, nonce_size: 13, tag_size: 3) == Error(Nil)
}

pub fn ccm_wrong_nonce_size_seal_test() {
  let assert Ok(cipher) = block.new_aes_128(crypto.random_bytes(16))
  let ctx = aead.ccm(cipher)
  let wrong_nonce = crypto.random_bytes(8)
  let plaintext = <<"test":utf8>>

  assert aead.seal(ctx, nonce: wrong_nonce, plaintext:) == Error(Nil)
}

pub fn ccm_wrong_nonce_size_open_test() {
  let assert Ok(cipher) = block.new_aes_128(crypto.random_bytes(16))
  let ctx = aead.ccm(cipher)
  let wrong_nonce = crypto.random_bytes(8)
  let tag = crypto.random_bytes(16)
  let ciphertext = <<"test":utf8>>

  assert aead.open(ctx, nonce: wrong_nonce, tag:, ciphertext:) == Error(Nil)
}

pub fn ccm_tampered_ciphertext_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
  let ctx = aead.ccm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered = <<0xFF, ciphertext:bits>>

  assert aead.open(ctx, nonce:, tag:, ciphertext: tampered) == Error(Nil)
}

pub fn ccm_tampered_tag_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
  let ctx = aead.ccm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, _tag)) = aead.seal(ctx, nonce:, plaintext:)
  let tampered_tag = crypto.random_bytes(16)

  assert aead.open(ctx, nonce:, tag: tampered_tag, ciphertext:) == Error(Nil)
}

pub fn ccm_wrong_aad_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
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

pub fn ccm_empty_plaintext_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
  let ctx = aead.ccm(cipher)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))
  let plaintext = <<>>

  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(output) = aead.open(ctx, nonce:, tag:, ciphertext:)

  assert output == plaintext
}

pub fn ccm_wrong_key_test() {
  let assert Ok(cipher1) = block.new_aes_256(crypto.random_bytes(32))
  let assert Ok(cipher2) = block.new_aes_256(crypto.random_bytes(32))
  let nonce = crypto.random_bytes(13)
  let plaintext = <<"secret":utf8>>

  let assert Ok(#(ciphertext, tag)) =
    aead.seal(aead.ccm(cipher1), nonce:, plaintext:)

  assert aead.open(aead.ccm(cipher2), nonce:, tag:, ciphertext:) == Error(Nil)
}

pub fn ccm_wrong_tag_size_test() {
  let assert Ok(cipher) = block.new_aes_256(crypto.random_bytes(32))
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
