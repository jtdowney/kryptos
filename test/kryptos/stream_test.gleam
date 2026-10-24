import gleam/bit_array
import kryptos/aead
import kryptos/crypto
import kryptos/stream
import qcheck

/// Test vector from RFC 8439 Section 2.4.2
pub fn chacha20_rfc8439_test_vector_test() {
  let assert Ok(key) =
    bit_array.base16_decode(
      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    )
  let assert Ok(nonce) = bit_array.base16_decode("000000000000004A00000000")
  let plaintext = <<
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.":utf8,
  >>
  let assert Ok(expected) =
    bit_array.base16_decode(
      "6E2E359A2568F98041BA0728DD0D6981E97E7AEC1D4360C20A27AFCCFD9FAE0BF91B65C5524733AB8F593DABCD62B3571639D624E65152AB8F530C359F0861D807CA0DBF500D6A6156A38E088A22B65E52BC514D16CCF806818CE91AB77937365AF90BBF74A35BE6B40B8EEDF2785E42874D",
    )

  let assert Ok(cipher) = stream.chacha20(key, nonce:, counter: 1)
  let assert Ok(ciphertext) = stream.xor(cipher, plaintext)
  assert ciphertext == expected
  assert stream.xor(cipher, ciphertext) == Ok(plaintext)
}

/// Test vector from draft-irtf-cfrg-xchacha-03 Section A.3.2.1
pub fn xchacha20_counter_0_test_vector_test() {
  let assert Ok(key) =
    bit_array.base16_decode(
      "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
    )
  let assert Ok(nonce) =
    bit_array.base16_decode("404142434445464748494A4B4C4D4E4F5051525354555658")
  let plaintext = <<
    "The dhole (pronounced \"dole\") is also known as the Asiatic wild dog, red dog, and whistling dog. It is about the size of a German shepherd but looks more like a long-legged fox. This highly elusive and skilled jumper is classified with wolves, coyotes, jackals, and foxes in the taxonomic family Canidae.":utf8,
  >>
  let assert Ok(expected) =
    bit_array.base16_decode(
      "4559ABBA4E48C16102E8BB2C05E6947F50A786DE162F9B0B7E592A9B53D0D4E98D8D6410D540A1A6375B26D80DACE4FAB52384C731ACBF16A5923C0C48D3575D4D0D2C673B666FAA731061277701093A6BF7A158A8864292A41C48E3A9B4C0DAECE0F8D98D0D7E05B37A307BBB66333164EC9E1B24EA0D6C3FFDDCEC4F68E7443056193A03C810E11344CA06D8ED8A2BFB1E8D48CFA6BC0EB4E2464B748142407C9F431AEE769960E15BA8B96890466EF2457599852385C661F752CE20F9DA0C09AB6B19DF74E76A95967446F8D0FD415E7BEE2A12A114C20EB5292AE7A349AE577820D5520A1F3FB62A17CE6A7E68FA7C79111D8860920BC048EF43FE84486CCB87C25F0AE045F0CCE1E7989A9AA220A28BDD4827E751A24A6D5C62D790A66393B93111C1A55DD7421A10184974C7C5",
    )

  let assert Ok(cipher) = stream.xchacha20(key, nonce:, counter: 0)
  let assert Ok(ciphertext) = stream.xor(cipher, plaintext)
  assert ciphertext == expected
  assert stream.xor(cipher, ciphertext) == Ok(plaintext)
}

/// Test vector from draft-irtf-cfrg-xchacha-03 Section A.3.2.2
pub fn xchacha20_counter_1_test_vector_test() {
  let assert Ok(key) =
    bit_array.base16_decode(
      "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
    )
  let assert Ok(nonce) =
    bit_array.base16_decode("404142434445464748494A4B4C4D4E4F5051525354555658")
  let plaintext = <<
    "The dhole (pronounced \"dole\") is also known as the Asiatic wild dog, red dog, and whistling dog. It is about the size of a German shepherd but looks more like a long-legged fox. This highly elusive and skilled jumper is classified with wolves, coyotes, jackals, and foxes in the taxonomic family Canidae.":utf8,
  >>
  let assert Ok(expected) =
    bit_array.base16_decode(
      "7D0A2E6B7F7C65A236542630294E063B7AB9B555A5D5149AA21E4AE1E4FBCE87ECC8E08A8B5E350ABE622B2FFA617B202CFAD72032A3037E76FFDCDC4376EE053A190D7E46CA1DE04144850381B9CB29F051915386B8A710B8AC4D027B8B050F7CBA5854E028D564E453B8A968824173FC16488B8970CAC828F11AE53CABD20112F87107DF24EE6183D2274FE4C8B1485534EF2C5FBC1EC24BFC3663EFAA08BC047D29D25043532DB8391A8A3D776BF4372A6955827CCB0CDD4AF403A7CE4C63D595C75A43E045F0CCE1F29C8B93BD65AFC5974922F214A40B7C402CDB91AE73C0B63615CDAD0480680F16515A7ACE9D39236464328A37743FFC28F4DDB324F4D0F5BBDC270C65B1749A6EFFF1FBAA09536175CCD29FB9E6057B307320D316838A9C71F70B5B5907A66F7EA49AADC409",
    )

  let assert Ok(cipher) = stream.xchacha20(key, nonce:, counter: 1)
  let assert Ok(ciphertext) = stream.xor(cipher, plaintext)
  assert ciphertext == expected
  assert stream.xor(cipher, ciphertext) == Ok(plaintext)
}

// Property: XChaCha20 at counter 1 matches the XChaCha20-Poly1305 ciphertext
pub fn xchacha20_matches_aead_ciphertext_property_test() {
  use plaintext <- qcheck.given(qcheck.byte_aligned_bit_array())
  let key = crypto.random_bytes(32)
  let nonce = crypto.random_bytes(24)
  let assert Ok(ctx) = aead.xchacha20_poly1305(key)
  let assert Ok(#(expected, _tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(cipher) = stream.xchacha20(key, nonce:, counter: 1)
  assert stream.xor(cipher, plaintext) == Ok(expected)
}

// Property: XORing twice returns the original input
pub fn xchacha20_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.bounded_int(0, 0xFFFF_0000),
      qcheck.byte_aligned_bit_array(),
    )
  use #(counter, plaintext) <- qcheck.given(gen)
  let assert Ok(cipher) =
    stream.xchacha20(
      crypto.random_bytes(32),
      nonce: crypto.random_bytes(24),
      counter:,
    )
  let assert Ok(ciphertext) = stream.xor(cipher, plaintext)
  assert stream.xor(cipher, ciphertext) == Ok(plaintext)
}

// Property: ChaCha20 at counter 1 matches the ChaCha20-Poly1305 ciphertext
pub fn chacha20_matches_aead_ciphertext_property_test() {
  use plaintext <- qcheck.given(qcheck.byte_aligned_bit_array())
  let key = crypto.random_bytes(32)
  let nonce = crypto.random_bytes(12)
  let assert Ok(ctx) = aead.chacha20_poly1305(key)
  let assert Ok(#(expected, _tag)) = aead.seal(ctx, nonce:, plaintext:)
  let assert Ok(cipher) = stream.chacha20(key, nonce:, counter: 1)
  assert stream.xor(cipher, plaintext) == Ok(expected)
}

// Property: XORing twice returns the original input
pub fn chacha20_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.bounded_int(0, 0xFFFF_0000),
      qcheck.byte_aligned_bit_array(),
    )
  use #(counter, plaintext) <- qcheck.given(gen)
  let assert Ok(cipher) =
    stream.chacha20(
      crypto.random_bytes(32),
      nonce: crypto.random_bytes(12),
      counter:,
    )
  let assert Ok(ciphertext) = stream.xor(cipher, plaintext)
  assert stream.xor(cipher, ciphertext) == Ok(plaintext)
}

// Property: XORing n whole blocks then the rest at counter + n matches
// XORing everything at once
pub fn chacha20_counter_continuity_property_test() {
  let gen =
    qcheck.tuple3(
      qcheck.bounded_int(0, 0xFFFF_0000),
      qcheck.bounded_int(0, 4),
      qcheck.byte_aligned_bit_array(),
    )
  use #(counter, blocks, tail) <- qcheck.given(gen)
  let key = crypto.random_bytes(32)
  let nonce = crypto.random_bytes(12)
  let head = crypto.random_bytes(blocks * 64)
  let assert Ok(first) = stream.chacha20(key, nonce:, counter:)
  let assert Ok(rest) = stream.chacha20(key, nonce:, counter: counter + blocks)
  let assert Ok(expected) = stream.xor(first, <<head:bits, tail:bits>>)
  let assert Ok(head_ct) = stream.xor(first, head)
  let assert Ok(tail_ct) = stream.xor(rest, tail)
  assert <<head_ct:bits, tail_ct:bits>> == expected
}

pub fn chacha20_rejects_invalid_parameters_test() {
  let key = crypto.random_bytes(32)
  let nonce = crypto.random_bytes(12)
  assert stream.chacha20(crypto.random_bytes(31), nonce:, counter: 0)
    == Error(Nil)
  assert stream.chacha20(key, nonce: crypto.random_bytes(24), counter: 0)
    == Error(Nil)
  assert stream.chacha20(key, nonce:, counter: -1) == Error(Nil)
  assert stream.chacha20(key, nonce:, counter: 0x1_0000_0000) == Error(Nil)
}

pub fn xchacha20_rejects_invalid_parameters_test() {
  let key = crypto.random_bytes(32)
  let nonce = crypto.random_bytes(24)
  assert stream.xchacha20(crypto.random_bytes(31), nonce:, counter: 0)
    == Error(Nil)
  assert stream.xchacha20(key, nonce: crypto.random_bytes(12), counter: 0)
    == Error(Nil)
  assert stream.xchacha20(key, nonce:, counter: -1) == Error(Nil)
  assert stream.xchacha20(key, nonce:, counter: 0x1_0000_0000) == Error(Nil)
}

pub fn xor_rejects_counter_overflow_test() {
  let assert Ok(cipher) =
    stream.chacha20(
      crypto.random_bytes(32),
      nonce: crypto.random_bytes(12),
      counter: 0xFFFF_FFFF,
    )
  let assert Ok(_) = stream.xor(cipher, crypto.random_bytes(64))
  assert stream.xor(cipher, crypto.random_bytes(65)) == Error(Nil)
}
