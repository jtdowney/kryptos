import gleam/bit_array
import gleam/list
import gleam/set
import gleam/string
import kryptos/crypto
import kryptos/hash
import qcheck

// Property: random_bytes(n) always returns exactly n bytes
pub fn random_bytes_length_property_test() {
  qcheck.run(qcheck.default_config(), qcheck.bounded_int(0, 1000), fn(size) {
    let bytes = crypto.random_bytes(size)
    assert bit_array.byte_size(bytes) == size
  })
}

// Edge case: negative sizes are handled gracefully
pub fn random_bytes_negative_test() {
  let bytes = crypto.random_bytes(-1)
  assert bit_array.byte_size(bytes) == 0
}

// Property: constant_time_equal is reflexive (a == a)
pub fn constant_time_equal_reflexive_property_test() {
  qcheck.run(qcheck.default_config(), qcheck.byte_aligned_bit_array(), fn(data) {
    assert crypto.constant_time_equal(data, data)
  })
}

// Property: constant_time_equal is symmetric (a == b implies b == a)
pub fn constant_time_equal_symmetric_property_test() {
  qcheck.run(
    qcheck.default_config(),
    qcheck.tuple2(
      qcheck.byte_aligned_bit_array(),
      qcheck.byte_aligned_bit_array(),
    ),
    fn(input) {
      let #(a, b) = input
      assert crypto.constant_time_equal(a, b)
        == crypto.constant_time_equal(b, a)
    },
  )
}

// Edge case: length mismatch always returns false
pub fn constant_time_equal_length_mismatch_test() {
  assert !crypto.constant_time_equal(<<"short":utf8>>, <<"longer":utf8>>)
  assert !crypto.constant_time_equal(<<>>, <<"nonempty":utf8>>)
}

// Property: UUIDs are always unique
pub fn uuid_uniqueness_property_test() {
  qcheck.run(qcheck.default_config(), qcheck.bounded_int(10, 100), fn(count) {
    let uuids = list.map(list.range(1, count), fn(_) { crypto.random_uuid() })
    let unique = set.from_list(uuids)
    assert set.size(unique) == count
  })
}

// Property: UUID format is always valid (version 4, correct structure)
pub fn uuid_format_property_test() {
  // Run 100 times to test format consistency
  list.each(list.range(1, 100), fn(_) {
    let uuid = crypto.random_uuid()

    // Length check
    assert string.length(uuid) == 36

    // Structure check (8-4-4-4-12)
    let parts = string.split(uuid, "-")
    assert list.length(parts) == 5

    let assert [p1, p2, p3, p4, p5] = parts
    assert string.length(p1) == 8
    assert string.length(p2) == 4
    assert string.length(p3) == 4
    assert string.length(p4) == 4
    assert string.length(p5) == 12

    // Version check (must be "4")
    let assert Ok(version_char) = string.first(string.drop_start(uuid, 14))
    assert version_char == "4"

    // Variant check (must be 8, 9, a, or b)
    let assert Ok(variant_char) = string.first(string.drop_start(uuid, 19))
    assert variant_char == "8"
      || variant_char == "9"
      || variant_char == "a"
      || variant_char == "b"
  })
}

// Property: Concat KDF output length matches requested length
pub fn concat_kdf_output_length_property_test() {
  let gen =
    qcheck.tuple3(
      qcheck.from_generators(qcheck.return(hash.Sha256), [
        qcheck.return(hash.Sha512),
        qcheck.return(hash.Sha1),
        qcheck.return(hash.Sha3x256),
      ]),
      qcheck.non_empty_byte_aligned_bit_array(),
      qcheck.bounded_int(1, 255),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(algorithm, secret, length) = input
    let assert Ok(result) =
      crypto.concat_kdf(algorithm, secret:, info: <<>>, length:)
    assert bit_array.byte_size(result) == length
  })
}

// Property: Concat KDF is deterministic - same inputs produce same output
pub fn concat_kdf_deterministic_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.non_empty_byte_aligned_bit_array(),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(secret, info) = input
    let length = 32

    let assert Ok(result1) =
      crypto.concat_kdf(hash.Sha256, secret:, info:, length:)
    let assert Ok(result2) =
      crypto.concat_kdf(hash.Sha256, secret:, info:, length:)

    assert result1 == result2
  })
}

// Test vectors from patrickfav/singlestep-kdf (NIST SP 800-56C Rev1 non-official vectors)
// https://github.com/patrickfav/singlestep-kdf/wiki/NIST-SP-800-56C-Rev1:-Non-Official-Test-Vectors
pub fn concat_kdf_sha256_test_vector_1_test() {
  let assert Ok(secret) =
    bit_array.base16_decode("AFC4E154498D4770AA8365F6903DC83B")
  let assert Ok(info) = bit_array.base16_decode("662AF20379B29D5EF813E655")
  let length = 16

  let assert Ok(result) =
    crypto.concat_kdf(hash.Sha256, secret:, info:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode("F0B80D6AE4C1E19E2105A37024E35DC6")
  assert result == expected
}

pub fn concat_kdf_sha256_test_vector_2_test() {
  let assert Ok(secret) =
    bit_array.base16_decode("A3CE8D61D699AD150E196A7AB6736A63")
  let assert Ok(info) = bit_array.base16_decode("CE5CD95A44EE83A8FB83F34C")
  let length = 16

  let assert Ok(result) =
    crypto.concat_kdf(hash.Sha256, secret:, info:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode("5DB3455A22B65EDFCFDE3DA3E8D724CD")
  assert result == expected
}

pub fn concat_kdf_sha256_test_vector_3_test() {
  let assert Ok(secret) =
    bit_array.base16_decode("A9723E56045F0847FDD9C1C78781C8B7")
  let assert Ok(info) = bit_array.base16_decode("E69B6005B78F7D42D0A8ED2A")
  let length = 16

  let assert Ok(result) =
    crypto.concat_kdf(hash.Sha256, secret:, info:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode("AC3878B8CF357976F7FD8266923E1882")
  assert result == expected
}

pub fn concat_kdf_sha256_test_vector_4_test() {
  let assert Ok(secret) =
    bit_array.base16_decode("A07A5E8DF7EE1B2CE2A3D1348EDFA8AB")
  let assert Ok(info) = bit_array.base16_decode("E22A8EE34296DD39B56B31FB")
  let length = 16

  let assert Ok(result) =
    crypto.concat_kdf(hash.Sha256, secret:, info:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode("70927D218B6D119268381E9930A4F256")
  assert result == expected
}

pub fn concat_kdf_sha384_test() {
  let secret = <<"shared secret":utf8>>
  let info = <<"application info":utf8>>
  let length = 48

  let assert Ok(result) =
    crypto.concat_kdf(hash.Sha384, secret:, info:, length:)

  assert bit_array.byte_size(result) == 48
}

pub fn concat_kdf_sha512_test() {
  let secret = <<"shared secret":utf8>>
  let info = <<"application info":utf8>>
  let length = 64

  let assert Ok(result) =
    crypto.concat_kdf(hash.Sha512, secret:, info:, length:)

  assert bit_array.byte_size(result) == 64
}

pub fn concat_kdf_sha3_256_test() {
  let secret = <<"shared secret":utf8>>
  let info = <<"application info":utf8>>
  let length = 32

  let assert Ok(result) =
    crypto.concat_kdf(hash.Sha3x256, secret:, info:, length:)

  assert bit_array.byte_size(result) == 32
}

pub fn concat_kdf_multi_block_test() {
  let secret = <<"test secret":utf8>>
  let info = <<>>
  let length = 100

  let assert Ok(result) =
    crypto.concat_kdf(hash.Sha256, secret:, info:, length:)

  assert bit_array.byte_size(result) == 100
}

pub fn concat_kdf_unsupported_algorithm_md5_test() {
  let secret = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let info = <<>>
  let length = 32

  assert crypto.concat_kdf(hash.Md5, secret, info, length) == Error(Nil)
}

pub fn concat_kdf_unsupported_algorithm_blake2s_test() {
  let secret = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let info = <<>>
  let length = 32

  assert crypto.concat_kdf(hash.Blake2s, secret, info, length) == Error(Nil)
}

pub fn concat_kdf_length_too_large_test() {
  let secret = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let info = <<>>

  let length = 255 * 32 + 1
  assert crypto.concat_kdf(hash.Sha256, secret, info, length) == Error(Nil)

  let length = 255 * 20 + 1
  assert crypto.concat_kdf(hash.Sha1, secret, info, length) == Error(Nil)
}

pub fn concat_kdf_zero_length_test() {
  let secret = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let info = <<>>
  let length = 0

  assert crypto.concat_kdf(hash.Sha256, secret, info, length) == Error(Nil)
}

pub fn concat_kdf_empty_other_info_test() {
  let secret = <<"secret":utf8>>
  let info = <<>>
  let length = 32

  let assert Ok(result) = crypto.concat_kdf(hash.Sha256, secret, info, length)

  assert bit_array.byte_size(result) == 32
}

pub fn concat_kdf_different_other_info_produces_different_output_test() {
  let secret = <<"shared secret":utf8>>
  let length = 32

  let assert Ok(result1) =
    crypto.concat_kdf(hash.Sha256, secret:, info: <<"info1":utf8>>, length:)
  let assert Ok(result2) =
    crypto.concat_kdf(hash.Sha256, secret:, info: <<"info2":utf8>>, length:)

  assert result1 != result2
}
