import gleam/bit_array
import kryptos/crypto
import kryptos/hash
import qcheck

// Property: PBKDF2 output length matches requested length
pub fn pbkdf2_output_length_property_test() {
  let gen =
    qcheck.tuple3(
      qcheck.from_generators(qcheck.return(hash.Sha256), [
        qcheck.return(hash.Sha512),
        qcheck.return(hash.Sha1),
      ]),
      qcheck.non_empty_byte_aligned_bit_array(),
      qcheck.bounded_int(1, 128),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(algorithm, password, length) = input
    let salt = <<"salt":utf8>>
    let iterations = 1

    let assert Ok(result) =
      crypto.pbkdf2(algorithm, password:, salt:, iterations:, length:)
    assert bit_array.byte_size(result) == length
  })
}

// Property: PBKDF2 is deterministic - same inputs produce same output
pub fn pbkdf2_deterministic_property_test() {
  let gen =
    qcheck.tuple3(
      qcheck.non_empty_byte_aligned_bit_array(),
      qcheck.non_empty_byte_aligned_bit_array(),
      qcheck.bounded_int(1, 10),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(password, salt, iterations) = input
    let length = 32

    let assert Ok(result1) =
      crypto.pbkdf2(hash.Sha256, password:, salt:, iterations:, length:)
    let assert Ok(result2) =
      crypto.pbkdf2(hash.Sha256, password:, salt:, iterations:, length:)

    assert result1 == result2
  })
}

// RFC 6070 Test Vectors for PBKDF2-HMAC-SHA1

// Test Case 1: 1 iteration
pub fn pbkdf2_sha1_rfc6070_test_case_1_test() {
  let password = <<"password">>
  let salt = <<"salt">>
  let iterations = 1
  let length = 20

  let assert Ok(result) =
    crypto.pbkdf2(hash.Sha1, password:, salt:, iterations:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode("0C60C80F961F0E71F3A9B524AF6012062FE037A6")
  assert result == expected
}

// Test Case 2: 2 iterations
pub fn pbkdf2_sha1_rfc6070_test_case_2_test() {
  let password = <<"password">>
  let salt = <<"salt">>
  let iterations = 2
  let length = 20

  let assert Ok(result) =
    crypto.pbkdf2(hash.Sha1, password:, salt:, iterations:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode("EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957")
  assert result == expected
}

// Test Case 3: 4096 iterations
pub fn pbkdf2_sha1_rfc6070_test_case_3_test() {
  let password = <<"password">>
  let salt = <<"salt">>
  let iterations = 4096
  let length = 20

  let assert Ok(result) =
    crypto.pbkdf2(hash.Sha1, password:, salt:, iterations:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode("4B007901B765489ABEAD49D926F721D065A429C1")
  assert result == expected
}

// Test Case 5: longer password and salt, 25 byte output
pub fn pbkdf2_sha1_rfc6070_test_case_5_test() {
  let password = <<"passwordPASSWORDpassword">>
  let salt = <<"saltSALTsaltSALTsaltSALTsaltSALTsalt">>
  let iterations = 4096
  let length = 25

  let assert Ok(result) =
    crypto.pbkdf2(hash.Sha1, password:, salt:, iterations:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode(
      "3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038",
    )
  assert result == expected
}

// Test Case 6: password and salt with null bytes
pub fn pbkdf2_sha1_rfc6070_test_case_6_test() {
  // "pass\0word" and "sa\0lt" with embedded null bytes
  let password = <<"pass", 0, "word">>
  let salt = <<"sa", 0, "lt">>
  let iterations = 4096
  let length = 16

  let assert Ok(result) =
    crypto.pbkdf2(hash.Sha1, password:, salt:, iterations:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode("56FA6AA75548099DCC37D7F03425E0C3")
  assert result == expected
}

// Test SHA-256
pub fn pbkdf2_sha256_test() {
  let password = <<"password">>
  let salt = <<"salt">>
  let iterations = 1
  let length = 32

  let assert Ok(result) =
    crypto.pbkdf2(hash.Sha256, password:, salt:, iterations:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode(
      "120FB6CFFCF8B32C43E7225256C4F837A86548C92CCC35480805987CB70BE17B",
    )
  assert result == expected
}

// Test SHA-512
pub fn pbkdf2_sha512_test() {
  let password = <<"password">>
  let salt = <<"salt">>
  let iterations = 1
  let length = 64

  let assert Ok(result) =
    crypto.pbkdf2(hash.Sha512, password:, salt:, iterations:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode(
      "867F70CF1ADE02CFF3752599A3A53DC4AF34C7A669815AE5D513554E1C8CF252C02D470A285A0501BAD999BFE943C08F050235D7D68B1DA55E63F73B60A57FCE",
    )
  assert result == expected
}

pub fn unsupported_algorithm_test() {
  let password = <<"password">>
  let salt = <<"salt">>
  let iterations = 1
  let length = 32

  assert crypto.pbkdf2(hash.Blake2b, password:, salt:, iterations:, length:)
    == Error(Nil)
}
