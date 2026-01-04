import gleam/bit_array
import gleam/option.{None, Some}
import kryptos/hash
import kryptos/hkdf

// RFC 5869 Appendix A - Test Case 1 (SHA-256)
pub fn hkdf_sha256_rfc5869_test_case_1_test() {
  let assert Ok(input) =
    bit_array.base16_decode("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
  let assert Ok(salt) = bit_array.base16_decode("000102030405060708090A0B0C")
  let assert Ok(info) = bit_array.base16_decode("F0F1F2F3F4F5F6F7F8F9")
  let length = 42

  let assert Ok(result) =
    hkdf.compute(hash.Sha256, input:, salt: Some(salt), info:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode(
      "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865",
    )
  assert result == expected
}

// RFC 5869 Appendix A - Test Case 2 (SHA-256, longer inputs/outputs)
pub fn hkdf_sha256_rfc5869_test_case_2_test() {
  let assert Ok(input) =
    bit_array.base16_decode(
      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
    )
  let assert Ok(salt) =
    bit_array.base16_decode(
      "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF",
    )
  let assert Ok(info) =
    bit_array.base16_decode(
      "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
    )
  let length = 82

  let assert Ok(result) =
    hkdf.compute(hash.Sha256, input:, salt: Some(salt), info:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode(
      "B11E398DC80327A1C8E7F78C596A49344F012EDA2D4EFAD8A050CC4C19AFA97C59045A99CAC7827271CB41C65E590E09DA3275600C2F09B8367793A9ACA3DB71CC30C58179EC3E87C14C01D5C1F3434F1D87",
    )
  assert result == expected
}

// RFC 5869 Appendix A - Test Case 3 (SHA-256, zero-length salt and info)
pub fn hkdf_sha256_rfc5869_test_case_3_test() {
  let assert Ok(input) =
    bit_array.base16_decode("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
  let info = <<>>
  let length = 42

  let assert Ok(result) =
    hkdf.compute(hash.Sha256, input:, salt: None, info:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode(
      "8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D9D201395FAA4B61A96C8",
    )
  assert result == expected
}

// RFC 5869 Appendix A - Test Case 4 (SHA-1)
pub fn hkdf_sha1_rfc5869_test_case_4_test() {
  let assert Ok(input) = bit_array.base16_decode("0B0B0B0B0B0B0B0B0B0B0B")
  let assert Ok(salt) = bit_array.base16_decode("000102030405060708090A0B0C")
  let assert Ok(info) = bit_array.base16_decode("F0F1F2F3F4F5F6F7F8F9")
  let length = 42

  let assert Ok(result) =
    hkdf.compute(hash.Sha1, input:, salt: Some(salt), info:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode(
      "085A01EA1B10F36933068B56EFA5AD81A4F14B822F5B091568A9CDD4F155FDA2C22E422478D305F3F896",
    )
  assert result == expected
}

// RFC 5869 Appendix A - Test Case 5 (SHA-1, longer inputs/outputs)
pub fn hkdf_sha1_rfc5869_test_case_5_test() {
  let assert Ok(input) =
    bit_array.base16_decode(
      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F",
    )
  let assert Ok(salt) =
    bit_array.base16_decode(
      "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF",
    )
  let assert Ok(info) =
    bit_array.base16_decode(
      "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
    )
  let length = 82

  let assert Ok(result) =
    hkdf.compute(hash.Sha1, input:, salt: Some(salt), info:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode(
      "0BD770A74D1160F7C9F12CD5912A06EBFF6ADCAE899D92191FE4305673BA2FFE8FA3F1A4E5AD79F3F334B3B202B2173C486EA37CE3D397ED034C7F9DFEB15C5E927336D0441F4C4300E2CFF0D0900B52D3B4",
    )
  assert result == expected
}

// RFC 5869 Appendix A - Test Case 6 (SHA-1, zero-length salt and info)
pub fn hkdf_sha1_rfc5869_test_case_6_test() {
  let assert Ok(input) =
    bit_array.base16_decode("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
  let info = <<>>
  let length = 42

  let assert Ok(result) =
    hkdf.compute(hash.Sha1, input:, salt: None, info:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode(
      "0AC1AF7002B3D761D1E55298DA9D0506B9AE52057220A306E07B6B87E8DF21D0EA00033DE03984D34918",
    )
  assert result == expected
}

// RFC 5869 Appendix A - Test Case 7 (SHA-1, zero-length salt, not provided)
pub fn hkdf_sha1_rfc5869_test_case_7_test() {
  let assert Ok(input) =
    bit_array.base16_decode("0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C")
  let info = <<>>
  let length = 42

  let assert Ok(result) =
    hkdf.compute(hash.Sha1, input:, salt: None, info:, length:)

  let assert Ok(expected) =
    bit_array.base16_decode(
      "2C91117204D745F3500D636A62F64F0AB3BAE548AA53D423B0D1F27EBBA6F5E5673A081D70CCE7ACFC48",
    )
  assert result == expected
}

// Test unsupported algorithm
pub fn unsupported_algorithm_test() {
  let input = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let info = <<>>
  let length = 32

  // BLAKE2b is not supported for HKDF
  assert hkdf.compute(hash.Blake2b, input:, salt: None, info:, length:)
    == Error(Nil)
  assert hkdf.compute(hash.Blake2s, input:, salt: None, info:, length:)
    == Error(Nil)
  assert hkdf.compute(hash.Sha3x256, input:, salt: None, info:, length:)
    == Error(Nil)
}

// Test length too large
pub fn length_too_large_test() {
  let input = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let info = <<>>

  // SHA-256 has hash length 32, so max is 255 * 32 = 8160
  let length = 255 * 32 + 1
  assert hkdf.compute(hash.Sha256, input:, salt: None, info:, length:)
    == Error(Nil)

  // SHA-1 has hash length 20, so max is 255 * 20 = 5100
  let length = 255 * 20 + 1
  assert hkdf.compute(hash.Sha1, input:, salt: None, info:, length:)
    == Error(Nil)
}

// Test zero length
pub fn zero_length_test() {
  let input = <<1, 2, 3, 4, 5, 6, 7, 8>>
  let info = <<>>
  let length = 0

  assert hkdf.compute(hash.Sha256, input:, salt: None, info:, length:)
    == Error(Nil)
}
