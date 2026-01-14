import gleam/bit_array
import gleam/dynamic/decode
import gleam/option.{None, Some}
import kryptos/crypto
import kryptos/hash
import wycheproof/utils.{Acceptable, Invalid, Valid}

type TestCase {
  TestCase(
    tc_id: Int,
    comment: String,
    input: String,
    salt: String,
    info: String,
    size: Int,
    okm: String,
    result: utils.TestResult,
  )
}

type TestGroup {
  TestGroup(key_size: Int, tests: List(TestCase))
}

type TestFile {
  TestFile(algorithm: String, test_groups: List(TestGroup))
}

fn test_case_decoder() -> decode.Decoder(TestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use input <- decode.field("ikm", decode.string)
  use salt <- decode.field("salt", decode.string)
  use info <- decode.field("info", decode.string)
  use size <- decode.field("size", decode.int)
  use okm <- decode.field("okm", decode.string)
  use result <- decode.field("result", utils.test_result_decoder())
  decode.success(TestCase(
    tc_id:,
    comment:,
    input:,
    salt:,
    info:,
    size:,
    okm:,
    result:,
  ))
}

fn test_group_decoder() -> decode.Decoder(TestGroup) {
  use key_size <- decode.field("keySize", decode.int)
  use tests <- decode.field("tests", decode.list(test_case_decoder()))
  decode.success(TestGroup(key_size:, tests:))
}

fn test_file_decoder() -> decode.Decoder(TestFile) {
  use algorithm <- decode.field("algorithm", decode.string)
  use test_groups <- decode.field(
    "testGroups",
    decode.list(test_group_decoder()),
  )
  decode.success(TestFile(algorithm:, test_groups:))
}

fn run_wycheproof_tests(filename: String, algorithm: hash.HashAlgorithm) -> Nil {
  let assert Ok(test_file) = utils.load_test_file(filename, test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, fn(_group, tc) {
    run_single_test(algorithm, tc)
  })
}

fn run_single_test(algorithm: hash.HashAlgorithm, tc: TestCase) -> Nil {
  let assert Ok(input) = bit_array.base16_decode(tc.input)
  let assert Ok(salt_bytes) = bit_array.base16_decode(tc.salt)
  let assert Ok(info) = bit_array.base16_decode(tc.info)
  let assert Ok(expected_okm) = bit_array.base16_decode(tc.okm)
  let length = tc.size

  let salt = case salt_bytes {
    <<>> -> None
    _ -> Some(salt_bytes)
  }

  let result = crypto.hkdf(algorithm, input:, salt:, info:, length:)
  let context = utils.test_context(tc.tc_id, tc.comment)

  case tc.result {
    Valid | Acceptable -> {
      let assert Ok(computed) = result as context
      assert computed == expected_okm as context
    }
    Invalid -> {
      case result {
        Error(Nil) -> Nil
        Ok(computed) -> {
          assert computed != expected_okm as context
        }
      }
    }
  }
}

pub fn wycheproof_hkdf_sha1_test() {
  run_wycheproof_tests("hkdf_sha1_test.json", hash.Sha1)
}

pub fn wycheproof_hkdf_sha256_test() {
  run_wycheproof_tests("hkdf_sha256_test.json", hash.Sha256)
}

pub fn wycheproof_hkdf_sha384_test() {
  run_wycheproof_tests("hkdf_sha384_test.json", hash.Sha384)
}

pub fn wycheproof_hkdf_sha512_test() {
  run_wycheproof_tests("hkdf_sha512_test.json", hash.Sha512)
}
