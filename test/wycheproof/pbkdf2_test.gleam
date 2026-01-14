import gleam/bit_array
import gleam/dynamic/decode
import kryptos/crypto
import kryptos/hash
import wycheproof/utils.{Acceptable, Invalid, Valid}

type TestCase {
  TestCase(
    tc_id: Int,
    comment: String,
    password: String,
    salt: String,
    iteration_count: Int,
    dk_len: Int,
    dk: String,
    result: utils.TestResult,
  )
}

type TestGroup {
  TestGroup(tests: List(TestCase))
}

type TestFile {
  TestFile(algorithm: String, test_groups: List(TestGroup))
}

fn test_case_decoder() -> decode.Decoder(TestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use password <- decode.field("password", decode.string)
  use salt <- decode.field("salt", decode.string)
  use iteration_count <- decode.field("iterationCount", decode.int)
  use dk_len <- decode.field("dkLen", decode.int)
  use dk <- decode.field("dk", decode.string)
  use result <- decode.field("result", utils.test_result_decoder())
  decode.success(TestCase(
    tc_id:,
    comment:,
    password:,
    salt:,
    iteration_count:,
    dk_len:,
    dk:,
    result:,
  ))
}

fn test_group_decoder() -> decode.Decoder(TestGroup) {
  use tests <- decode.field("tests", decode.list(test_case_decoder()))
  decode.success(TestGroup(tests:))
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
  let assert Ok(password) = bit_array.base16_decode(tc.password)
  let assert Ok(salt) = bit_array.base16_decode(tc.salt)
  let assert Ok(expected_dk) = bit_array.base16_decode(tc.dk)
  let iterations = tc.iteration_count
  let length = tc.dk_len

  let result = crypto.pbkdf2(algorithm, password:, salt:, iterations:, length:)
  let context = utils.test_context(tc.tc_id, tc.comment)

  case tc.result {
    Valid | Acceptable -> {
      let assert Ok(computed) = result as context
      assert computed == expected_dk as context
    }
    Invalid -> {
      case result {
        Error(Nil) -> Nil
        Ok(computed) -> {
          assert computed != expected_dk as context
        }
      }
    }
  }
}

pub fn wycheproof_pbkdf2_hmacsha1_test() {
  run_wycheproof_tests("pbkdf2_hmacsha1_test.json", hash.Sha1)
}

pub fn wycheproof_pbkdf2_hmacsha256_test() {
  run_wycheproof_tests("pbkdf2_hmacsha256_test.json", hash.Sha256)
}

pub fn wycheproof_pbkdf2_hmacsha384_test() {
  run_wycheproof_tests("pbkdf2_hmacsha384_test.json", hash.Sha384)
}

pub fn wycheproof_pbkdf2_hmacsha512_test() {
  run_wycheproof_tests("pbkdf2_hmacsha512_test.json", hash.Sha512)
}
