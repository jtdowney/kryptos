import gleam/bit_array
import gleam/dynamic/decode
import kryptos/crypto
import kryptos/hash
import unitest
import wycheproof/utils.{Acceptable, Invalid, Valid}

type TestCase {
  TestCase(
    tc_id: Int,
    comment: String,
    key: String,
    msg: String,
    tag: String,
    result: utils.TestResult,
  )
}

type TestGroup {
  TestGroup(key_size: Int, tag_size: Int, tests: List(TestCase))
}

type TestFile {
  TestFile(algorithm: String, test_groups: List(TestGroup))
}

fn test_case_decoder() -> decode.Decoder(TestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use key <- decode.field("key", decode.string)
  use msg <- decode.field("msg", decode.string)
  use tag <- decode.field("tag", decode.string)
  use result <- decode.field("result", utils.test_result_decoder())
  decode.success(TestCase(tc_id:, comment:, key:, msg:, tag:, result:))
}

fn test_group_decoder() -> decode.Decoder(TestGroup) {
  use key_size <- decode.field("keySize", decode.int)
  use tag_size <- decode.field("tagSize", decode.int)
  use tests <- decode.field("tests", decode.list(test_case_decoder()))
  decode.success(TestGroup(key_size:, tag_size:, tests:))
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
  use <- unitest.guard(!hash.is_supported(algorithm))
  let assert Ok(test_file) = utils.load_test_file(filename, test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, fn(group, tc) {
    run_single_test(algorithm, group, tc)
  })
}

fn run_single_test(
  algorithm: hash.HashAlgorithm,
  group: TestGroup,
  tc: TestCase,
) -> Nil {
  let assert Ok(key) = bit_array.base16_decode(tc.key)
  let assert Ok(msg) = bit_array.base16_decode(tc.msg)
  let assert Ok(expected_tag) = bit_array.base16_decode(tc.tag)

  let assert Ok(computed) = crypto.hmac(algorithm, key, msg)
  let tag_bytes = group.tag_size / 8
  let assert Ok(truncated) = bit_array.slice(computed, 0, tag_bytes)
  let valid = crypto.constant_time_equal(truncated, expected_tag)

  let expected = case tc.result {
    Valid | Acceptable -> True
    Invalid -> False
  }
  assert valid == expected as utils.test_context(tc.tc_id, tc.comment)
}

pub fn wycheproof_hmac_sha1_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("hmac_sha1_test.json", hash.Sha1)
}

pub fn wycheproof_hmac_sha256_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("hmac_sha256_test.json", hash.Sha256)
}

pub fn wycheproof_hmac_sha384_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("hmac_sha384_test.json", hash.Sha384)
}

pub fn wycheproof_hmac_sha512_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("hmac_sha512_test.json", hash.Sha512)
}

pub fn wycheproof_hmac_sha512_224_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("hmac_sha512_224_test.json", hash.Sha512x224)
}

pub fn wycheproof_hmac_sha512_256_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("hmac_sha512_256_test.json", hash.Sha512x256)
}
