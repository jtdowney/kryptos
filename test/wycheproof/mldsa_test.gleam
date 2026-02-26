import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option, None, Some}
import kryptos/internal/mldsa as mldsa_internal
import kryptos/mldsa.{type ParameterSet, Mldsa44, Mldsa65, Mldsa87}
import unitest
import wycheproof/utils

type TestCase {
  TestCase(
    tc_id: Int,
    comment: String,
    msg: String,
    sig: String,
    ctx: Option(String),
    result: utils.TestResult,
  )
}

type TestGroup {
  TestGroup(public_key: String, tests: List(TestCase))
}

type TestFile {
  TestFile(test_groups: List(TestGroup))
}

fn test_case_decoder() -> decode.Decoder(TestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use msg <- decode.optional_field("msg", "", decode.string)
  use sig <- decode.field("sig", decode.string)
  use ctx <- decode.optional_field("ctx", None, decode.map(decode.string, Some))
  use result <- decode.field("result", utils.test_result_decoder())
  decode.success(TestCase(tc_id:, comment:, msg:, sig:, ctx:, result:))
}

fn test_group_decoder() -> decode.Decoder(TestGroup) {
  use public_key <- decode.field("publicKey", decode.string)
  use tests <- decode.field("tests", decode.list(test_case_decoder()))
  decode.success(TestGroup(public_key:, tests:))
}

fn test_file_decoder() -> decode.Decoder(TestFile) {
  use test_groups <- decode.field(
    "testGroups",
    decode.list(test_group_decoder()),
  )
  decode.success(TestFile(test_groups:))
}

fn has_non_empty_context(ctx: Option(String)) -> Bool {
  case ctx {
    Some(c) if c != "" -> True
    _ -> False
  }
}

fn run_single_test(param: ParameterSet, group: TestGroup, tc: TestCase) -> Nil {
  let context = utils.test_context(tc.tc_id, tc.comment)
  use <- bool.guard(has_non_empty_context(tc.ctx), Nil)

  let assert Ok(pk_bytes) = bit_array.base16_decode(group.public_key)
  let assert Ok(msg_bytes) = bit_array.base16_decode(tc.msg)
  let assert Ok(sig_bytes) = bit_array.base16_decode(tc.sig)

  case tc.result {
    utils.Invalid -> {
      case mldsa.public_key_from_bytes(param, pk_bytes) {
        Ok(pub_key) -> {
          assert !mldsa.verify(pub_key, msg_bytes, signature: sig_bytes)
            as { "ML-DSA verification succeeded for invalid test: " <> context }
        }
        Error(Nil) -> Nil
      }
    }
    utils.Valid -> {
      let assert Ok(pub_key) = mldsa.public_key_from_bytes(param, pk_bytes)
        as { "Public key import failed: " <> context }
      assert mldsa.verify(pub_key, msg_bytes, signature: sig_bytes)
        as { "ML-DSA verification failed for valid test: " <> context }
    }
    utils.Acceptable -> {
      case mldsa.public_key_from_bytes(param, pk_bytes) {
        Ok(pub_key) -> {
          let _ = mldsa.verify(pub_key, msg_bytes, signature: sig_bytes)
          Nil
        }
        Error(Nil) -> Nil
      }
    }
  }
}

fn run_verify_tests(filename: String, param: ParameterSet) -> Nil {
  let assert Ok(test_file) = utils.load_test_file(filename, test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, fn(group, tc) {
    run_single_test(param, group, tc)
  })
}

pub fn wycheproof_mldsa_44_verify_test() {
  use <- unitest.tag("wycheproof")
  run_verify_tests("mldsa_44_verify_test.json", Mldsa44)
}

pub fn wycheproof_mldsa_65_verify_test() {
  use <- unitest.tag("wycheproof")
  run_verify_tests("mldsa_65_verify_test.json", Mldsa65)
}

pub fn wycheproof_mldsa_87_verify_test() {
  use <- unitest.tag("wycheproof")
  run_verify_tests("mldsa_87_verify_test.json", Mldsa87)
}

type SeedTestGroup {
  SeedTestGroup(private_seed: String, public_key: String, tests: List(TestCase))
}

type SeedTestFile {
  SeedTestFile(test_groups: List(SeedTestGroup))
}

fn seed_test_group_decoder() -> decode.Decoder(SeedTestGroup) {
  use private_seed <- decode.field("privateSeed", decode.string)
  use public_key <- decode.field("publicKey", decode.string)
  use tests <- decode.field("tests", decode.list(test_case_decoder()))
  decode.success(SeedTestGroup(private_seed:, public_key:, tests:))
}

fn seed_test_file_decoder() -> decode.Decoder(SeedTestFile) {
  use test_groups <- decode.field(
    "testGroups",
    decode.list(seed_test_group_decoder()),
  )
  decode.success(SeedTestFile(test_groups:))
}

fn run_seed_sign_test(
  param: ParameterSet,
  group: SeedTestGroup,
  tc: TestCase,
) -> Nil {
  let context = utils.test_context(tc.tc_id, tc.comment)
  use <- bool.guard(has_non_empty_context(tc.ctx), Nil)
  use <- bool.guard(tc.msg == "", Nil)

  let assert Ok(pk_bytes) = bit_array.base16_decode(group.public_key)
  let assert Ok(msg_bytes) = bit_array.base16_decode(tc.msg)
  let assert Ok(sig_bytes) = bit_array.base16_decode(tc.sig)
  let assert Ok(pub_key) = mldsa.public_key_from_bytes(param, pk_bytes)

  case tc.result {
    utils.Valid -> {
      assert mldsa.verify(pub_key, msg_bytes, signature: sig_bytes)
        as { "Seed sign verification failed: " <> context }
    }
    utils.Invalid -> {
      assert !mldsa.verify(pub_key, msg_bytes, signature: sig_bytes)
        as { "Seed sign verification succeeded for invalid: " <> context }
    }
    utils.Acceptable -> {
      let _ = mldsa.verify(pub_key, msg_bytes, signature: sig_bytes)
      Nil
    }
  }
}

fn run_seed_sign_tests(filename: String, param: ParameterSet) -> Nil {
  let assert Ok(file) = utils.load_test_file(filename, seed_test_file_decoder())
  utils.run_tests(file.test_groups, fn(g) { g.tests }, fn(group, tc) {
    run_seed_sign_test(param, group, tc)
  })
}

pub fn wycheproof_mldsa_44_sign_seed_test() {
  use <- unitest.tag("wycheproof")
  run_seed_sign_tests("mldsa_44_sign_seed_test.json", Mldsa44)
}

pub fn wycheproof_mldsa_65_sign_seed_test() {
  use <- unitest.tag("wycheproof")
  run_seed_sign_tests("mldsa_65_sign_seed_test.json", Mldsa65)
}

pub fn wycheproof_mldsa_87_sign_seed_test() {
  use <- unitest.tag("wycheproof")
  run_seed_sign_tests("mldsa_87_sign_seed_test.json", Mldsa87)
}

fn run_keygen_test(filename: String, param: ParameterSet) -> Nil {
  let assert Ok(file) = utils.load_test_file(filename, seed_test_file_decoder())
  list.each(file.test_groups, fn(group) {
    let assert Ok(seed) = bit_array.base16_decode(group.private_seed)
    let assert Ok(expected_pk) = bit_array.base16_decode(group.public_key)
    let assert Ok(derived_pk) = mldsa_internal.public_key_from_seed(param, seed)
    assert derived_pk == expected_pk
  })
}

pub fn wycheproof_mldsa_44_keygen_from_seed_test() {
  use <- unitest.tag("wycheproof")
  run_keygen_test("mldsa_44_sign_seed_test.json", Mldsa44)
}

pub fn wycheproof_mldsa_65_keygen_from_seed_test() {
  use <- unitest.tag("wycheproof")
  run_keygen_test("mldsa_65_sign_seed_test.json", Mldsa65)
}

pub fn wycheproof_mldsa_87_keygen_from_seed_test() {
  use <- unitest.tag("wycheproof")
  run_keygen_test("mldsa_87_sign_seed_test.json", Mldsa87)
}

type NoseedTestCase {
  NoseedTestCase(
    tc_id: Int,
    comment: String,
    msg: Option(String),
    ctx: Option(String),
    sig: String,
    result: utils.TestResult,
  )
}

type NoseedTestGroup {
  NoseedTestGroup(
    private_key: String,
    public_key: Option(String),
    tests: List(NoseedTestCase),
  )
}

type NoseedTestFile {
  NoseedTestFile(test_groups: List(NoseedTestGroup))
}

fn noseed_test_case_decoder() -> decode.Decoder(NoseedTestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use msg <- decode.optional_field("msg", None, decode.map(decode.string, Some))
  use ctx <- decode.optional_field("ctx", None, decode.map(decode.string, Some))
  use sig <- decode.field("sig", decode.string)
  use result <- decode.field("result", utils.test_result_decoder())
  decode.success(NoseedTestCase(tc_id:, comment:, msg:, ctx:, sig:, result:))
}

fn noseed_test_group_decoder() -> decode.Decoder(NoseedTestGroup) {
  use private_key <- decode.field("privateKey", decode.string)
  use public_key <- decode.field("publicKey", decode.optional(decode.string))
  use tests <- decode.field("tests", decode.list(noseed_test_case_decoder()))
  decode.success(NoseedTestGroup(private_key:, public_key:, tests:))
}

fn noseed_test_file_decoder() -> decode.Decoder(NoseedTestFile) {
  use test_groups <- decode.field(
    "testGroups",
    decode.list(noseed_test_group_decoder()),
  )
  decode.success(NoseedTestFile(test_groups:))
}

fn run_noseed_sign_test(
  param: ParameterSet,
  group: NoseedTestGroup,
  tc: NoseedTestCase,
) -> Nil {
  let context = utils.test_context(tc.tc_id, tc.comment)

  use <- bool.guard(when: group.public_key == None, return: Nil)
  let assert Some(pk_hex) = group.public_key

  use <- bool.guard(when: tc.msg == None, return: Nil)
  let assert Some(msg_hex) = tc.msg

  use <- bool.guard(when: has_non_empty_context(tc.ctx), return: Nil)

  let assert Ok(pk_bytes) = bit_array.base16_decode(pk_hex)
  let assert Ok(msg_bytes) = bit_array.base16_decode(msg_hex)
  let assert Ok(sig_bytes) = bit_array.base16_decode(tc.sig)

  case mldsa.public_key_from_bytes(param, pk_bytes) {
    Ok(pub_key) -> {
      case tc.result {
        utils.Valid -> {
          assert mldsa.verify(pub_key, msg_bytes, signature: sig_bytes)
            as { "Noseed sign verification failed: " <> context }
        }
        utils.Invalid -> {
          assert !mldsa.verify(pub_key, msg_bytes, signature: sig_bytes)
            as { "Noseed sign verification succeeded for invalid: " <> context }
        }
        utils.Acceptable -> {
          let _ = mldsa.verify(pub_key, msg_bytes, signature: sig_bytes)
          Nil
        }
      }
    }
    Error(Nil) -> {
      case tc.result {
        utils.Valid ->
          panic as { "Public key import failed for valid test: " <> context }
        _ -> Nil
      }
    }
  }
}

fn run_noseed_sign_tests(filename: String, param: ParameterSet) -> Nil {
  let assert Ok(file) =
    utils.load_test_file(filename, noseed_test_file_decoder())
  utils.run_tests(file.test_groups, fn(g) { g.tests }, fn(group, tc) {
    run_noseed_sign_test(param, group, tc)
  })
}

pub fn wycheproof_mldsa_44_sign_noseed_test() {
  use <- unitest.tag("wycheproof")
  run_noseed_sign_tests("mldsa_44_sign_noseed_test.json", Mldsa44)
}

pub fn wycheproof_mldsa_65_sign_noseed_test() {
  use <- unitest.tag("wycheproof")
  run_noseed_sign_tests("mldsa_65_sign_noseed_test.json", Mldsa65)
}

pub fn wycheproof_mldsa_87_sign_noseed_test() {
  use <- unitest.tag("wycheproof")
  run_noseed_sign_tests("mldsa_87_sign_noseed_test.json", Mldsa87)
}
