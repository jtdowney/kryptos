import gleam/bit_array
import gleam/dynamic/decode
import kryptos/eddsa
import wycheproof/utils

type TestResult {
  Valid
  Acceptable
  Invalid
}

type PublicKeyInfo {
  PublicKeyInfo(curve: String, pk: String)
}

type TestCase {
  TestCase(
    tc_id: Int,
    comment: String,
    msg: String,
    sig: String,
    result: TestResult,
  )
}

type TestGroup {
  TestGroup(public_key: PublicKeyInfo, tests: List(TestCase))
}

type TestFile {
  TestFile(test_groups: List(TestGroup))
}

fn test_result_decoder() -> decode.Decoder(TestResult) {
  use value <- decode.then(decode.string)
  case value {
    "valid" -> decode.success(Valid)
    "acceptable" -> decode.success(Acceptable)
    "invalid" -> decode.success(Invalid)
    _ -> decode.failure(Invalid, "TestResult")
  }
}

fn public_key_decoder() -> decode.Decoder(PublicKeyInfo) {
  use curve <- decode.field("curve", decode.string)
  use pk <- decode.field("pk", decode.string)
  decode.success(PublicKeyInfo(curve:, pk:))
}

fn test_case_decoder() -> decode.Decoder(TestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use msg <- decode.field("msg", decode.string)
  use sig <- decode.field("sig", decode.string)
  use result <- decode.field("result", test_result_decoder())
  decode.success(TestCase(tc_id:, comment:, msg:, sig:, result:))
}

fn test_group_decoder() -> decode.Decoder(TestGroup) {
  use public_key <- decode.field("publicKey", public_key_decoder())
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

fn curve_from_name(name: String) -> Result(eddsa.Curve, Nil) {
  case name {
    "edwards25519" -> Ok(eddsa.Ed25519)
    "edwards448" -> Ok(eddsa.Ed448)
    _ -> Error(Nil)
  }
}

fn run_single_test(group: TestGroup, tc: TestCase) -> Nil {
  let context = utils.test_context(tc.tc_id, tc.comment)

  let assert Ok(curve) = curve_from_name(group.public_key.curve)
  let assert Ok(pk_bytes) = bit_array.base16_decode(group.public_key.pk)
  let assert Ok(msg_bytes) = bit_array.base16_decode(tc.msg)
  let assert Ok(sig_bytes) = bit_array.base16_decode(tc.sig)

  case tc.result {
    Invalid -> {
      case eddsa.public_key_from_bytes(curve, pk_bytes) {
        Ok(pub_key) -> {
          assert !eddsa.verify(pub_key, msg_bytes, sig_bytes)
            as { "EdDSA verification succeeded for invalid test: " <> context }
        }
        Error(Nil) -> Nil
      }
    }
    Valid -> {
      let assert Ok(pub_key) = eddsa.public_key_from_bytes(curve, pk_bytes)
        as { "Public key import failed: " <> context }
      assert eddsa.verify(pub_key, msg_bytes, sig_bytes)
        as { "EdDSA verification failed for valid test: " <> context }
    }
    Acceptable -> {
      case eddsa.public_key_from_bytes(curve, pk_bytes) {
        Ok(pub_key) -> {
          let _ = eddsa.verify(pub_key, msg_bytes, sig_bytes)
          Nil
        }
        Error(Nil) -> Nil
      }
    }
  }
}

pub fn wycheproof_ed25519_test() {
  let assert Ok(test_file) =
    utils.load_test_file("ed25519_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}

pub fn wycheproof_ed448_test() {
  let assert Ok(test_file) =
    utils.load_test_file("ed448_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}
