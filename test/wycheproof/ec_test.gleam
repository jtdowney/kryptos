import gleam/bit_array
import gleam/dynamic/decode
import kryptos/ec
import kryptos/ecdh
import kryptos/internal/ec as internal_ec
import unitest
import wycheproof/utils

type TestResult {
  Valid
  Acceptable
  Invalid
}

type TestCase {
  TestCase(
    tc_id: Int,
    comment: String,
    public: String,
    private: String,
    shared: String,
    result: TestResult,
  )
}

type TestGroup {
  TestGroup(curve: String, tests: List(TestCase))
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

fn test_case_decoder() -> decode.Decoder(TestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use public <- decode.field("public", decode.string)
  use private <- decode.field("private", decode.string)
  use shared <- decode.field("shared", decode.string)
  use result <- decode.field("result", test_result_decoder())
  decode.success(TestCase(tc_id:, comment:, public:, private:, shared:, result:))
}

fn test_group_decoder() -> decode.Decoder(TestGroup) {
  use curve <- decode.field("curve", decode.string)
  use tests <- decode.field("tests", decode.list(test_case_decoder()))
  decode.success(TestGroup(curve:, tests:))
}

fn test_file_decoder() -> decode.Decoder(TestFile) {
  use test_groups <- decode.field(
    "testGroups",
    decode.list(test_group_decoder()),
  )
  decode.success(TestFile(test_groups:))
}

fn curve_from_name(name: String) -> Result(ec.Curve, Nil) {
  case name {
    "secp256r1" -> Ok(ec.P256)
    "secp384r1" -> Ok(ec.P384)
    "secp521r1" -> Ok(ec.P521)
    "secp256k1" -> Ok(ec.Secp256k1)
    _ -> Error(Nil)
  }
}

fn run_single_test(group: TestGroup, tc: TestCase) -> Nil {
  case curve_from_name(group.curve) {
    Error(Nil) -> Nil
    Ok(curve) -> run_test_for_curve(curve, tc)
  }
}

fn run_test_for_curve(curve: ec.Curve, tc: TestCase) -> Nil {
  let context = utils.test_context(tc.tc_id, tc.comment)
  let assert Ok(public_point) = bit_array.base16_decode(tc.public)
  let assert Ok(private_bytes) = bit_array.base16_decode(tc.private)
  let assert Ok(expected_shared) = bit_array.base16_decode(tc.shared)

  let pub_key_result = ec.public_key_from_raw_point(curve, public_point)
  let priv_key_result = internal_ec.private_key_from_bytes(curve, private_bytes)

  case tc.result, pub_key_result, priv_key_result {
    Invalid, Ok(peer_pub), Ok(#(priv_key, _)) ->
      case ecdh.compute_shared_secret(priv_key, peer_pub) {
        Error(Nil) -> Nil
        Ok(shared) -> {
          assert shared != expected_shared
            as { "ECDH succeeded for invalid test: " <> context }
        }
      }
    Invalid, _, _ -> Nil

    Valid, Ok(peer_pub), Ok(#(priv_key, _)) -> {
      let assert Ok(shared) = ecdh.compute_shared_secret(priv_key, peer_pub)
      assert shared == expected_shared as context
    }
    Valid, _, _ -> panic as { "Key import failed for valid test: " <> context }

    Acceptable, Ok(peer_pub), Ok(#(priv_key, _)) ->
      case ecdh.compute_shared_secret(priv_key, peer_pub) {
        Ok(shared) -> {
          assert shared == expected_shared as context
        }
        Error(Nil) -> Nil
      }
    Acceptable, _, _ -> Nil
  }
}

pub fn wycheproof_ec_ecpoint_secp256r1_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "ecdh_secp256r1_ecpoint_test.json",
      test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}

pub fn wycheproof_ec_ecpoint_secp384r1_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "ecdh_secp384r1_ecpoint_test.json",
      test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}

pub fn wycheproof_ec_ecpoint_secp521r1_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "ecdh_secp521r1_ecpoint_test.json",
      test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}
