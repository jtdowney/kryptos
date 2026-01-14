import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/result
import kryptos/xdh
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

fn curve_from_name(name: String) -> Result(xdh.Curve, Nil) {
  case name {
    "curve25519" -> Ok(xdh.X25519)
    "curve448" -> Ok(xdh.X448)
    _ -> Error(Nil)
  }
}

fn run_single_test(group: TestGroup, tc: TestCase) -> Nil {
  let curve_result = curve_from_name(group.curve)
  use <- bool.guard(result.is_error(curve_result), Nil)
  let assert Ok(curve) = curve_result

  run_test_for_curve(curve, tc)
}

fn run_test_for_curve(curve: xdh.Curve, tc: TestCase) -> Nil {
  let context = utils.test_context(tc.tc_id, tc.comment)
  let assert Ok(public_bytes) = bit_array.base16_decode(tc.public)
  let assert Ok(private_bytes) = bit_array.base16_decode(tc.private)
  let assert Ok(expected_shared) = bit_array.base16_decode(tc.shared)

  let pub_key_result = xdh.public_key_from_bytes(curve, public_bytes)
  let priv_key_result = xdh.from_bytes(curve, private_bytes)

  case tc.result, pub_key_result, priv_key_result {
    Invalid, Ok(peer_pub), Ok(#(priv_key, _)) ->
      case xdh.compute_shared_secret(priv_key, peer_pub) {
        Error(Nil) -> Nil
        Ok(shared) -> {
          assert shared != expected_shared
            as { "XDH succeeded for invalid test: " <> context }
        }
      }
    Invalid, _, _ -> Nil

    Valid, Ok(peer_pub), Ok(#(priv_key, my_pub)) -> {
      let assert Ok(shared) = xdh.compute_shared_secret(priv_key, peer_pub)
      assert shared == expected_shared as context

      let exported_priv = xdh.to_bytes(priv_key)
      assert exported_priv == private_bytes
        as { "Private key roundtrip failed: " <> context }

      let exported_peer_pub = xdh.public_key_to_bytes(peer_pub)
      assert exported_peer_pub == public_bytes
        as { "Peer public key roundtrip failed: " <> context }

      let exported_my_pub = xdh.public_key_to_bytes(my_pub)
      let assert Ok(reimported_pub) =
        xdh.public_key_from_bytes(curve, exported_my_pub)
      let exported_again = xdh.public_key_to_bytes(reimported_pub)
      assert exported_my_pub == exported_again
        as { "Own public key roundtrip failed: " <> context }
    }
    Valid, _, _ -> panic as { "Key import failed for valid test: " <> context }

    Acceptable, Ok(peer_pub), Ok(#(priv_key, _)) ->
      case xdh.compute_shared_secret(priv_key, peer_pub) {
        Ok(shared) -> {
          assert shared == expected_shared as context
        }
        Error(Nil) -> Nil
      }
    Acceptable, _, _ -> Nil
  }
}

pub fn wycheproof_x25519_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("x25519_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}

pub fn wycheproof_x448_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("x448_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}

fn run_asn_test(group: TestGroup, tc: TestCase) -> Nil {
  let curve_result = curve_from_name(group.curve)
  use <- bool.guard(result.is_error(curve_result), Nil)

  let context = utils.test_context(tc.tc_id, tc.comment)
  let assert Ok(public_der) = bit_array.base16_decode(tc.public)
  let assert Ok(private_der) = bit_array.base16_decode(tc.private)
  let assert Ok(expected_shared) = bit_array.base16_decode(tc.shared)

  let pub_key_result = xdh.public_key_from_der(public_der)
  let priv_key_result = xdh.from_der(private_der)

  case tc.result, pub_key_result, priv_key_result {
    Invalid, Ok(peer_pub), Ok(#(priv_key, _)) ->
      case xdh.compute_shared_secret(priv_key, peer_pub) {
        Error(Nil) -> Nil
        Ok(shared) -> {
          assert shared != expected_shared
            as { "XDH succeeded for invalid test: " <> context }
        }
      }
    Invalid, _, _ -> Nil

    Valid, Ok(peer_pub), Ok(#(priv_key, _)) -> {
      let assert Ok(shared) = xdh.compute_shared_secret(priv_key, peer_pub)
      assert shared == expected_shared as context
    }
    Valid, _, _ -> panic as { "Key import failed for valid test: " <> context }

    Acceptable, Ok(peer_pub), Ok(#(priv_key, _)) ->
      case xdh.compute_shared_secret(priv_key, peer_pub) {
        Ok(shared) -> {
          assert shared == expected_shared as context
        }
        Error(Nil) -> Nil
      }
    Acceptable, _, _ -> Nil
  }
}

pub fn wycheproof_x25519_asn_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("x25519_asn_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_asn_test)
}

pub fn wycheproof_x448_asn_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("x448_asn_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_asn_test)
}

fn run_pem_test(group: TestGroup, tc: TestCase) -> Nil {
  let curve_result = curve_from_name(group.curve)
  use <- bool.guard(result.is_error(curve_result), Nil)

  let context = utils.test_context(tc.tc_id, tc.comment)
  let assert Ok(expected_shared) = bit_array.base16_decode(tc.shared)

  let pub_key_result = xdh.public_key_from_pem(tc.public)
  let priv_key_result = xdh.from_pem(tc.private)

  case tc.result, pub_key_result, priv_key_result {
    Invalid, Ok(peer_pub), Ok(#(priv_key, _)) ->
      case xdh.compute_shared_secret(priv_key, peer_pub) {
        Error(Nil) -> Nil
        Ok(shared) -> {
          assert shared != expected_shared
            as { "XDH succeeded for invalid test: " <> context }
        }
      }
    Invalid, _, _ -> Nil

    Valid, Ok(peer_pub), Ok(#(priv_key, _)) -> {
      let assert Ok(shared) = xdh.compute_shared_secret(priv_key, peer_pub)
      assert shared == expected_shared as context
    }
    Valid, _, _ -> panic as { "Key import failed for valid test: " <> context }

    Acceptable, Ok(peer_pub), Ok(#(priv_key, _)) ->
      case xdh.compute_shared_secret(priv_key, peer_pub) {
        Ok(shared) -> {
          assert shared == expected_shared as context
        }
        Error(Nil) -> Nil
      }
    Acceptable, _, _ -> Nil
  }
}

pub fn wycheproof_x25519_pem_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("x25519_pem_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pem_test)
}

pub fn wycheproof_x448_pem_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("x448_pem_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pem_test)
}
