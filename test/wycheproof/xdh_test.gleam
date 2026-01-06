import gleam/bit_array
import gleam/dynamic/decode
import kryptos/xdh
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
  let context = utils.test_context(tc.tc_id, tc.comment)

  let curve_result = curve_from_name(group.curve)
  case curve_result {
    Error(Nil) -> Nil
    Ok(curve) -> {
      let public_result = bit_array.base16_decode(tc.public)
      let private_result = bit_array.base16_decode(tc.private)
      let shared_result = bit_array.base16_decode(tc.shared)

      case public_result, private_result, shared_result {
        Ok(public_bytes), Ok(private_bytes), Ok(expected_shared) -> {
          let pub_key_result = xdh.public_key_from_bytes(curve, public_bytes)
          let priv_key_result = xdh.private_key_from_bytes(curve, private_bytes)

          case tc.result {
            Invalid -> {
              case pub_key_result, priv_key_result {
                Ok(peer_pub), Ok(#(priv_key, _)) -> {
                  let _ = xdh.compute_shared_secret(priv_key, peer_pub)
                  Nil
                }
                _, _ -> Nil
              }
            }
            Valid | Acceptable -> {
              case pub_key_result, priv_key_result {
                Ok(peer_pub), Ok(#(priv_key, _)) -> {
                  case xdh.compute_shared_secret(priv_key, peer_pub) {
                    Ok(shared) -> {
                      assert shared == expected_shared as context
                    }
                    Error(Nil) -> {
                      case tc.result {
                        Acceptable -> Nil
                        _ ->
                          panic as { "XDH failed for valid test: " <> context }
                      }
                    }
                  }
                }
                _, _ -> {
                  case tc.result {
                    Acceptable -> Nil
                    _ ->
                      panic as {
                        "Key import failed for valid test: " <> context
                      }
                  }
                }
              }
            }
          }
        }
        _, _, _ -> Nil
      }
    }
  }
}

pub fn wycheproof_x25519_test() {
  let assert Ok(test_file) =
    utils.load_test_file("x25519_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}

pub fn wycheproof_x448_test() {
  let assert Ok(test_file) =
    utils.load_test_file("x448_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}
