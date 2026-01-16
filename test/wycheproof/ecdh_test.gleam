import gleam/bit_array
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option, None}
import gleam/result
import gleam/string
import kryptos/ec
import kryptos/ecdh
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
  let assert Ok(public_der) = bit_array.base16_decode(tc.public)
  let assert Ok(private_bytes) = bit_array.base16_decode(tc.private)
  let assert Ok(expected_shared) = bit_array.base16_decode(tc.shared)

  let pub_key_result = ec.public_key_from_der(public_der)
  let priv_key_result = ec.from_bytes(curve, private_bytes)

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

pub fn wycheproof_ecdh_secp256r1_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("ecdh_secp256r1_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}

pub fn wycheproof_ecdh_secp384r1_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("ecdh_secp384r1_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}

pub fn wycheproof_ecdh_secp521r1_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("ecdh_secp521r1_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}

pub fn wycheproof_ecdh_secp256k1_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("ecdh_secp256k1_test.json", test_file_decoder())
  let groups =
    list.filter(test_file.test_groups, fn(g) { g.curve == "secp256k1" })
  utils.run_tests(groups, fn(g) { g.tests }, run_single_test)
}

fn run_pem_test(group: TestGroup, tc: TestCase) -> Nil {
  case curve_from_name(group.curve) {
    Error(Nil) -> Nil
    Ok(_curve) -> run_pem_test_for_supported_curve(tc)
  }
}

fn run_pem_test_for_supported_curve(tc: TestCase) -> Nil {
  let context = utils.test_context(tc.tc_id, tc.comment)
  let assert Ok(expected_shared) = bit_array.base16_decode(tc.shared)

  let pub_key_result = ec.public_key_from_pem(tc.public)
  let priv_key_result = ec.from_pem(tc.private)

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

pub fn wycheproof_ecdh_secp256r1_pem_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("ecdh_secp256r1_pem_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pem_test)
}

pub fn wycheproof_ecdh_secp384r1_pem_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("ecdh_secp384r1_pem_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pem_test)
}

pub fn wycheproof_ecdh_secp521r1_pem_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("ecdh_secp521r1_pem_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pem_test)
}

// WebCrypto (JWK format) tests

type WebCryptoJwk {
  WebCryptoJwk(crv: String, x: String, y: String, d: Option(String))
}

type WebCryptoTestCase {
  WebCryptoTestCase(
    tc_id: Int,
    comment: String,
    public: WebCryptoJwk,
    private: WebCryptoJwk,
    shared: String,
    result: TestResult,
  )
}

type WebCryptoTestGroup {
  WebCryptoTestGroup(curve: String, tests: List(WebCryptoTestCase))
}

type WebCryptoTestFile {
  WebCryptoTestFile(test_groups: List(WebCryptoTestGroup))
}

fn webcrypto_jwk_decoder() -> decode.Decoder(WebCryptoJwk) {
  use crv <- decode.field("crv", decode.string)
  use x <- decode.field("x", decode.string)
  use y <- decode.field("y", decode.string)
  use d <- decode.optional_field("d", None, decode.optional(decode.string))
  decode.success(WebCryptoJwk(crv:, x:, y:, d:))
}

fn webcrypto_test_case_decoder() -> decode.Decoder(WebCryptoTestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use public <- decode.field("public", webcrypto_jwk_decoder())
  use private <- decode.field("private", webcrypto_jwk_decoder())
  use shared <- decode.field("shared", decode.string)
  use result <- decode.field("result", test_result_decoder())
  decode.success(WebCryptoTestCase(
    tc_id:,
    comment:,
    public:,
    private:,
    shared:,
    result:,
  ))
}

fn webcrypto_test_group_decoder() -> decode.Decoder(WebCryptoTestGroup) {
  use curve <- decode.field("curve", decode.string)
  use tests <- decode.field("tests", decode.list(webcrypto_test_case_decoder()))
  decode.success(WebCryptoTestGroup(curve:, tests:))
}

fn webcrypto_test_file_decoder() -> decode.Decoder(WebCryptoTestFile) {
  use test_groups <- decode.field(
    "testGroups",
    decode.list(webcrypto_test_group_decoder()),
  )
  decode.success(WebCryptoTestFile(test_groups:))
}

fn webcrypto_curve_from_name(name: String) -> Result(ec.Curve, Nil) {
  case name {
    "P-256" -> Ok(ec.P256)
    "P-384" -> Ok(ec.P384)
    "P-521" -> Ok(ec.P521)
    _ -> Error(Nil)
  }
}

fn base64url_decode(input: String) -> Result(BitArray, Nil) {
  let padded = case string.length(input) % 4 {
    2 -> input <> "=="
    3 -> input <> "="
    _ -> input
  }
  let standard =
    padded
    |> string.replace("-", "+")
    |> string.replace("_", "/")
  bit_array.base64_decode(standard)
}

fn jwk_to_public_key(
  curve: ec.Curve,
  jwk: WebCryptoJwk,
) -> Result(ec.PublicKey, Nil) {
  use x <- result.try(base64url_decode(jwk.x))
  use y <- result.try(base64url_decode(jwk.y))
  let point = <<0x04, x:bits, y:bits>>
  ec.public_key_from_raw_point(curve, point)
}

fn jwk_to_private_key(
  curve: ec.Curve,
  jwk: WebCryptoJwk,
) -> Result(#(ec.PrivateKey, ec.PublicKey), Nil) {
  use d_str <- result.try(option.to_result(jwk.d, Nil))
  use d <- result.try(base64url_decode(d_str))
  ec.from_bytes(curve, d)
}

fn run_webcrypto_test(group: WebCryptoTestGroup, tc: WebCryptoTestCase) -> Nil {
  case webcrypto_curve_from_name(group.curve) {
    Error(Nil) -> Nil
    Ok(curve) -> run_webcrypto_test_for_curve(curve, tc)
  }
}

fn run_webcrypto_test_for_curve(curve: ec.Curve, tc: WebCryptoTestCase) -> Nil {
  let context = utils.test_context(tc.tc_id, tc.comment)
  let assert Ok(expected_shared) = bit_array.base16_decode(tc.shared)

  let pub_key_result = jwk_to_public_key(curve, tc.public)
  let priv_key_result = jwk_to_private_key(curve, tc.private)

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

pub fn wycheproof_ecdh_secp256r1_webcrypto_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "ecdh_secp256r1_webcrypto_test.json",
      webcrypto_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_webcrypto_test)
}

pub fn wycheproof_ecdh_secp384r1_webcrypto_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "ecdh_secp384r1_webcrypto_test.json",
      webcrypto_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_webcrypto_test)
}

pub fn wycheproof_ecdh_secp521r1_webcrypto_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "ecdh_secp521r1_webcrypto_test.json",
      webcrypto_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_webcrypto_test)
}
