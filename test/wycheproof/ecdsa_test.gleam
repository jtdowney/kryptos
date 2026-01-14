import gleam/bit_array
import gleam/dynamic/decode
import kryptos/ec
import kryptos/ecdsa
import kryptos/hash
import unitest
import wycheproof/utils

type TestResult {
  Valid
  Acceptable
  Invalid
}

type PublicKeyInfo {
  PublicKeyInfo(curve: String, uncompressed: String)
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
  use uncompressed <- decode.field("uncompressed", decode.string)
  decode.success(PublicKeyInfo(curve:, uncompressed:))
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

fn curve_from_name(name: String) -> Result(ec.Curve, Nil) {
  case name {
    "secp256r1" -> Ok(ec.P256)
    "secp384r1" -> Ok(ec.P384)
    "secp521r1" -> Ok(ec.P521)
    "secp256k1" -> Ok(ec.Secp256k1)
    _ -> Error(Nil)
  }
}

fn run_single_test(
  hash_alg: hash.HashAlgorithm,
  group: TestGroup,
  tc: TestCase,
) -> Nil {
  let context = utils.test_context(tc.tc_id, tc.comment)

  case curve_from_name(group.public_key.curve) {
    Error(Nil) -> Nil
    Ok(curve) -> {
      let assert Ok(pk_bytes) =
        bit_array.base16_decode(group.public_key.uncompressed)
      let assert Ok(msg_bytes) = bit_array.base16_decode(tc.msg)
      let assert Ok(sig_bytes) = bit_array.base16_decode(tc.sig)

      case tc.result {
        Invalid -> {
          case ec.public_key_from_raw_point(curve, pk_bytes) {
            Ok(pub_key) -> {
              assert !ecdsa.verify(pub_key, msg_bytes, sig_bytes, hash_alg)
                as {
                  "ECDSA verification succeeded for invalid test: " <> context
                }
            }
            Error(Nil) -> Nil
          }
        }
        Valid -> {
          let assert Ok(pub_key) = ec.public_key_from_raw_point(curve, pk_bytes)
            as { "Public key import failed: " <> context }
          assert ecdsa.verify(pub_key, msg_bytes, sig_bytes, hash_alg)
            as { "ECDSA verification failed for valid test: " <> context }
        }
        Acceptable -> {
          case ec.public_key_from_raw_point(curve, pk_bytes) {
            Ok(pub_key) -> {
              let _ = ecdsa.verify(pub_key, msg_bytes, sig_bytes, hash_alg)
              Nil
            }
            Error(Nil) -> Nil
          }
        }
      }
    }
  }
}

fn run_wycheproof_tests(filename: String, hash_alg: hash.HashAlgorithm) -> Nil {
  let assert Ok(test_file) = utils.load_test_file(filename, test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, fn(group, tc) {
    run_single_test(hash_alg, group, tc)
  })
}

pub fn wycheproof_ecdsa_secp256r1_sha256_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp256r1_sha256_test.json", hash.Sha256)
}

pub fn wycheproof_ecdsa_secp256r1_sha512_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp256r1_sha512_test.json", hash.Sha512)
}

pub fn wycheproof_ecdsa_secp256r1_sha3_256_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp256r1_sha3_256_test.json", hash.Sha3x256)
}

pub fn wycheproof_ecdsa_secp256r1_sha3_512_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp256r1_sha3_512_test.json", hash.Sha3x512)
}

pub fn wycheproof_ecdsa_secp384r1_sha384_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp384r1_sha384_test.json", hash.Sha384)
}

pub fn wycheproof_ecdsa_secp384r1_sha512_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp384r1_sha512_test.json", hash.Sha512)
}

pub fn wycheproof_ecdsa_secp384r1_sha3_384_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp384r1_sha3_384_test.json", hash.Sha3x384)
}

pub fn wycheproof_ecdsa_secp384r1_sha3_512_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp384r1_sha3_512_test.json", hash.Sha3x512)
}

pub fn wycheproof_ecdsa_secp521r1_sha512_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp521r1_sha512_test.json", hash.Sha512)
}

pub fn wycheproof_ecdsa_secp521r1_sha3_512_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp521r1_sha3_512_test.json", hash.Sha3x512)
}

pub fn wycheproof_ecdsa_secp256k1_sha256_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp256k1_sha256_test.json", hash.Sha256)
}

pub fn wycheproof_ecdsa_secp256k1_sha512_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp256k1_sha512_test.json", hash.Sha512)
}

pub fn wycheproof_ecdsa_secp256k1_sha3_256_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp256k1_sha3_256_test.json", hash.Sha3x256)
}

pub fn wycheproof_ecdsa_secp256k1_sha3_512_test() {
  use <- unitest.tag("wycheproof")
  run_wycheproof_tests("ecdsa_secp256k1_sha3_512_test.json", hash.Sha3x512)
}
