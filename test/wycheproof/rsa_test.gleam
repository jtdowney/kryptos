import gleam/bit_array
import gleam/bool
import gleam/dynamic/decode
import gleam/int
import gleam/result
import kryptos/hash
import kryptos/rsa
import unitest
import wycheproof/utils

type TestResult {
  Valid
  Acceptable
  Invalid
}

type SignatureTestCase {
  SignatureTestCase(
    tc_id: Int,
    comment: String,
    msg: String,
    sig: String,
    result: TestResult,
  )
}

type SignatureTestGroup {
  SignatureTestGroup(
    key_size: Int,
    public_key_der: String,
    sha: String,
    tests: List(SignatureTestCase),
  )
}

type SignatureTestFile {
  SignatureTestFile(test_groups: List(SignatureTestGroup))
}

type PssTestCase {
  PssTestCase(
    tc_id: Int,
    comment: String,
    msg: String,
    sig: String,
    result: TestResult,
  )
}

type PssTestGroup {
  PssTestGroup(
    key_size: Int,
    public_key_der: String,
    sha: String,
    mgf_sha: String,
    s_len: Int,
    tests: List(PssTestCase),
  )
}

type PssTestFile {
  PssTestFile(test_groups: List(PssTestGroup))
}

type OaepTestCase {
  OaepTestCase(
    tc_id: Int,
    comment: String,
    msg: String,
    ct: String,
    label: String,
    result: TestResult,
  )
}

type OaepTestGroup {
  OaepTestGroup(
    key_size: Int,
    private_key_pkcs8: String,
    sha: String,
    mgf_sha: String,
    tests: List(OaepTestCase),
  )
}

type OaepTestFile {
  OaepTestFile(test_groups: List(OaepTestGroup))
}

type Pkcs1DecryptTestCase {
  Pkcs1DecryptTestCase(
    tc_id: Int,
    comment: String,
    msg: String,
    ct: String,
    result: TestResult,
  )
}

type Pkcs1DecryptTestGroup {
  Pkcs1DecryptTestGroup(
    key_size: Int,
    private_key_pkcs8: String,
    tests: List(Pkcs1DecryptTestCase),
  )
}

type Pkcs1DecryptTestFile {
  Pkcs1DecryptTestFile(test_groups: List(Pkcs1DecryptTestGroup))
}

type SigGenTestCase {
  SigGenTestCase(
    tc_id: Int,
    comment: String,
    msg: String,
    sig: String,
    result: TestResult,
  )
}

type SigGenTestGroup {
  SigGenTestGroup(
    key_size: Int,
    private_key_pkcs8: String,
    sha: String,
    tests: List(SigGenTestCase),
  )
}

type SigGenTestFile {
  SigGenTestFile(test_groups: List(SigGenTestGroup))
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

fn signature_test_case_decoder() -> decode.Decoder(SignatureTestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use msg <- decode.field("msg", decode.string)
  use sig <- decode.field("sig", decode.string)
  use result <- decode.field("result", test_result_decoder())
  decode.success(SignatureTestCase(tc_id:, comment:, msg:, sig:, result:))
}

fn signature_test_group_decoder() -> decode.Decoder(SignatureTestGroup) {
  use key_size <- decode.field("keySize", decode.int)
  use public_key_der <- decode.field("publicKeyDer", decode.string)
  use sha <- decode.field("sha", decode.string)
  use tests <- decode.field("tests", decode.list(signature_test_case_decoder()))
  decode.success(SignatureTestGroup(key_size:, public_key_der:, sha:, tests:))
}

fn signature_test_file_decoder() -> decode.Decoder(SignatureTestFile) {
  use test_groups <- decode.field(
    "testGroups",
    decode.list(signature_test_group_decoder()),
  )
  decode.success(SignatureTestFile(test_groups:))
}

fn pss_test_case_decoder() -> decode.Decoder(PssTestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use msg <- decode.field("msg", decode.string)
  use sig <- decode.field("sig", decode.string)
  use result <- decode.field("result", test_result_decoder())
  decode.success(PssTestCase(tc_id:, comment:, msg:, sig:, result:))
}

fn pss_test_group_decoder() -> decode.Decoder(PssTestGroup) {
  use key_size <- decode.field("keySize", decode.int)
  use public_key_der <- decode.field("publicKeyDer", decode.string)
  use sha <- decode.field("sha", decode.string)
  use mgf_sha <- decode.field("mgfSha", decode.string)
  use s_len <- decode.field("sLen", decode.int)
  use tests <- decode.field("tests", decode.list(pss_test_case_decoder()))
  decode.success(PssTestGroup(
    key_size:,
    public_key_der:,
    sha:,
    mgf_sha:,
    s_len:,
    tests:,
  ))
}

fn pss_test_file_decoder() -> decode.Decoder(PssTestFile) {
  use test_groups <- decode.field(
    "testGroups",
    decode.list(pss_test_group_decoder()),
  )
  decode.success(PssTestFile(test_groups:))
}

fn oaep_test_case_decoder() -> decode.Decoder(OaepTestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use msg <- decode.field("msg", decode.string)
  use ct <- decode.field("ct", decode.string)
  use label <- decode.field("label", decode.string)
  use result <- decode.field("result", test_result_decoder())
  decode.success(OaepTestCase(tc_id:, comment:, msg:, ct:, label:, result:))
}

fn oaep_test_group_decoder() -> decode.Decoder(OaepTestGroup) {
  use key_size <- decode.field("keySize", decode.int)
  use private_key_pkcs8 <- decode.field("privateKeyPkcs8", decode.string)
  use sha <- decode.field("sha", decode.string)
  use mgf_sha <- decode.field("mgfSha", decode.string)
  use tests <- decode.field("tests", decode.list(oaep_test_case_decoder()))
  decode.success(OaepTestGroup(
    key_size:,
    private_key_pkcs8:,
    sha:,
    mgf_sha:,
    tests:,
  ))
}

fn oaep_test_file_decoder() -> decode.Decoder(OaepTestFile) {
  use test_groups <- decode.field(
    "testGroups",
    decode.list(oaep_test_group_decoder()),
  )
  decode.success(OaepTestFile(test_groups:))
}

fn pkcs1_decrypt_test_case_decoder() -> decode.Decoder(Pkcs1DecryptTestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use msg <- decode.field("msg", decode.string)
  use ct <- decode.field("ct", decode.string)
  use result <- decode.field("result", test_result_decoder())
  decode.success(Pkcs1DecryptTestCase(tc_id:, comment:, msg:, ct:, result:))
}

fn pkcs1_decrypt_test_group_decoder() -> decode.Decoder(Pkcs1DecryptTestGroup) {
  use private_key_pkcs8 <- decode.field("privateKeyPkcs8", decode.string)
  use tests <- decode.field(
    "tests",
    decode.list(pkcs1_decrypt_test_case_decoder()),
  )
  decode.success(Pkcs1DecryptTestGroup(key_size: 0, private_key_pkcs8:, tests:))
}

fn pkcs1_decrypt_test_file_decoder() -> decode.Decoder(Pkcs1DecryptTestFile) {
  use test_groups <- decode.field(
    "testGroups",
    decode.list(pkcs1_decrypt_test_group_decoder()),
  )
  decode.success(Pkcs1DecryptTestFile(test_groups:))
}

fn sig_gen_test_case_decoder() -> decode.Decoder(SigGenTestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use msg <- decode.field("msg", decode.string)
  use sig <- decode.field("sig", decode.string)
  use result <- decode.field("result", test_result_decoder())
  decode.success(SigGenTestCase(tc_id:, comment:, msg:, sig:, result:))
}

fn sig_gen_test_group_decoder() -> decode.Decoder(SigGenTestGroup) {
  use key_size <- decode.field("keySize", decode.int)
  use private_key_pkcs8 <- decode.field("privateKeyPkcs8", decode.string)
  use sha <- decode.field("sha", decode.string)
  use tests <- decode.field("tests", decode.list(sig_gen_test_case_decoder()))
  decode.success(SigGenTestGroup(key_size:, private_key_pkcs8:, sha:, tests:))
}

fn sig_gen_test_file_decoder() -> decode.Decoder(SigGenTestFile) {
  use test_groups <- decode.field(
    "testGroups",
    decode.list(sig_gen_test_group_decoder()),
  )
  decode.success(SigGenTestFile(test_groups:))
}

fn hash_from_name(name: String) -> Result(hash.HashAlgorithm, Nil) {
  case name {
    "SHA-1" -> Ok(hash.Sha1)
    "SHA-256" -> Ok(hash.Sha256)
    "SHA-384" -> Ok(hash.Sha384)
    "SHA-512" -> Ok(hash.Sha512)
    "SHA-512/224" -> Ok(hash.Sha512x224)
    "SHA-512/256" -> Ok(hash.Sha512x256)
    "SHA3-224" -> Ok(hash.Sha3x224)
    "SHA3-256" -> Ok(hash.Sha3x256)
    "SHA3-384" -> Ok(hash.Sha3x384)
    "SHA3-512" -> Ok(hash.Sha3x512)
    _ -> Error(Nil)
  }
}

fn run_signature_test(group: SignatureTestGroup, tc: SignatureTestCase) -> Nil {
  let context =
    utils.test_context(tc.tc_id, tc.comment)
    <> " (keySize: "
    <> int.to_string(group.key_size)
    <> ", sha: "
    <> group.sha
    <> ")"

  let hash_alg = hash_from_name(group.sha)
  use <- bool.guard(result.is_error(hash_alg), Nil)
  let assert Ok(hash_alg) = hash_alg

  let assert Ok(pub_der) = bit_array.base16_decode(group.public_key_der)
  let assert Ok(msg) = bit_array.base16_decode(tc.msg)
  let assert Ok(sig) = bit_array.base16_decode(tc.sig)

  case rsa.public_key_from_der(pub_der, rsa.Spki) {
    Error(Nil) -> {
      case tc.result {
        Invalid | Acceptable -> Nil
        Valid -> panic as { "Key import failed for valid: " <> context }
      }
    }
    Ok(public_key) -> {
      let valid = rsa.verify(public_key, msg, sig, hash_alg, rsa.Pkcs1v15)
      case tc.result {
        Valid -> {
          assert valid as { "Expected valid: " <> context }
        }
        Invalid -> {
          assert !valid as { "Expected invalid: " <> context }
        }
        Acceptable -> Nil
      }
    }
  }
}

fn run_pss_test(group: PssTestGroup, tc: PssTestCase) -> Nil {
  let context =
    utils.test_context(tc.tc_id, tc.comment)
    <> " (keySize: "
    <> int.to_string(group.key_size)
    <> ", sha: "
    <> group.sha
    <> ", sLen: "
    <> int.to_string(group.s_len)
    <> ")"

  use <- bool.guard(group.sha != group.mgf_sha, Nil)

  let hash_alg = hash_from_name(group.sha)
  use <- bool.guard(result.is_error(hash_alg), Nil)
  let assert Ok(hash_alg) = hash_alg

  let assert Ok(pub_der) = bit_array.base16_decode(group.public_key_der)
  let assert Ok(msg) = bit_array.base16_decode(tc.msg)
  let assert Ok(sig) = bit_array.base16_decode(tc.sig)

  case rsa.public_key_from_der(pub_der, rsa.Spki) {
    Error(Nil) -> {
      case tc.result {
        Invalid | Acceptable -> Nil
        Valid -> panic as { "Key import failed for valid: " <> context }
      }
    }
    Ok(public_key) -> {
      let padding = rsa.Pss(rsa.SaltLengthExplicit(group.s_len))
      let valid = rsa.verify(public_key, msg, sig, hash_alg, padding)
      case tc.result {
        Valid -> {
          assert valid as { "Expected valid: " <> context }
        }
        Invalid -> {
          assert !valid as { "Expected invalid: " <> context }
        }
        Acceptable -> Nil
      }
    }
  }
}

fn run_oaep_test(group: OaepTestGroup, tc: OaepTestCase) -> Nil {
  let context =
    utils.test_context(tc.tc_id, tc.comment)
    <> " (keySize: "
    <> int.to_string(group.key_size)
    <> ", sha: "
    <> group.sha
    <> ")"

  use <- bool.guard(group.sha != group.mgf_sha, Nil)

  let hash_alg = hash_from_name(group.sha)
  use <- bool.guard(result.is_error(hash_alg), Nil)
  let assert Ok(hash_alg) = hash_alg

  let assert Ok(priv_der) = bit_array.base16_decode(group.private_key_pkcs8)
  let assert Ok(ct) = bit_array.base16_decode(tc.ct)
  let assert Ok(expected_msg) = bit_array.base16_decode(tc.msg)
  let assert Ok(label) = bit_array.base16_decode(tc.label)

  case rsa.from_der(priv_der, rsa.Pkcs8) {
    Error(Nil) -> {
      case tc.result {
        Invalid | Acceptable -> Nil
        Valid -> panic as { "Key import failed for valid: " <> context }
      }
    }
    Ok(#(private_key, _public_key)) -> {
      let padding = rsa.Oaep(hash: hash_alg, label: label)
      let decrypt_result = rsa.decrypt(private_key, ct, padding)
      case tc.result {
        Valid -> {
          let assert Ok(decrypted) = decrypt_result
          assert decrypted == expected_msg
            as { "Decryption mismatch: " <> context }
        }
        Invalid ->
          case decrypt_result {
            Error(Nil) -> Nil
            Ok(decrypted) -> {
              assert decrypted != expected_msg
                as { "Expected invalid: " <> context }
            }
          }
        Acceptable -> Nil
      }
    }
  }
}

fn run_pkcs1_decrypt_test(
  group: Pkcs1DecryptTestGroup,
  tc: Pkcs1DecryptTestCase,
) -> Nil {
  let context = utils.test_context(tc.tc_id, tc.comment)

  let assert Ok(priv_der) = bit_array.base16_decode(group.private_key_pkcs8)
  let assert Ok(ct) = bit_array.base16_decode(tc.ct)
  let assert Ok(expected_msg) = bit_array.base16_decode(tc.msg)

  case rsa.from_der(priv_der, rsa.Pkcs8) {
    Error(Nil) -> {
      case tc.result {
        Invalid | Acceptable -> Nil
        Valid -> panic as { "Key import failed for valid: " <> context }
      }
    }
    Ok(#(private_key, _public_key)) -> {
      let decrypt_result = rsa.decrypt(private_key, ct, rsa.EncryptPkcs1v15)
      case tc.result {
        Valid -> {
          let assert Ok(decrypted) = decrypt_result
          assert decrypted == expected_msg
            as { "Decryption mismatch: " <> context }
        }
        Invalid ->
          case decrypt_result {
            Error(Nil) -> Nil
            Ok(decrypted) -> {
              assert decrypted != expected_msg
                as { "Expected invalid: " <> context }
            }
          }
        Acceptable -> Nil
      }
    }
  }
}

fn run_sig_gen_test(group: SigGenTestGroup, tc: SigGenTestCase) -> Nil {
  let context =
    utils.test_context(tc.tc_id, tc.comment)
    <> " (keySize: "
    <> int.to_string(group.key_size)
    <> ", sha: "
    <> group.sha
    <> ")"

  let hash_alg = hash_from_name(group.sha)
  use <- bool.guard(result.is_error(hash_alg), Nil)
  let assert Ok(hash_alg) = hash_alg

  let assert Ok(priv_der) = bit_array.base16_decode(group.private_key_pkcs8)
  let assert Ok(msg) = bit_array.base16_decode(tc.msg)
  let assert Ok(expected_sig) = bit_array.base16_decode(tc.sig)

  case rsa.from_der(priv_der, rsa.Pkcs8) {
    Error(Nil) -> {
      case tc.result {
        Invalid | Acceptable -> Nil
        Valid -> panic as { "Key import failed for valid: " <> context }
      }
    }
    Ok(#(private_key, public_key)) -> {
      case tc.result {
        Valid | Acceptable -> {
          let sig = rsa.sign(private_key, msg, hash_alg, rsa.Pkcs1v15)
          assert sig == expected_sig as { "Signature mismatch: " <> context }
          let valid =
            rsa.verify(public_key, msg, expected_sig, hash_alg, rsa.Pkcs1v15)
          assert valid as { "Verification failed: " <> context }
        }
        Invalid -> Nil
      }
    }
  }
}

pub fn wycheproof_rsa_signature_2048_sha256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_2048_sha256_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_2048_sha384_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_2048_sha384_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_2048_sha512_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_2048_sha512_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_3072_sha256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_3072_sha256_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_4096_sha512_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_4096_sha512_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_pss_2048_sha256_mgf1_32_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pss_2048_sha256_mgf1_32_test.json",
      pss_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

pub fn wycheproof_rsa_pss_3072_sha256_mgf1_32_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pss_3072_sha256_mgf1_32_test.json",
      pss_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

pub fn wycheproof_rsa_pss_4096_sha256_mgf1_32_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pss_4096_sha256_mgf1_32_test.json",
      pss_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

pub fn wycheproof_rsa_pss_4096_sha512_mgf1_64_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pss_4096_sha512_mgf1_64_test.json",
      pss_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

pub fn wycheproof_rsa_oaep_2048_sha256_mgf1sha256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_oaep_2048_sha256_mgf1sha256_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_oaep_2048_sha384_mgf1sha384_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_oaep_2048_sha384_mgf1sha384_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_oaep_2048_sha512_mgf1sha512_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_oaep_2048_sha512_mgf1sha512_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_oaep_3072_sha256_mgf1sha256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_oaep_3072_sha256_mgf1sha256_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_oaep_4096_sha256_mgf1sha256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_oaep_4096_sha256_mgf1sha256_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_oaep_4096_sha512_mgf1sha512_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_oaep_4096_sha512_mgf1sha512_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_pkcs1_2048_decrypt_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pkcs1_2048_test.json",
      pkcs1_decrypt_test_file_decoder(),
    )
  utils.run_tests(
    test_file.test_groups,
    fn(g) { g.tests },
    run_pkcs1_decrypt_test,
  )
}

pub fn wycheproof_rsa_pkcs1_3072_decrypt_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pkcs1_3072_test.json",
      pkcs1_decrypt_test_file_decoder(),
    )
  utils.run_tests(
    test_file.test_groups,
    fn(g) { g.tests },
    run_pkcs1_decrypt_test,
  )
}

pub fn wycheproof_rsa_pkcs1_4096_decrypt_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pkcs1_4096_test.json",
      pkcs1_decrypt_test_file_decoder(),
    )
  utils.run_tests(
    test_file.test_groups,
    fn(g) { g.tests },
    run_pkcs1_decrypt_test,
  )
}

pub fn wycheproof_rsa_signature_2048_sha224_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_2048_sha224_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_2048_sha3_224_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_2048_sha3_224_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_2048_sha3_256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_2048_sha3_256_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_2048_sha3_384_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_2048_sha3_384_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_2048_sha3_512_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_2048_sha3_512_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_2048_sha512_224_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_2048_sha512_224_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_2048_sha512_256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_2048_sha512_256_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_3072_sha3_256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_3072_sha3_256_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_3072_sha3_384_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_3072_sha3_384_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_3072_sha3_512_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_3072_sha3_512_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_3072_sha384_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_3072_sha384_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_3072_sha512_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_3072_sha512_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_3072_sha512_256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_3072_sha512_256_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_4096_sha256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_4096_sha256_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_4096_sha384_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_4096_sha384_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_4096_sha512_256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_4096_sha512_256_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_8192_sha256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_8192_sha256_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_8192_sha384_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_8192_sha384_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

pub fn wycheproof_rsa_signature_8192_sha512_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_signature_8192_sha512_test.json",
      signature_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_signature_test)
}

// Additional PSS tests

pub fn wycheproof_rsa_pss_2048_sha1_mgf1_20_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pss_2048_sha1_mgf1_20_test.json",
      pss_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

pub fn wycheproof_rsa_pss_2048_sha256_mgf1_0_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pss_2048_sha256_mgf1_0_test.json",
      pss_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

pub fn wycheproof_rsa_pss_2048_sha384_mgf1_48_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pss_2048_sha384_mgf1_48_test.json",
      pss_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

pub fn wycheproof_rsa_pss_2048_sha512_224_mgf1_28_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pss_2048_sha512_224_mgf1_28_test.json",
      pss_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

pub fn wycheproof_rsa_pss_2048_sha512_256_mgf1_32_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pss_2048_sha512_256_mgf1_32_test.json",
      pss_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

pub fn wycheproof_rsa_pss_4096_sha384_mgf1_48_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pss_4096_sha384_mgf1_48_test.json",
      pss_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

pub fn wycheproof_rsa_pss_4096_sha512_mgf1_32_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pss_4096_sha512_mgf1_32_test.json",
      pss_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

pub fn wycheproof_rsa_pss_misc_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("rsa_pss_misc_test.json", pss_test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_pss_test)
}

// Additional OAEP tests

pub fn wycheproof_rsa_oaep_2048_sha1_mgf1sha1_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_oaep_2048_sha1_mgf1sha1_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_oaep_2048_sha224_mgf1sha224_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_oaep_2048_sha224_mgf1sha224_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_oaep_2048_sha512_224_mgf1sha512_224_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_oaep_2048_sha512_224_mgf1sha512_224_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_oaep_3072_sha512_256_mgf1sha512_256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_oaep_3072_sha512_256_mgf1sha512_256_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_oaep_3072_sha512_mgf1sha512_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_oaep_3072_sha512_mgf1sha512_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_oaep_misc_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("rsa_oaep_misc_test.json", oaep_test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_three_primes_oaep_2048_sha1_mgf1sha1_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_three_primes_oaep_2048_sha1_mgf1sha1_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_three_primes_oaep_3072_sha224_mgf1sha224_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_three_primes_oaep_3072_sha224_mgf1sha224_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

pub fn wycheproof_rsa_three_primes_oaep_4096_sha256_mgf1sha256_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_three_primes_oaep_4096_sha256_mgf1sha256_test.json",
      oaep_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_oaep_test)
}

// Signature generation tests

pub fn wycheproof_rsa_pkcs1_1024_sig_gen_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pkcs1_1024_sig_gen_test.json",
      sig_gen_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_sig_gen_test)
}

pub fn wycheproof_rsa_pkcs1_1536_sig_gen_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pkcs1_1536_sig_gen_test.json",
      sig_gen_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_sig_gen_test)
}

pub fn wycheproof_rsa_pkcs1_2048_sig_gen_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pkcs1_2048_sig_gen_test.json",
      sig_gen_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_sig_gen_test)
}

pub fn wycheproof_rsa_pkcs1_3072_sig_gen_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pkcs1_3072_sig_gen_test.json",
      sig_gen_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_sig_gen_test)
}

pub fn wycheproof_rsa_pkcs1_4096_sig_gen_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file(
      "rsa_pkcs1_4096_sig_gen_test.json",
      sig_gen_test_file_decoder(),
    )
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_sig_gen_test)
}
