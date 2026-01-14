import gleam/bit_array
import gleam/dynamic/decode
import kryptos/block
import unitest
import wycheproof/utils.{Acceptable, Invalid, Valid}

type CbcTestCase {
  CbcTestCase(
    tc_id: Int,
    comment: String,
    key: String,
    iv: String,
    msg: String,
    ct: String,
    result: utils.TestResult,
  )
}

type CbcTestGroup {
  CbcTestGroup(iv_size: Int, key_size: Int, tests: List(CbcTestCase))
}

type CbcTestFile {
  CbcTestFile(algorithm: String, test_groups: List(CbcTestGroup))
}

fn cbc_test_case_decoder() -> decode.Decoder(CbcTestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use key <- decode.field("key", decode.string)
  use iv <- decode.field("iv", decode.string)
  use msg <- decode.field("msg", decode.string)
  use ct <- decode.field("ct", decode.string)
  use result <- decode.field("result", utils.test_result_decoder())
  decode.success(CbcTestCase(tc_id:, comment:, key:, iv:, msg:, ct:, result:))
}

fn cbc_test_group_decoder() -> decode.Decoder(CbcTestGroup) {
  use iv_size <- decode.field("ivSize", decode.int)
  use key_size <- decode.field("keySize", decode.int)
  use tests <- decode.field("tests", decode.list(cbc_test_case_decoder()))
  decode.success(CbcTestGroup(iv_size:, key_size:, tests:))
}

fn cbc_test_file_decoder() -> decode.Decoder(CbcTestFile) {
  use algorithm <- decode.field("algorithm", decode.string)
  use test_groups <- decode.field(
    "testGroups",
    decode.list(cbc_test_group_decoder()),
  )
  decode.success(CbcTestFile(algorithm:, test_groups:))
}

type KeywrapTestCase {
  KeywrapTestCase(
    tc_id: Int,
    comment: String,
    key: String,
    msg: String,
    ct: String,
    result: utils.TestResult,
  )
}

type KeywrapTestGroup {
  KeywrapTestGroup(key_size: Int, tests: List(KeywrapTestCase))
}

type KeywrapTestFile {
  KeywrapTestFile(algorithm: String, test_groups: List(KeywrapTestGroup))
}

fn keywrap_test_case_decoder() -> decode.Decoder(KeywrapTestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use key <- decode.field("key", decode.string)
  use msg <- decode.field("msg", decode.string)
  use ct <- decode.field("ct", decode.string)
  use result <- decode.field("result", utils.test_result_decoder())
  decode.success(KeywrapTestCase(tc_id:, comment:, key:, msg:, ct:, result:))
}

fn keywrap_test_group_decoder() -> decode.Decoder(KeywrapTestGroup) {
  use key_size <- decode.field("keySize", decode.int)
  use tests <- decode.field("tests", decode.list(keywrap_test_case_decoder()))
  decode.success(KeywrapTestGroup(key_size:, tests:))
}

fn keywrap_test_file_decoder() -> decode.Decoder(KeywrapTestFile) {
  use algorithm <- decode.field("algorithm", decode.string)
  use test_groups <- decode.field(
    "testGroups",
    decode.list(keywrap_test_group_decoder()),
  )
  decode.success(KeywrapTestFile(algorithm:, test_groups:))
}

fn create_cipher(key: BitArray, key_size: Int) -> Result(block.BlockCipher, Nil) {
  case key_size {
    128 -> block.aes_128(key)
    192 -> block.aes_192(key)
    256 -> block.aes_256(key)
    _ -> Error(Nil)
  }
}

fn run_cbc_test(group: CbcTestGroup, tc: CbcTestCase) -> Nil {
  let assert Ok(key) = bit_array.base16_decode(tc.key)
  let assert Ok(iv) = bit_array.base16_decode(tc.iv)
  let assert Ok(msg) = bit_array.base16_decode(tc.msg)
  let assert Ok(expected_ct) = bit_array.base16_decode(tc.ct)
  let context = utils.test_context(tc.tc_id, tc.comment)

  case create_cipher(key, group.key_size) {
    Error(Nil) -> Nil
    Ok(cipher) -> {
      case block.cbc(cipher, iv:) {
        Error(Nil) -> {
          assert tc.result == Invalid as context
        }
        Ok(ctx) ->
          case tc.result {
            Valid | Acceptable -> {
              let assert Ok(ct) = block.encrypt(ctx, msg) as context
              assert ct == expected_ct as context

              let assert Ok(plaintext) = block.decrypt(ctx, expected_ct)
                as context
              assert plaintext == msg as context
            }
            Invalid -> {
              let result = block.decrypt(ctx, expected_ct)
              assert result == Error(Nil) as context
            }
          }
      }
    }
  }
}

pub fn wycheproof_aes_cbc_pkcs5_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("aes_cbc_pkcs5_test.json", cbc_test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_cbc_test)
}

fn run_keywrap_test(group: KeywrapTestGroup, tc: KeywrapTestCase) -> Nil {
  let assert Ok(key) = bit_array.base16_decode(tc.key)
  let msg_result = bit_array.base16_decode(tc.msg)
  let ct_result = bit_array.base16_decode(tc.ct)
  let context = utils.test_context(tc.tc_id, tc.comment)

  case create_cipher(key, group.key_size), msg_result, ct_result {
    Ok(cipher), Ok(msg), Ok(expected_ct) ->
      case tc.result {
        Valid -> {
          let assert Ok(ct) = block.wrap(cipher, msg) as context
          assert ct == expected_ct as context

          let assert Ok(plaintext) = block.unwrap(cipher, expected_ct)
            as context
          assert plaintext == msg as context
        }
        Invalid -> {
          case block.wrap(cipher, msg) {
            Error(Nil) -> Nil
            Ok(_) -> {
              let result = block.unwrap(cipher, expected_ct)
              assert result == Error(Nil) as context
            }
          }
        }
        Acceptable -> {
          case block.wrap(cipher, msg) {
            Ok(ct) -> {
              assert ct == expected_ct as context
              let assert Ok(plaintext) = block.unwrap(cipher, expected_ct)
                as context
              assert plaintext == msg as context
            }
            Error(Nil) -> Nil
          }
        }
      }
    _, _, _ -> Nil
  }
}

pub fn wycheproof_aes_wrap_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(test_file) =
    utils.load_test_file("aes_wrap_test.json", keywrap_test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_keywrap_test)
}
