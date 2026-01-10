import gleam/bit_array
import gleam/dynamic/decode
import kryptos/block
import wycheproof/utils.{Invalid, Valid}

type TestCase {
  TestCase(
    tc_id: Int,
    comment: String,
    key: String,
    iv: String,
    msg: String,
    ct: String,
    result: utils.TestResult,
  )
}

type TestGroup {
  TestGroup(iv_size: Int, key_size: Int, tests: List(TestCase))
}

type TestFile {
  TestFile(algorithm: String, test_groups: List(TestGroup))
}

fn test_case_decoder() -> decode.Decoder(TestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use key <- decode.field("key", decode.string)
  use iv <- decode.field("iv", decode.string)
  use msg <- decode.field("msg", decode.string)
  use ct <- decode.field("ct", decode.string)
  use result <- decode.field("result", utils.test_result_decoder())
  decode.success(TestCase(tc_id:, comment:, key:, iv:, msg:, ct:, result:))
}

fn test_group_decoder() -> decode.Decoder(TestGroup) {
  use iv_size <- decode.field("ivSize", decode.int)
  use key_size <- decode.field("keySize", decode.int)
  use tests <- decode.field("tests", decode.list(test_case_decoder()))
  decode.success(TestGroup(iv_size:, key_size:, tests:))
}

fn test_file_decoder() -> decode.Decoder(TestFile) {
  use algorithm <- decode.field("algorithm", decode.string)
  use test_groups <- decode.field(
    "testGroups",
    decode.list(test_group_decoder()),
  )
  decode.success(TestFile(algorithm:, test_groups:))
}

fn create_cipher(key: BitArray, key_size: Int) -> Result(block.BlockCipher, Nil) {
  case key_size {
    128 -> block.aes_128(key)
    192 -> block.aes_192(key)
    256 -> block.aes_256(key)
    _ -> Error(Nil)
  }
}

fn run_cbc_test(group: TestGroup, tc: TestCase) -> Nil {
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
            Valid -> {
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
  let assert Ok(test_file) =
    utils.load_test_file("aes_cbc_pkcs5_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_cbc_test)
}
