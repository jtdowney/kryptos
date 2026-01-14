import gleam/bit_array
import gleam/dynamic/decode
import kryptos/aead
import kryptos/block
import wycheproof/utils.{Acceptable, Invalid, Valid}

type TestCase {
  TestCase(
    tc_id: Int,
    comment: String,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: utils.TestResult,
  )
}

type TestGroup {
  TestGroup(iv_size: Int, key_size: Int, tag_size: Int, tests: List(TestCase))
}

type TestFile {
  TestFile(algorithm: String, test_groups: List(TestGroup))
}

fn test_case_decoder() -> decode.Decoder(TestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use key <- decode.field("key", decode.string)
  use iv <- decode.field("iv", decode.string)
  use aad <- decode.field("aad", decode.string)
  use msg <- decode.field("msg", decode.string)
  use ct <- decode.field("ct", decode.string)
  use tag <- decode.field("tag", decode.string)
  use result <- decode.field("result", utils.test_result_decoder())
  decode.success(TestCase(
    tc_id:,
    comment:,
    key:,
    iv:,
    aad:,
    msg:,
    ct:,
    tag:,
    result:,
  ))
}

fn test_group_decoder() -> decode.Decoder(TestGroup) {
  use iv_size <- decode.field("ivSize", decode.int)
  use key_size <- decode.field("keySize", decode.int)
  use tag_size <- decode.field("tagSize", decode.int)
  use tests <- decode.field("tests", decode.list(test_case_decoder()))
  decode.success(TestGroup(iv_size:, key_size:, tag_size:, tests:))
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

fn run_single_test(group: TestGroup, tc: TestCase) -> Nil {
  let assert Ok(key) = bit_array.base16_decode(tc.key)
  let assert Ok(iv) = bit_array.base16_decode(tc.iv)
  let assert Ok(aad) = bit_array.base16_decode(tc.aad)
  let assert Ok(msg) = bit_array.base16_decode(tc.msg)
  let assert Ok(expected_ct) = bit_array.base16_decode(tc.ct)
  let assert Ok(expected_tag) = bit_array.base16_decode(tc.tag)
  let context = utils.test_context(tc.tc_id, tc.comment)

  case create_cipher(key, group.key_size) {
    Error(Nil) -> Nil
    Ok(cipher) -> {
      let nonce_size = group.iv_size / 8
      case aead.gcm_with_nonce_size(cipher, nonce_size) {
        // Nonce size out of range - skip this test
        Error(Nil) -> Nil
        Ok(ctx) ->
          case tc.result {
            Valid | Acceptable -> {
              // Test encryption
              let assert Ok(#(ct, tag)) = aead.seal_with_aad(ctx, iv, msg, aad)
                as context
              assert ct == expected_ct as context
              assert tag == expected_tag as context

              // Test decryption
              let assert Ok(plaintext) =
                aead.open_with_aad(ctx, iv, expected_tag, expected_ct, aad)
                as context
              assert plaintext == msg as context
            }
            Invalid -> {
              // Invalid test cases should fail decryption
              let result =
                aead.open_with_aad(ctx, iv, expected_tag, expected_ct, aad)
              assert result == Error(Nil) as context
            }
          }
      }
    }
  }
}

pub fn wycheproof_aes_gcm_test() {
  let assert Ok(test_file) =
    utils.load_test_file("aes_gcm_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_single_test)
}

fn run_chacha20_poly1305_test(_group: TestGroup, tc: TestCase) -> Nil {
  let assert Ok(key) = bit_array.base16_decode(tc.key)
  let assert Ok(iv) = bit_array.base16_decode(tc.iv)
  let assert Ok(aad) = bit_array.base16_decode(tc.aad)
  let assert Ok(msg) = bit_array.base16_decode(tc.msg)
  let assert Ok(expected_ct) = bit_array.base16_decode(tc.ct)
  let assert Ok(expected_tag) = bit_array.base16_decode(tc.tag)
  let context = utils.test_context(tc.tc_id, tc.comment)

  let assert Ok(ctx) = aead.chacha20_poly1305(key) as context

  case tc.result {
    Valid | Acceptable -> {
      // Test encryption
      let assert Ok(#(ct, tag)) = aead.seal_with_aad(ctx, iv, msg, aad)
        as context
      assert ct == expected_ct as context
      assert tag == expected_tag as context

      // Test decryption
      let assert Ok(plaintext) =
        aead.open_with_aad(ctx, iv, expected_tag, expected_ct, aad)
        as context
      assert plaintext == msg as context
    }
    Invalid -> {
      // Invalid test cases should fail decryption
      let result = aead.open_with_aad(ctx, iv, expected_tag, expected_ct, aad)
      assert result == Error(Nil) as context
    }
  }
}

pub fn wycheproof_chacha20_poly1305_test() {
  let assert Ok(test_file) =
    utils.load_test_file("chacha20_poly1305_test.json", test_file_decoder())
  utils.run_tests(
    test_file.test_groups,
    fn(g) { g.tests },
    run_chacha20_poly1305_test,
  )
}

fn run_ccm_test(group: TestGroup, tc: TestCase) -> Nil {
  let nonce_size = group.iv_size / 8
  let tag_size = group.tag_size / 8

  let assert Ok(key) = bit_array.base16_decode(tc.key)
  let assert Ok(iv) = bit_array.base16_decode(tc.iv)
  let assert Ok(aad) = bit_array.base16_decode(tc.aad)
  let assert Ok(msg) = bit_array.base16_decode(tc.msg)
  let assert Ok(expected_ct) = bit_array.base16_decode(tc.ct)
  let assert Ok(expected_tag) = bit_array.base16_decode(tc.tag)
  let context = utils.test_context(tc.tc_id, tc.comment)

  case create_cipher(key, group.key_size) {
    Error(Nil) -> Nil
    Ok(cipher) -> {
      // Use ccm_with_sizes to properly validate nonce/tag sizes
      case aead.ccm_with_sizes(cipher, nonce_size:, tag_size:) {
        Error(Nil) -> {
          // Invalid configuration - should only happen for Invalid test cases
          assert tc.result == Invalid as context
        }
        Ok(ctx) -> {
          case tc.result {
            Valid | Acceptable -> {
              // Test encryption
              let assert Ok(#(ct, tag)) = aead.seal_with_aad(ctx, iv, msg, aad)
                as context
              assert ct == expected_ct as context
              assert tag == expected_tag as context

              // Test decryption
              let assert Ok(plaintext) =
                aead.open_with_aad(ctx, iv, expected_tag, expected_ct, aad)
                as context
              assert plaintext == msg as context
            }
            Invalid -> {
              // Invalid test cases should fail decryption
              let result =
                aead.open_with_aad(ctx, iv, expected_tag, expected_ct, aad)
              assert result == Error(Nil) as context
            }
          }
        }
      }
    }
  }
}

pub fn wycheproof_aes_ccm_test() {
  let assert Ok(test_file) =
    utils.load_test_file("aes_ccm_test.json", test_file_decoder())
  utils.run_tests(test_file.test_groups, fn(g) { g.tests }, run_ccm_test)
}
