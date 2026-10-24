import gleam/bit_array
import gleam/dynamic/decode
import gleam/list
import kryptos/stream
import unitest
import wycheproof/utils

type TestCase {
  TestCase(
    tc_id: Int,
    comment: String,
    key: String,
    iv: String,
    msg: String,
    ct: String,
    result: utils.TestResult,
    flags: List(String),
  )
}

type TestGroup {
  TestGroup(tests: List(TestCase))
}

fn test_case_decoder() -> decode.Decoder(TestCase) {
  use tc_id <- decode.field("tcId", decode.int)
  use comment <- decode.field("comment", decode.string)
  use key <- decode.field("key", decode.string)
  use iv <- decode.field("iv", decode.string)
  use msg <- decode.field("msg", decode.string)
  use ct <- decode.field("ct", decode.string)
  use result <- decode.field("result", utils.test_result_decoder())
  use flags <- decode.field("flags", decode.list(decode.string))
  decode.success(TestCase(
    tc_id:,
    comment:,
    key:,
    iv:,
    msg:,
    ct:,
    result:,
    flags:,
  ))
}

fn test_groups_decoder() -> decode.Decoder(List(TestGroup)) {
  let group_decoder = {
    use tests <- decode.field("tests", decode.list(test_case_decoder()))
    decode.success(TestGroup(tests:))
  }
  decode.at(["testGroups"], decode.list(group_decoder))
}

fn run_test(
  tc: TestCase,
  cipher_for: fn(BitArray, BitArray) -> Result(stream.StreamCipher, Nil),
) -> Nil {
  let assert Ok(key) = bit_array.base16_decode(tc.key)
  let assert Ok(iv) = bit_array.base16_decode(tc.iv)
  let assert Ok(msg) = bit_array.base16_decode(tc.msg)
  let assert Ok(expected_ct) = bit_array.base16_decode(tc.ct)
  let context = utils.test_context(tc.tc_id, tc.comment)

  case tc.result, list.contains(tc.flags, "InvalidNonceSize") {
    utils.Valid, _ | utils.Acceptable, _ -> {
      let assert Ok(cipher) = cipher_for(key, iv) as context
      let assert Ok(ct) = stream.xor(cipher, msg) as context
      assert ct == expected_ct as context
      let assert Ok(plaintext) = stream.xor(cipher, expected_ct) as context
      assert plaintext == msg as context
    }
    utils.Invalid, True -> {
      assert cipher_for(key, iv) == Error(Nil) as context
    }
    // The remaining invalid cases modify the tag, which a raw stream cipher
    // can't detect.
    utils.Invalid, False -> Nil
  }
}

pub fn wycheproof_chacha20_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(groups) =
    utils.load_test_file("chacha20_poly1305_test.json", test_groups_decoder())
  use _group, tc <- utils.run_tests(groups, fn(g) { g.tests })
  run_test(tc, fn(key, nonce) { stream.chacha20(key, nonce:, counter: 1) })
}

pub fn wycheproof_xchacha20_test() {
  use <- unitest.tag("wycheproof")
  let assert Ok(groups) =
    utils.load_test_file("xchacha20_poly1305_test.json", test_groups_decoder())
  use _group, tc <- utils.run_tests(groups, fn(g) { g.tests })
  run_test(tc, fn(key, nonce) { stream.xchacha20(key, nonce:, counter: 1) })
}
