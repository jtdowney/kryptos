import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import simplifile

pub type TestResult {
  Valid
  Invalid
  Acceptable
}

pub fn test_result_decoder() -> decode.Decoder(TestResult) {
  use value <- decode.then(decode.string)
  case value {
    "valid" -> decode.success(Valid)
    "invalid" -> decode.success(Invalid)
    "acceptable" -> decode.success(Acceptable)
    _ -> decode.failure(Valid, "TestResult")
  }
}

pub fn load_test_file(
  filename: String,
  decoder: decode.Decoder(a),
) -> Result(a, json.DecodeError) {
  let path = "wycheproof/testvectors_v1/" <> filename
  let assert Ok(content) = simplifile.read(path)
  json.parse(content, decoder)
}

pub fn run_tests(
  test_groups: List(group),
  get_tests: fn(group) -> List(tc),
  run_test: fn(group, tc) -> Nil,
) -> Nil {
  list.each(test_groups, fn(group) {
    list.each(get_tests(group), fn(tc) { run_test(group, tc) })
  })
}

pub fn test_context(tc_id: Int, comment: String) -> String {
  "tcId=" <> int.to_string(tc_id) <> " " <> comment
}
