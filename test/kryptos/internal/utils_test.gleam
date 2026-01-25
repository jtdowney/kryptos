import gleam/list
import gleam/string
import kryptos/internal/utils
import qcheck

pub fn is_ascii_accepts_empty_string_test() {
  assert utils.is_ascii("") == True
}

pub fn is_ascii_accepts_printable_ascii_test() {
  assert utils.is_ascii("Hello, World!") == True
  assert utils.is_ascii("test@example.com") == True
  assert utils.is_ascii("0123456789") == True
}

pub fn is_ascii_accepts_control_characters_test() {
  assert utils.is_ascii("\t\n\r") == True
}

pub fn is_ascii_rejects_non_ascii_test() {
  assert utils.is_ascii("café") == False
  assert utils.is_ascii("日本語") == False
  assert utils.is_ascii("tëst") == False
}

pub fn is_ascii_property_test() {
  let ascii_char = qcheck.bounded_int(0, 127)
  let gen =
    qcheck.generic_list(ascii_char, qcheck.bounded_int(0, 20))
    |> qcheck.map(fn(codepoints) {
      codepoints
      |> list.map(fn(c) {
        let assert Ok(cp) = string.utf_codepoint(c)
        cp
      })
      |> string.from_utf_codepoints
    })

  qcheck.run(qcheck.default_config() |> qcheck.with_test_count(100), gen, fn(s) {
    assert utils.is_ascii(s) == True
    Nil
  })
}

pub fn non_ascii_rejected_property_test() {
  let non_ascii_char = qcheck.bounded_int(128, 1000)
  let gen =
    non_ascii_char
    |> qcheck.map(fn(non_ascii) {
      let assert Ok(cp) = string.utf_codepoint(non_ascii)
      "test" <> string.from_utf_codepoints([cp])
    })

  qcheck.run(qcheck.default_config() |> qcheck.with_test_count(100), gen, fn(s) {
    assert utils.is_ascii(s) == False
    Nil
  })
}

pub fn chunk_string_single_chunk_test() {
  assert utils.chunk_string("hello", 10) == ["hello"]
  assert utils.chunk_string("hello", 5) == ["hello"]
}

pub fn chunk_string_multiple_chunks_test() {
  assert utils.chunk_string("hello world", 5) == ["hello", " worl", "d"]
  assert utils.chunk_string("abcdef", 2) == ["ab", "cd", "ef"]
}

pub fn chunk_string_empty_test() {
  assert utils.chunk_string("", 5) == [""]
}
