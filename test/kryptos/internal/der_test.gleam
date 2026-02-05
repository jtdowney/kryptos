import gleam/bit_array
import gleam/list
import gleam/time/calendar
import gleam/time/timestamp
import kryptos/internal/der
import qcheck

pub fn encode_length_short_form_test() {
  assert der.encode_length(0) == Ok(<<0>>)
  assert der.encode_length(1) == Ok(<<1>>)
  assert der.encode_length(127) == Ok(<<127>>)
}

pub fn encode_length_long_form_81_test() {
  assert der.encode_length(128) == Ok(<<0x81, 128>>)
  assert der.encode_length(255) == Ok(<<0x81, 255>>)
}

pub fn encode_length_long_form_82_test() {
  assert der.encode_length(256) == Ok(<<0x82, 0x01, 0x00>>)
  assert der.encode_length(65_535) == Ok(<<0x82, 0xff, 0xff>>)
}

pub fn encode_length_rejects_too_large_test() {
  assert der.encode_length(65_536) == Error(Nil)
  assert der.encode_length(100_000) == Error(Nil)
}

pub fn encode_length_rejects_negative_test() {
  assert der.encode_length(-1) == Error(Nil)
  assert der.encode_length(-100) == Error(Nil)
}

pub fn encode_length_canonical_test() {
  assert der.encode_length(127) == Ok(<<127>>)
  assert der.encode_length(128) == Ok(<<0x81, 128>>)
  assert der.encode_length(255) == Ok(<<0x81, 255>>)
  assert der.encode_length(256) == Ok(<<0x82, 0x01, 0x00>>)
}

pub fn parse_length_short_form_test() {
  assert der.parse_length(<<0>>) == Ok(#(0, <<>>))
  assert der.parse_length(<<1>>) == Ok(#(1, <<>>))
  assert der.parse_length(<<127>>) == Ok(#(127, <<>>))
  assert der.parse_length(<<100, 0xaa, 0xbb>>) == Ok(#(100, <<0xaa, 0xbb>>))
}

pub fn parse_length_long_form_128_test() {
  assert der.parse_length(<<0x81, 128>>) == Ok(#(128, <<>>))
  assert der.parse_length(<<0x81, 255>>) == Ok(#(255, <<>>))
  assert der.parse_length(<<0x81, 200, 0xcc>>) == Ok(#(200, <<0xcc>>))
}

pub fn parse_length_long_form_256_test() {
  assert der.parse_length(<<0x82, 0x01, 0x00>>) == Ok(#(256, <<>>))
  assert der.parse_length(<<0x82, 0xff, 0xff>>) == Ok(#(65_535, <<>>))
  assert der.parse_length(<<0x82, 0x02, 0x00, 0xdd>>) == Ok(#(512, <<0xdd>>))
}

pub fn parse_length_rejects_noncanonical_81_test() {
  assert der.parse_length(<<0x81, 0>>) == Error(Nil)
  assert der.parse_length(<<0x81, 127>>) == Error(Nil)
}

pub fn parse_length_rejects_noncanonical_82_test() {
  assert der.parse_length(<<0x82, 0x00, 0x00>>) == Error(Nil)
  assert der.parse_length(<<0x82, 0x00, 0xff>>) == Error(Nil)
}

pub fn parse_length_empty_input_test() {
  assert der.parse_length(<<>>) == Error(Nil)
}

pub fn length_roundtrip_property_test() {
  let gen = qcheck.bounded_int(0, 65_535)

  qcheck.run(qcheck.default_config(), gen, fn(len) {
    let assert Ok(encoded) = der.encode_length(len)
    let result = der.parse_length(encoded)
    assert result == Ok(#(len, <<>>))
  })
}

pub fn encode_integer_zero_test() {
  assert der.encode_integer(<<>>) == Ok(<<0x02, 0x01, 0x00>>)
  assert der.encode_integer(<<0x00>>) == Ok(<<0x02, 0x01, 0x00>>)
}

pub fn encode_integer_strips_leading_zeros_test() {
  assert der.encode_integer(<<0x00, 0x00, 0x42>>) == Ok(<<0x02, 0x01, 0x42>>)
  assert der.encode_integer(<<0x00, 0x00, 0x00, 0x01>>)
    == Ok(<<0x02, 0x01, 0x01>>)
}

pub fn encode_integer_adds_high_bit_padding_test() {
  assert der.encode_integer(<<0x80>>) == Ok(<<0x02, 0x02, 0x00, 0x80>>)
  assert der.encode_integer(<<0xff>>) == Ok(<<0x02, 0x02, 0x00, 0xff>>)
}

pub fn encode_integer_preserves_needed_zeros_test() {
  assert der.encode_integer(<<0x00, 0x80>>) == Ok(<<0x02, 0x02, 0x00, 0x80>>)
}

pub fn encode_integer_tag_and_length_test() {
  let assert Ok(<<0x02, _:bits>> as result) =
    der.encode_integer(<<0x01, 0x02, 0x03>>)
  assert result == <<0x02, 0x03, 0x01, 0x02, 0x03>>
}

pub fn encode_integer_large_value_test() {
  let big_value = <<0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08>>
  let result = der.encode_integer(big_value)
  assert result
    == Ok(<<0x02, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08>>)
}

pub fn parse_integer_single_byte_test() {
  assert der.parse_integer(<<0x02, 0x01, 0x00>>) == Ok(#(<<0x00>>, <<>>))
  assert der.parse_integer(<<0x02, 0x01, 0x7f>>) == Ok(#(<<0x7f>>, <<>>))
  assert der.parse_integer(<<0x02, 0x01, 0x42>>) == Ok(#(<<0x42>>, <<>>))
}

pub fn parse_integer_high_bit_padding_test() {
  assert der.parse_integer(<<0x02, 0x02, 0x00, 0x80>>)
    == Ok(#(<<0x00, 0x80>>, <<>>))
  assert der.parse_integer(<<0x02, 0x02, 0x00, 0xff>>)
    == Ok(#(<<0x00, 0xff>>, <<>>))
}

pub fn parse_integer_rejects_empty_test() {
  assert der.parse_integer(<<0x02, 0x00>>) == Error(Nil)
}

pub fn parse_integer_rejects_nonminimal_zeros_test() {
  assert der.parse_integer(<<0x02, 0x02, 0x00, 0x7f>>) == Error(Nil)
  assert der.parse_integer(<<0x02, 0x02, 0x00, 0x00>>) == Error(Nil)
}

pub fn parse_integer_preserves_remaining_test() {
  assert der.parse_integer(<<0x02, 0x01, 0x42, 0xaa, 0xbb>>)
    == Ok(#(<<0x42>>, <<0xaa, 0xbb>>))
}

pub fn parse_integer_wrong_tag_test() {
  assert der.parse_integer(<<0x03, 0x01, 0x42>>) == Error(Nil)
}

pub fn parse_integer_truncated_test() {
  assert der.parse_integer(<<0x02, 0x05, 0x42, 0x43>>) == Error(Nil)
}

pub fn integer_roundtrip_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(50),
    gen,
    fn(bytes) {
      let assert Ok(encoded) = der.encode_integer(bytes)
      let result = der.parse_integer(encoded)
      let assert Ok(#(_value, remaining)) = result
      assert remaining == <<>>
    },
  )
}

pub fn encode_sequence_empty_test() {
  assert der.encode_sequence(<<>>) == Ok(<<0x30, 0x00>>)
}

pub fn encode_sequence_with_content_test() {
  assert der.encode_sequence(<<0x01, 0x02, 0x03>>)
    == Ok(<<0x30, 0x03, 0x01, 0x02, 0x03>>)
}

pub fn encode_sequence_length_encoding_test() {
  let content = bit_array.concat(list.repeat(<<0xaa>>, 130))
  let assert Ok(<<0x30, _:bits>> as result) = der.encode_sequence(content)
  assert result == bit_array.concat([<<0x30, 0x81, 130>>, content])
}

pub fn parse_sequence_valid_test() {
  let bytes = <<0x30, 0x03, 0x01, 0x02, 0x03>>
  assert der.parse_sequence(bytes) == Ok(#(<<0x01, 0x02, 0x03>>, <<>>))
}

pub fn parse_sequence_empty_test() {
  let bytes = <<0x30, 0x00>>
  assert der.parse_sequence(bytes) == Ok(#(<<>>, <<>>))
}

pub fn parse_sequence_wrong_tag_test() {
  let bytes = <<0x31, 0x03, 0x01, 0x02, 0x03>>
  assert der.parse_sequence(bytes) == Error(Nil)
}

pub fn parse_sequence_truncated_test() {
  let bytes = <<0x30, 0x05, 0x01, 0x02>>
  assert der.parse_sequence(bytes) == Error(Nil)
}

pub fn parse_sequence_with_remaining_test() {
  let bytes = <<0x30, 0x02, 0xaa, 0xbb, 0xcc, 0xdd>>
  assert der.parse_sequence(bytes) == Ok(#(<<0xaa, 0xbb>>, <<0xcc, 0xdd>>))
}

pub fn sequence_roundtrip_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(qcheck.default_config(), gen, fn(content) {
    let assert Ok(encoded) = der.encode_sequence(content)
    let result = der.parse_sequence(encoded)
    assert result == Ok(#(content, <<>>))
  })
}

pub fn sequence_large_content_test() {
  let content = bit_array.concat(list.repeat(<<0xaa>>, 1000))
  let assert Ok(encoded) = der.encode_sequence(content)
  let assert Ok(#(parsed, <<>>)) = der.parse_sequence(encoded)
  assert parsed == content
}

pub fn encode_set_tag_test() {
  assert der.encode_set(<<0x01, 0x02>>) == Ok(<<0x31, 0x02, 0x01, 0x02>>)
}

pub fn encode_set_empty_test() {
  assert der.encode_set(<<>>) == Ok(<<0x31, 0x00>>)
}

pub fn parse_set_valid_test() {
  let bytes = <<0x31, 0x03, 0x01, 0x02, 0x03>>
  assert der.parse_set(bytes) == Ok(#(<<0x01, 0x02, 0x03>>, <<>>))
}

pub fn parse_set_empty_test() {
  let bytes = <<0x31, 0x00>>
  assert der.parse_set(bytes) == Ok(#(<<>>, <<>>))
}

pub fn parse_set_wrong_tag_test() {
  let bytes = <<0x30, 0x03, 0x01, 0x02, 0x03>>
  assert der.parse_set(bytes) == Error(Nil)
}

pub fn set_roundtrip_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(qcheck.default_config(), gen, fn(content) {
    let assert Ok(encoded) = der.encode_set(content)
    let result = der.parse_set(encoded)
    assert result == Ok(#(content, <<>>))
  })
}

pub fn encode_bit_string_prepends_zero_test() {
  let result = der.encode_bit_string(<<0xaa, 0xbb, 0xcc>>)
  assert result == Ok(<<0x03, 0x04, 0x00, 0xaa, 0xbb, 0xcc>>)
}

pub fn encode_bit_string_tag_test() {
  let assert Ok(<<0x03, _:bits>>) = der.encode_bit_string(<<0x42>>)
}

pub fn encode_bit_string_length_test() {
  let result = der.encode_bit_string(<<0x01, 0x02, 0x03>>)
  assert result == Ok(<<0x03, 0x04, 0x00, 0x01, 0x02, 0x03>>)
}

pub fn encode_bit_string_empty_test() {
  let result = der.encode_bit_string(<<>>)
  assert result == Ok(<<0x03, 0x01, 0x00>>)
}

pub fn parse_bit_string_valid_test() {
  let bytes = <<0x03, 0x04, 0x00, 0xaa, 0xbb, 0xcc>>
  assert der.parse_bit_string(bytes) == Ok(#(<<0xaa, 0xbb, 0xcc>>, <<>>))
}

pub fn parse_bit_string_rejects_nonzero_unused_test() {
  let bytes = <<0x03, 0x04, 0x01, 0xaa, 0xbb, 0xcc>>
  assert der.parse_bit_string(bytes) == Error(Nil)
}

pub fn parse_bit_string_rejects_empty_test() {
  let bytes = <<0x03, 0x00>>
  assert der.parse_bit_string(bytes) == Error(Nil)
}

pub fn parse_bit_string_preserves_remaining_test() {
  let bytes = <<0x03, 0x03, 0x00, 0xaa, 0xbb, 0xcc, 0xdd>>
  assert der.parse_bit_string(bytes) == Ok(#(<<0xaa, 0xbb>>, <<0xcc, 0xdd>>))
}

pub fn parse_bit_string_wrong_tag_test() {
  let bytes = <<0x04, 0x04, 0x00, 0xaa, 0xbb, 0xcc>>
  assert der.parse_bit_string(bytes) == Error(Nil)
}

pub fn parse_bit_string_empty_content_test() {
  let bytes = <<0x03, 0x01, 0x00>>
  assert der.parse_bit_string(bytes) == Ok(#(<<>>, <<>>))
}

pub fn bit_string_roundtrip_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(qcheck.default_config(), gen, fn(content) {
    let assert Ok(encoded) = der.encode_bit_string(content)
    let result = der.parse_bit_string(encoded)
    assert result == Ok(#(content, <<>>))
  })
}

pub fn encode_octet_string_tag_test() {
  let assert Ok(<<0x04, _:bits>>) = der.encode_octet_string(<<0x42>>)
}

pub fn encode_octet_string_empty_test() {
  assert der.encode_octet_string(<<>>) == Ok(<<0x04, 0x00>>)
}

pub fn encode_octet_string_content_test() {
  assert der.encode_octet_string(<<0xaa, 0xbb, 0xcc>>)
    == Ok(<<0x04, 0x03, 0xaa, 0xbb, 0xcc>>)
}

pub fn parse_octet_string_valid_test() {
  let bytes = <<0x04, 0x03, 0xaa, 0xbb, 0xcc>>
  assert der.parse_octet_string(bytes) == Ok(#(<<0xaa, 0xbb, 0xcc>>, <<>>))
}

pub fn parse_octet_string_empty_test() {
  let bytes = <<0x04, 0x00>>
  assert der.parse_octet_string(bytes) == Ok(#(<<>>, <<>>))
}

pub fn parse_octet_string_wrong_tag_test() {
  let bytes = <<0x03, 0x03, 0xaa, 0xbb, 0xcc>>
  assert der.parse_octet_string(bytes) == Error(Nil)
}

pub fn parse_octet_string_with_remaining_test() {
  let bytes = <<0x04, 0x02, 0xaa, 0xbb, 0xcc, 0xdd>>
  assert der.parse_octet_string(bytes) == Ok(#(<<0xaa, 0xbb>>, <<0xcc, 0xdd>>))
}

pub fn parse_octet_string_truncated_test() {
  let bytes = <<0x04, 0x05, 0xaa, 0xbb>>
  assert der.parse_octet_string(bytes) == Error(Nil)
}

pub fn octet_string_roundtrip_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(qcheck.default_config(), gen, fn(content) {
    let assert Ok(encoded) = der.encode_octet_string(content)
    let result = der.parse_octet_string(encoded)
    assert result == Ok(#(content, <<>>))
  })
}

pub fn encode_utf8_string_tag_test() {
  let assert Ok(<<0x0c, _:bits>>) = der.encode_utf8_string("test")
}

pub fn encode_utf8_string_content_test() {
  assert der.encode_utf8_string("hi") == Ok(<<0x0c, 0x02, 0x68, 0x69>>)
}

pub fn encode_utf8_string_unicode_test() {
  let result = der.encode_utf8_string("🔑")
  assert result == Ok(<<0x0c, 0x04, 0xf0, 0x9f, 0x94, 0x91>>)
}

pub fn parse_utf8_string_valid_test() {
  let bytes = <<0x0c, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f>>
  assert der.parse_utf8_string(bytes) == Ok(#("hello", <<>>))
}

pub fn parse_utf8_string_unicode_test() {
  let bytes = <<0x0c, 0x04, 0xf0, 0x9f, 0x94, 0x91>>
  assert der.parse_utf8_string(bytes) == Ok(#("🔑", <<>>))
}

pub fn parse_utf8_string_empty_test() {
  let bytes = <<0x0c, 0x00>>
  assert der.parse_utf8_string(bytes) == Ok(#("", <<>>))
}

pub fn parse_utf8_string_invalid_utf8_test() {
  let bytes = <<0x0c, 0x02, 0xff, 0xfe>>
  assert der.parse_utf8_string(bytes) == Error(Nil)
}

pub fn parse_utf8_string_with_remaining_test() {
  let bytes = <<0x0c, 0x02, 0x68, 0x69, 0xaa, 0xbb>>
  assert der.parse_utf8_string(bytes) == Ok(#("hi", <<0xaa, 0xbb>>))
}

pub fn utf8_string_roundtrip_property_test() {
  let gen = qcheck.string_from(qcheck.printable_ascii_codepoint())

  qcheck.run(qcheck.default_config(), gen, fn(s) {
    let assert Ok(encoded) = der.encode_utf8_string(s)
    let result = der.parse_utf8_string(encoded)
    assert result == Ok(#(s, <<>>))
  })
}

pub fn encode_printable_string_tag_test() {
  let assert Ok(<<0x13, _:bits>>) = der.encode_printable_string("test")
}

pub fn encode_printable_string_valid_chars_test() {
  assert der.encode_printable_string("") == Ok(<<0x13, 0x00>>)
  let assert Ok(_) = der.encode_printable_string("ABC")
  let assert Ok(_) = der.encode_printable_string("abc")
  let assert Ok(_) = der.encode_printable_string("012")
  let assert Ok(_) = der.encode_printable_string(" ")
  let assert Ok(_) = der.encode_printable_string("'")
  let assert Ok(_) = der.encode_printable_string("()")
  let assert Ok(_) = der.encode_printable_string("+,-./:=?")
  let assert Ok(_) = der.encode_printable_string("US")
  let assert Ok(_) = der.encode_printable_string("GB")
}

pub fn encode_printable_string_invalid_chars_test() {
  assert der.encode_printable_string("@") == Error(Nil)
  assert der.encode_printable_string("#") == Error(Nil)
  assert der.encode_printable_string("!") == Error(Nil)
  assert der.encode_printable_string("*") == Error(Nil)
  assert der.encode_printable_string("&") == Error(Nil)
  assert der.encode_printable_string("$") == Error(Nil)
  assert der.encode_printable_string("%") == Error(Nil)
  assert der.encode_printable_string("^") == Error(Nil)
  assert der.encode_printable_string("_") == Error(Nil)
  assert der.encode_printable_string("<>") == Error(Nil)
  assert der.encode_printable_string("[") == Error(Nil)
  assert der.encode_printable_string("]") == Error(Nil)
  assert der.encode_printable_string("{") == Error(Nil)
  assert der.encode_printable_string("}") == Error(Nil)
  assert der.encode_printable_string("é") == Error(Nil)
  assert der.encode_printable_string("ñ") == Error(Nil)
  assert der.encode_printable_string("US@") == Error(Nil)
  assert der.encode_printable_string("hello!") == Error(Nil)
}

pub fn parse_printable_string_valid_test() {
  let bytes = <<0x13, 0x04, 0x54, 0x65, 0x73, 0x74>>
  assert der.parse_printable_string(bytes) == Ok(#("Test", <<>>))
}

pub fn parse_printable_string_empty_test() {
  let bytes = <<0x13, 0x00>>
  assert der.parse_printable_string(bytes) == Ok(#("", <<>>))
}

pub fn printable_string_roundtrip_property_test() {
  let printable_string_rest = [
    // A-Z (except 'A' which is first)
    66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
    85, 86, 87, 88, 89, 90,
    // a-z
    97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
    113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
    // 0-9
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
    // Special chars: space, '()+,-./:=?
    32, 39, 40, 41, 43, 44, 45, 46, 47, 58, 61, 63,
  ]
  let gen =
    qcheck.string_from(qcheck.codepoint_from_ints(65, printable_string_rest))

  qcheck.run(qcheck.default_config(), gen, fn(s) {
    let assert Ok(encoded) = der.encode_printable_string(s)
    let result = der.parse_printable_string(encoded)
    assert result == Ok(#(s, <<>>))
  })
}

pub fn encode_ia5_string_tag_test() {
  let assert Ok(<<0x16, _:bits>>) = der.encode_ia5_string("test")
}

pub fn parse_ia5_string_valid_test() {
  let bytes = <<0x16, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f>>
  assert der.parse_ia5_string(bytes) == Ok(#("hello", <<>>))
}

pub fn parse_ia5_string_empty_test() {
  let bytes = <<0x16, 0x00>>
  assert der.parse_ia5_string(bytes) == Ok(#("", <<>>))
}

pub fn ia5_string_roundtrip_property_test() {
  let gen = qcheck.string_from(qcheck.printable_ascii_codepoint())

  qcheck.run(qcheck.default_config(), gen, fn(s) {
    let assert Ok(encoded) = der.encode_ia5_string(s)
    let result = der.parse_ia5_string(encoded)
    assert result == Ok(#(s, <<>>))
  })
}

pub fn encode_string_empty_test() {
  assert der.encode_utf8_string("") == Ok(<<0x0c, 0x00>>)
  assert der.encode_printable_string("") == Ok(<<0x13, 0x00>>)
  assert der.encode_ia5_string("") == Ok(<<0x16, 0x00>>)
}

pub fn parse_teletex_string_ascii_test() {
  let bytes = <<0x14, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f>>
  assert der.parse_teletex_string(bytes) == Ok(#("hello", <<>>))
}

pub fn parse_teletex_string_latin1_test() {
  // Latin-1 character é (0xe9) should convert to UTF-8
  let bytes = <<0x14, 0x04, 0x63, 0x61, 0x66, 0xe9>>
  assert der.parse_teletex_string(bytes) == Ok(#("café", <<>>))
}

pub fn parse_teletex_string_empty_test() {
  let bytes = <<0x14, 0x00>>
  assert der.parse_teletex_string(bytes) == Ok(#("", <<>>))
}

pub fn parse_teletex_string_with_remaining_test() {
  let bytes = <<0x14, 0x02, 0x68, 0x69, 0xaa, 0xbb>>
  assert der.parse_teletex_string(bytes) == Ok(#("hi", <<0xaa, 0xbb>>))
}

pub fn parse_teletex_string_wrong_tag_test() {
  let bytes = <<0x0c, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f>>
  assert der.parse_teletex_string(bytes) == Error(Nil)
}

pub fn parse_bmp_string_ascii_test() {
  let bytes = <<0x1e, 0x04, 0x00, 0x68, 0x00, 0x69>>
  assert der.parse_bmp_string(bytes) == Ok(#("hi", <<>>))
}

pub fn parse_bmp_string_unicode_test() {
  let bytes = <<0x1e, 0x02, 0x20, 0xac>>
  assert der.parse_bmp_string(bytes) == Ok(#("€", <<>>))
}

pub fn parse_bmp_string_empty_test() {
  let bytes = <<0x1e, 0x00>>
  assert der.parse_bmp_string(bytes) == Ok(#("", <<>>))
}

pub fn parse_bmp_string_odd_length_rejected_test() {
  let bytes = <<0x1e, 0x03, 0x00, 0x68, 0x00>>
  assert der.parse_bmp_string(bytes) == Error(Nil)
}

pub fn parse_bmp_string_with_remaining_test() {
  let bytes = <<0x1e, 0x04, 0x00, 0x68, 0x00, 0x69, 0xcc, 0xdd>>
  assert der.parse_bmp_string(bytes) == Ok(#("hi", <<0xcc, 0xdd>>))
}

pub fn parse_bmp_string_wrong_tag_test() {
  let bytes = <<0x0c, 0x04, 0x00, 0x68, 0x00, 0x69>>
  assert der.parse_bmp_string(bytes) == Error(Nil)
}

pub fn parse_universal_string_ascii_test() {
  let bytes = <<0x1c, 0x04, 0x00, 0x00, 0x00, 0x41>>
  assert der.parse_universal_string(bytes) == Ok(#("A", <<>>))
}

pub fn parse_universal_string_unicode_test() {
  let bytes = <<0x1c, 0x04, 0x00, 0x01, 0xf5, 0x11>>
  assert der.parse_universal_string(bytes) == Ok(#("🔑", <<>>))
}

pub fn parse_universal_string_empty_test() {
  let bytes = <<0x1c, 0x00>>
  assert der.parse_universal_string(bytes) == Ok(#("", <<>>))
}

pub fn parse_universal_string_not_multiple_of_4_rejected_test() {
  let bytes = <<0x1c, 0x03, 0x00, 0x00, 0x00>>
  assert der.parse_universal_string(bytes) == Error(Nil)
}

pub fn parse_universal_string_with_remaining_test() {
  let bytes = <<0x1c, 0x04, 0x00, 0x00, 0x00, 0x41, 0xee, 0xff>>
  assert der.parse_universal_string(bytes) == Ok(#("A", <<0xee, 0xff>>))
}

pub fn parse_universal_string_wrong_tag_test() {
  let bytes = <<0x0c, 0x04, 0x00, 0x00, 0x00, 0x41>>
  assert der.parse_universal_string(bytes) == Error(Nil)
}

pub fn parse_bool_valid_test() {
  assert der.parse_bool(<<0x01, 0x01, 0xff>>) == Ok(#(True, <<>>))
  assert der.parse_bool(<<0x01, 0x01, 0x00>>) == Ok(#(False, <<>>))
  assert der.parse_bool(<<0x01, 0x01, 0x01>>) == Ok(#(True, <<>>))
}

pub fn parse_bool_with_remaining_test() {
  assert der.parse_bool(<<0x01, 0x01, 0xff, 0xaa, 0xbb>>)
    == Ok(#(True, <<0xaa, 0xbb>>))
}

pub fn parse_bool_invalid_test() {
  assert der.parse_bool(<<0x02, 0x01, 0xff>>) == Error(Nil)
  assert der.parse_bool(<<0x01, 0x02, 0xff, 0x00>>) == Error(Nil)
  assert der.parse_bool(<<>>) == Error(Nil)
}

pub fn bool_roundtrip_test() {
  let assert Ok(#(True, <<>>)) = der.parse_bool(der.encode_bool(True))
  let assert Ok(#(False, <<>>)) = der.parse_bool(der.encode_bool(False))
}

pub fn encode_oid_first_byte_test() {
  let result = der.encode_oid([1, 2])
  assert result == Ok(<<0x06, 0x01, 0x2a>>)
}

pub fn encode_oid_small_components_test() {
  let result = der.encode_oid([2, 5, 4, 3])
  assert result == Ok(<<0x06, 0x03, 0x55, 0x04, 0x03>>)
}

pub fn encode_oid_large_component_test() {
  let result = der.encode_oid([1, 2, 840])
  assert result == Ok(<<0x06, 0x03, 0x2a, 0x86, 0x48>>)
}

pub fn encode_oid_very_large_component_test() {
  let result = der.encode_oid([1, 2, 840, 113_549])
  assert result == Ok(<<0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d>>)
}

pub fn encode_oid_tag_test() {
  let assert Ok(<<0x06, _:bits>>) = der.encode_oid([1, 2, 3])
}

pub fn encode_oid_empty_returns_error_test() {
  assert der.encode_oid([]) == Error(Nil)
}

pub fn encode_oid_single_component_returns_error_test() {
  assert der.encode_oid([1]) == Error(Nil)
}

pub fn parse_oid_simple_test() {
  let bytes = <<0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d>>
  let result = der.parse_oid(bytes)
  assert result == Ok(#([1, 2, 840, 113_549], <<>>))
}

pub fn parse_oid_with_remaining_test() {
  let bytes = <<0x06, 0x03, 0x55, 0x04, 0x03, 0xaa, 0xbb>>
  let result = der.parse_oid(bytes)
  assert result == Ok(#([2, 5, 4, 3], <<0xaa, 0xbb>>))
}

pub fn parse_oid_rejects_unterminated_base128_test() {
  let bytes = <<0x06, 0x02, 0x2a, 0x81>>
  let result = der.parse_oid(bytes)
  assert result == Error(Nil)
}

pub fn parse_oid_rejects_multiple_unterminated_bytes_test() {
  let bytes = <<0x06, 0x03, 0x2a, 0x81, 0x82>>
  let result = der.parse_oid(bytes)
  assert result == Error(Nil)
}

pub fn parse_oid_accepts_multibyte_component_test() {
  let bytes = <<0x06, 0x04, 0x2a, 0x81, 0x00, 0x01>>
  let result = der.parse_oid(bytes)
  assert result == Ok(#([1, 2, 128, 1], <<>>))
}

pub fn parse_oid_common_name_test() {
  let bytes = <<0x06, 0x03, 0x55, 0x04, 0x03>>
  let result = der.parse_oid(bytes)
  assert result == Ok(#([2, 5, 4, 3], <<>>))
}

pub fn parse_oid_rsa_encryption_test() {
  let bytes = <<
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  >>
  let result = der.parse_oid(bytes)
  assert result == Ok(#([1, 2, 840, 113_549, 1, 1, 1], <<>>))
}

pub fn parse_oid_sha256_test() {
  let bytes = <<
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
  >>
  let result = der.parse_oid(bytes)
  assert result == Ok(#([2, 16, 840, 1, 101, 3, 4, 2, 1], <<>>))
}

pub fn encode_oid_large_first_component_180_test() {
  let result = der.encode_oid([2, 100])
  assert result == Ok(<<0x06, 0x02, 0x81, 0x34>>)
}

pub fn parse_oid_large_first_component_180_test() {
  let bytes = <<0x06, 0x02, 0x81, 0x34>>
  let result = der.parse_oid(bytes)
  assert result == Ok(#([2, 100], <<>>))
}

pub fn encode_oid_large_first_component_1079_test() {
  let result = der.encode_oid([2, 999])
  assert result == Ok(<<0x06, 0x02, 0x88, 0x37>>)
}

pub fn parse_oid_large_first_component_1079_test() {
  let bytes = <<0x06, 0x02, 0x88, 0x37>>
  let result = der.parse_oid(bytes)
  assert result == Ok(#([2, 999], <<>>))
}

pub fn oid_large_first_component_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.bounded_int(40, 10_000),
      qcheck.list_from(qcheck.bounded_int(0, 100_000)),
    )

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(50),
    gen,
    fn(input) {
      let #(second, rest) = input
      let components = [2, second, ..rest]
      let assert Ok(encoded) = der.encode_oid(components)
      let result = der.parse_oid(encoded)
      assert result == Ok(#(components, <<>>))
    },
  )
}

pub fn parse_oid_empty_test() {
  let bytes = <<0x06, 0x00>>
  let result = der.parse_oid(bytes)
  assert result == Error(Nil)
}

pub fn oid_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.bounded_int(0, 2),
      qcheck.tuple2(
        qcheck.bounded_int(0, 39),
        qcheck.list_from(qcheck.bounded_int(0, 100_000)),
      ),
    )

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(50),
    gen,
    fn(input) {
      let #(first, #(second, rest)) = input
      let components = [first, second, ..rest]
      let assert Ok(encoded) = der.encode_oid(components)
      let result = der.parse_oid(encoded)
      assert result == Ok(#(components, <<>>))
    },
  )
}

pub fn encode_context_tag_test() {
  assert der.encode_context_tag(0, <<0x01, 0x02>>)
    == Ok(<<0xa0, 0x02, 0x01, 0x02>>)
  assert der.encode_context_tag(1, <<0xaa>>) == Ok(<<0xa1, 0x01, 0xaa>>)
  assert der.encode_context_tag(3, <<>>) == Ok(<<0xa3, 0x00>>)
}

pub fn encode_context_tag_content_test() {
  let content = <<0xde, 0xad, 0xbe, 0xef>>
  let result = der.encode_context_tag(5, content)
  assert result == Ok(<<0xa5, 0x04, 0xde, 0xad, 0xbe, 0xef>>)
}

pub fn parse_context_tag_0_test() {
  let bytes = <<0xa0, 0x03, 0x01, 0x02, 0x03>>
  assert der.parse_context_tag(bytes, 0) == Ok(#(<<0x01, 0x02, 0x03>>, <<>>))
}

pub fn parse_context_tag_1_test() {
  let bytes = <<0xa1, 0x03, 0x01, 0x02, 0x03>>
  assert der.parse_context_tag(bytes, 1) == Ok(#(<<0x01, 0x02, 0x03>>, <<>>))
}

pub fn parse_context_tag_2_test() {
  let bytes = <<0xa2, 0x02, 0xaa, 0xbb>>
  assert der.parse_context_tag(bytes, 2) == Ok(#(<<0xaa, 0xbb>>, <<>>))
}

pub fn parse_context_tag_wrong_tag_test() {
  let bytes = <<0xa0, 0x03, 0x01, 0x02, 0x03>>
  assert der.parse_context_tag(bytes, 1) == Error(Nil)
}

pub fn parse_context_tag_with_remaining_test() {
  let bytes = <<0xa0, 0x02, 0xaa, 0xbb, 0xcc, 0xdd>>
  assert der.parse_context_tag(bytes, 0)
    == Ok(#(<<0xaa, 0xbb>>, <<0xcc, 0xdd>>))
}

pub fn parse_context_tag_form_mismatch_test() {
  // Primitive tag (0x80) should not match constructed parser
  let bytes = <<0x80, 0x02, 0xaa, 0xbb>>
  assert der.parse_context_tag(bytes, 0) == Error(Nil)
}

pub fn context_tag_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(qcheck.bounded_int(0, 30), qcheck.byte_aligned_bit_array())

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(tag, content) = input
    let assert Ok(encoded) = der.encode_context_tag(tag, content)
    let result = der.parse_context_tag(encoded, tag)
    assert result == Ok(#(content, <<>>))
  })
}

pub fn encode_context_primitive_tag_test() {
  assert der.encode_context_primitive_tag(0, <<0x01, 0x02>>)
    == Ok(<<0x80, 0x02, 0x01, 0x02>>)
  assert der.encode_context_primitive_tag(2, <<0xaa>>)
    == Ok(<<0x82, 0x01, 0xaa>>)
}

pub fn parse_content_valid_test() {
  assert der.parse_content(<<0x01, 0x02, 0x03, 0x04>>, 2)
    == Ok(#(<<0x01, 0x02>>, <<0x03, 0x04>>))
  assert der.parse_content(<<0xaa, 0xbb>>, 2) == Ok(#(<<0xaa, 0xbb>>, <<>>))
  assert der.parse_content(<<0xaa, 0xbb, 0xcc>>, 0)
    == Ok(#(<<>>, <<0xaa, 0xbb, 0xcc>>))
}

pub fn parse_content_truncated_test() {
  assert der.parse_content(<<0x01, 0x02>>, 5) == Error(Nil)
  assert der.parse_content(<<>>, 1) == Error(Nil)
}

pub fn parse_tlv_valid_test() {
  assert der.parse_tlv(<<0x02, 0x01, 0x42>>) == Ok(#(0x02, <<0x42>>, <<>>))
  assert der.parse_tlv(<<0x30, 0x03, 0x01, 0x02, 0x03, 0xaa>>)
    == Ok(#(0x30, <<0x01, 0x02, 0x03>>, <<0xaa>>))
}

pub fn parse_tlv_empty_content_test() {
  assert der.parse_tlv(<<0x30, 0x00>>) == Ok(#(0x30, <<>>, <<>>))
}

pub fn parse_tlv_empty_input_test() {
  assert der.parse_tlv(<<>>) == Error(Nil)
}

pub fn parse_tlv_truncated_test() {
  assert der.parse_tlv(<<0x02, 0x05, 0x01, 0x02>>) == Error(Nil)
}

pub fn parse_tlv_long_form_length_test() {
  let content = bit_array.concat(list.repeat(<<0xaa>>, 130))
  let tlv = bit_array.concat([<<0x04, 0x81, 130>>, content])
  let result = der.parse_tlv(tlv)
  assert result == Ok(#(0x04, content, <<>>))
}

pub fn parse_tlv_with_remaining_test() {
  let bytes = <<0x02, 0x01, 0x42, 0x04, 0x02, 0xaa, 0xbb>>
  assert der.parse_tlv(bytes)
    == Ok(#(0x02, <<0x42>>, <<0x04, 0x02, 0xaa, 0xbb>>))
}

pub fn parse_tlv_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(qcheck.bounded_int(0, 255), qcheck.byte_aligned_bit_array())

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(50),
    gen,
    fn(input) {
      let #(tag, content) = input
      let assert Ok(len_bytes) = der.encode_length(bit_array.byte_size(content))
      let tlv = bit_array.concat([<<tag:8>>, len_bytes, content])
      let result = der.parse_tlv(tlv)
      assert result == Ok(#(tag, content, <<>>))
    },
  )
}

pub fn nested_sequence_test() {
  let assert Ok(inner) = der.encode_sequence(<<0x01, 0x02>>)
  let assert Ok(outer) = der.encode_sequence(inner)

  let assert Ok(#(outer_content, <<>>)) = der.parse_sequence(outer)
  let assert Ok(#(inner_content, <<>>)) = der.parse_sequence(outer_content)
  assert inner_content == <<0x01, 0x02>>
}

pub fn sequence_with_integer_test() {
  let assert Ok(int_encoded) = der.encode_integer(<<0x42>>)
  let assert Ok(seq) = der.encode_sequence(int_encoded)

  let assert Ok(#(seq_content, <<>>)) = der.parse_sequence(seq)
  let assert Ok(#(int_value, <<>>)) = der.parse_integer(seq_content)
  assert int_value == <<0x42>>
}

pub fn sequence_with_multiple_elements_test() {
  let assert Ok(oid) = der.encode_oid([1, 2, 3])
  let assert Ok(int) = der.encode_integer(<<0xff>>)
  let assert Ok(seq) = der.encode_sequence(bit_array.concat([oid, int]))

  let assert Ok(#(content, <<>>)) = der.parse_sequence(seq)
  let assert Ok(#([1, 2, 3], rest)) = der.parse_oid(content)
  let assert Ok(#(int_value, <<>>)) = der.parse_integer(rest)
  assert int_value == <<0x00, 0xff>>
}

pub fn set_with_utf8_string_test() {
  let assert Ok(str) = der.encode_utf8_string("test")
  let assert Ok(set) = der.encode_set(str)

  let assert Ok(#(set_content, <<>>)) = der.parse_set(set)
  let assert Ok(#(str_value, <<>>)) = der.parse_utf8_string(set_content)
  assert str_value == "test"
}

pub fn context_tag_with_octet_string_test() {
  let assert Ok(octet) = der.encode_octet_string(<<0xde, 0xad, 0xbe, 0xef>>)
  let assert Ok(tagged) = der.encode_context_tag(0, octet)

  let assert Ok(#(tag_content, <<>>)) = der.parse_context_tag(tagged, 0)
  let assert Ok(#(octet_value, <<>>)) = der.parse_octet_string(tag_content)
  assert octet_value == <<0xde, 0xad, 0xbe, 0xef>>
}

pub fn bit_string_containing_sequence_test() {
  let assert Ok(seq) = der.encode_sequence(<<0x01, 0x02, 0x03>>)
  let assert Ok(bit_str) = der.encode_bit_string(seq)

  let assert Ok(#(bit_content, <<>>)) = der.parse_bit_string(bit_str)
  let assert Ok(#(seq_content, <<>>)) = der.parse_sequence(bit_content)
  assert seq_content == <<0x01, 0x02, 0x03>>
}

pub fn parse_utc_time_test() {
  let input = <<0x17, 13, "250615143000Z":utf8>>
  let assert Ok(#(ts, <<>>)) = der.parse_utc_time(input)
  let expected = make_timestamp(2025, 6, 15, 14, 30, 0)
  assert ts == expected
}

pub fn encode_generalized_time_test() {
  let ts = make_timestamp(2050, 12, 31, 23, 59, 59)
  let assert Ok(encoded) = der.encode_generalized_time(ts)
  assert encoded == <<0x18, 15, "20501231235959Z":utf8>>
}

pub fn parse_generalized_time_test() {
  let input = <<0x18, 15, "20501231235959Z":utf8>>
  let assert Ok(#(ts, <<>>)) = der.parse_generalized_time(input)
  let expected = make_timestamp(2050, 12, 31, 23, 59, 59)
  assert ts == expected
}

pub fn utc_time_handles_y2k_window_test() {
  let input_2000 = <<0x17, 13, "000101000000Z":utf8>>
  let assert Ok(#(ts_2000, _)) = der.parse_utc_time(input_2000)
  let expected_2000 = make_timestamp(2000, 1, 1, 0, 0, 0)
  assert ts_2000 == expected_2000

  let input_1999 = <<0x17, 13, "991231235959Z":utf8>>
  let assert Ok(#(ts_1999, _)) = der.parse_utc_time(input_1999)
  let expected_1999 = make_timestamp(1999, 12, 31, 23, 59, 59)
  assert ts_1999 == expected_1999
}

pub fn utc_time_roundtrip_property_test() {
  let gen =
    qcheck.tuple6(
      qcheck.bounded_int(1950, 2049),
      qcheck.bounded_int(1, 12),
      qcheck.bounded_int(1, 28),
      qcheck.bounded_int(0, 23),
      qcheck.bounded_int(0, 59),
      qcheck.bounded_int(0, 59),
    )

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(50),
    gen,
    fn(input) {
      let #(year, month, day, hour, minute, second) = input
      let ts = make_timestamp(year, month, day, hour, minute, second)
      let assert Ok(encoded) = der.encode_timestamp(ts)
      let assert Ok(#(parsed_ts, <<>>)) = der.parse_utc_time(encoded)
      assert parsed_ts == ts
    },
  )
}

pub fn generalized_time_roundtrip_property_test() {
  let gen =
    qcheck.tuple6(
      qcheck.bounded_int(1, 9999),
      qcheck.bounded_int(1, 12),
      qcheck.bounded_int(1, 28),
      qcheck.bounded_int(0, 23),
      qcheck.bounded_int(0, 59),
      qcheck.bounded_int(0, 59),
    )

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(50),
    gen,
    fn(input) {
      let #(year, month, day, hour, minute, second) = input
      let ts = make_timestamp(year, month, day, hour, minute, second)
      let assert Ok(encoded) = der.encode_generalized_time(ts)
      let assert Ok(#(parsed_ts, <<>>)) = der.parse_generalized_time(encoded)
      assert parsed_ts == ts
    },
  )
}

pub fn parse_utc_time_with_remaining_test() {
  let input = <<0x17, 13, "250615143000Z":utf8, 0xaa, 0xbb>>
  let assert Ok(#(ts, remaining)) = der.parse_utc_time(input)
  let expected = make_timestamp(2025, 6, 15, 14, 30, 0)
  assert ts == expected
  assert remaining == <<0xaa, 0xbb>>
}

pub fn parse_generalized_time_with_remaining_test() {
  let input = <<0x18, 15, "20501231235959Z":utf8, 0xcc, 0xdd>>
  let assert Ok(#(ts, remaining)) = der.parse_generalized_time(input)
  let expected = make_timestamp(2050, 12, 31, 23, 59, 59)
  assert ts == expected
  assert remaining == <<0xcc, 0xdd>>
}

pub fn parse_utc_time_wrong_tag_test() {
  let input = <<0x18, 13, "250615143000Z":utf8>>
  assert der.parse_utc_time(input) == Error(Nil)
}

pub fn parse_generalized_time_wrong_tag_test() {
  let input = <<0x17, 15, "20501231235959Z":utf8>>
  assert der.parse_generalized_time(input) == Error(Nil)
}

pub fn parse_utc_time_invalid_length_test() {
  let input = <<0x17, 12, "25061514300Z":utf8>>
  assert der.parse_utc_time(input) == Error(Nil)
}

pub fn parse_generalized_time_invalid_length_test() {
  let input = <<0x18, 14, "2050123123595Z":utf8>>
  assert der.parse_generalized_time(input) == Error(Nil)
}

pub fn parse_utc_time_missing_z_suffix_test() {
  let input = <<0x17, 13, "2506151430001":utf8>>
  assert der.parse_utc_time(input) == Error(Nil)
}

pub fn parse_generalized_time_missing_z_suffix_test() {
  let input = <<0x18, 15, "205012312359591":utf8>>
  assert der.parse_generalized_time(input) == Error(Nil)
}

fn make_timestamp(
  year: Int,
  month: Int,
  day: Int,
  hour: Int,
  minute: Int,
  second: Int,
) -> timestamp.Timestamp {
  let assert Ok(m) = calendar.month_from_int(month)
  timestamp.from_calendar(
    calendar.Date(year:, month: m, day:),
    calendar.TimeOfDay(
      hours: hour,
      minutes: minute,
      seconds: second,
      nanoseconds: 0,
    ),
    calendar.utc_offset,
  )
}
