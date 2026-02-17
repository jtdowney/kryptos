import bitty as p
import bitty/bytes as b
import gleam/bit_array
import gleam/list
import gleam/result
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
  let assert Ok(0) = p.run(der.length(), on: <<0>>)
  let assert Ok(1) = p.run(der.length(), on: <<1>>)
  let assert Ok(127) = p.run(der.length(), on: <<127>>)
  let assert Ok(#(100, <<0xaa, 0xbb>>)) =
    p.run_partial(der.length(), on: <<100, 0xaa, 0xbb>>)
}

pub fn parse_length_long_form_128_test() {
  let assert Ok(128) = p.run(der.length(), on: <<0x81, 128>>)
  let assert Ok(255) = p.run(der.length(), on: <<0x81, 255>>)
  let assert Ok(#(200, <<0xcc>>)) =
    p.run_partial(der.length(), on: <<0x81, 200, 0xcc>>)
}

pub fn parse_length_long_form_256_test() {
  let assert Ok(256) = p.run(der.length(), on: <<0x82, 0x01, 0x00>>)
  let assert Ok(65_535) = p.run(der.length(), on: <<0x82, 0xff, 0xff>>)
  let assert Ok(#(512, <<0xdd>>)) =
    p.run_partial(der.length(), on: <<0x82, 0x02, 0x00, 0xdd>>)
}

pub fn parse_length_rejects_noncanonical_81_test() {
  assert p.run(der.length(), on: <<0x81, 0>>) |> result.is_error
  assert p.run(der.length(), on: <<0x81, 127>>) |> result.is_error
}

pub fn parse_length_rejects_noncanonical_82_test() {
  assert p.run(der.length(), on: <<0x82, 0x00, 0x00>>) |> result.is_error
  assert p.run(der.length(), on: <<0x82, 0x00, 0xff>>) |> result.is_error
}

pub fn parse_length_empty_input_test() {
  assert p.run(der.length(), on: <<>>) |> result.is_error
}

pub fn length_roundtrip_property_test() {
  let gen = qcheck.bounded_int(0, 65_535)

  qcheck.run(qcheck.default_config(), gen, fn(len) {
    let assert Ok(encoded) = der.encode_length(len)
    let assert Ok(parsed) = p.run(der.length(), on: encoded)
    assert parsed == len
  })
}

pub fn encode_small_int_single_byte_values_test() {
  assert der.encode_small_int(0) == Ok(<<0x02, 0x01, 0x00>>)
  assert der.encode_small_int(1) == Ok(<<0x02, 0x01, 0x01>>)
  assert der.encode_small_int(127) == Ok(<<0x02, 0x01, 0x7f>>)
}

pub fn encode_small_int_high_bit_padding_test() {
  assert der.encode_small_int(128) == Ok(<<0x02, 0x02, 0x00, 0x80>>)
  assert der.encode_small_int(255) == Ok(<<0x02, 0x02, 0x00, 0xff>>)
}

pub fn encode_small_int_multibyte_boundaries_test() {
  assert der.encode_small_int(256) == Ok(<<0x02, 0x02, 0x01, 0x00>>)
  assert der.encode_small_int(0xffff) == Ok(<<0x02, 0x03, 0x00, 0xff, 0xff>>)
  assert der.encode_small_int(0x10000) == Ok(<<0x02, 0x03, 0x01, 0x00, 0x00>>)
  assert der.encode_small_int(0x1000000)
    == Ok(<<0x02, 0x04, 0x01, 0x00, 0x00, 0x00>>)
}

pub fn encode_small_int_max_accepted_test() {
  assert der.encode_small_int(0xffff_ffff)
    == Ok(<<0x02, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff>>)
}

pub fn encode_small_int_rejects_negative_test() {
  assert der.encode_small_int(-1) == Error(Nil)
  assert der.encode_small_int(-100) == Error(Nil)
}

pub fn encode_small_int_rejects_overflow_test() {
  assert der.encode_small_int(0x1_0000_0000) == Error(Nil)
  assert der.encode_small_int(0x1_0000_0001) == Error(Nil)
  assert der.encode_small_int(0xffff_ffff_ffff) == Error(Nil)
}

pub fn encode_small_int_roundtrip_property_test() {
  let gen = qcheck.bounded_int(0, 0xffff_ffff)

  qcheck.run(qcheck.default_config(), gen, fn(n) {
    let assert Ok(encoded) = der.encode_small_int(n)
    let assert Ok(parsed_bytes) = p.run(der.integer(), on: encoded)
    let assert Ok(re_encoded) = der.encode_integer(parsed_bytes)
    assert re_encoded == encoded
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
  let assert Ok(<<0x00>>) = p.run(der.integer(), on: <<0x02, 0x01, 0x00>>)
  let assert Ok(<<0x7f>>) = p.run(der.integer(), on: <<0x02, 0x01, 0x7f>>)
  let assert Ok(<<0x42>>) = p.run(der.integer(), on: <<0x02, 0x01, 0x42>>)
}

pub fn parse_integer_high_bit_padding_test() {
  let assert Ok(<<0x00, 0x80>>) =
    p.run(der.integer(), on: <<0x02, 0x02, 0x00, 0x80>>)
  let assert Ok(<<0x00, 0xff>>) =
    p.run(der.integer(), on: <<0x02, 0x02, 0x00, 0xff>>)
}

pub fn parse_integer_rejects_empty_test() {
  assert p.run(der.integer(), on: <<0x02, 0x00>>) |> result.is_error
}

pub fn parse_integer_rejects_nonminimal_zeros_test() {
  assert p.run(der.integer(), on: <<0x02, 0x02, 0x00, 0x7f>>)
    |> result.is_error
  assert p.run(der.integer(), on: <<0x02, 0x02, 0x00, 0x00>>)
    |> result.is_error
}

pub fn parse_integer_preserves_remaining_test() {
  let assert Ok(#(<<0x42>>, <<0xaa, 0xbb>>)) =
    p.run_partial(der.integer(), on: <<0x02, 0x01, 0x42, 0xaa, 0xbb>>)
}

pub fn parse_integer_wrong_tag_test() {
  assert p.run(der.integer(), on: <<0x03, 0x01, 0x42>>) |> result.is_error
}

pub fn parse_integer_truncated_test() {
  assert p.run(der.integer(), on: <<0x02, 0x05, 0x42, 0x43>>)
    |> result.is_error
}

pub fn integer_roundtrip_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(50),
    gen,
    fn(bytes) {
      let assert Ok(encoded) = der.encode_integer(bytes)
      let assert Ok(_) = p.run(der.integer(), on: encoded)
      Nil
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
  let assert Ok(<<0x01, 0x02, 0x03>>) =
    p.run(der.sequence(b.rest()), on: <<
      0x30,
      0x03,
      0x01,
      0x02,
      0x03,
    >>)
}

pub fn parse_sequence_empty_test() {
  let assert Ok(<<>>) = p.run(der.sequence(b.rest()), on: <<0x30, 0x00>>)
}

pub fn parse_sequence_wrong_tag_test() {
  assert p.run(der.sequence(b.rest()), on: <<
      0x31,
      0x03,
      0x01,
      0x02,
      0x03,
    >>)
    |> result.is_error
}

pub fn parse_sequence_truncated_test() {
  assert p.run(der.sequence(b.rest()), on: <<
      0x30,
      0x05,
      0x01,
      0x02,
    >>)
    |> result.is_error
}

pub fn parse_sequence_with_remaining_test() {
  let assert Ok(#(<<0xaa, 0xbb>>, <<0xcc, 0xdd>>)) =
    p.run_partial(der.sequence(b.rest()), on: <<
      0x30,
      0x02,
      0xaa,
      0xbb,
      0xcc,
      0xdd,
    >>)
}

pub fn sequence_roundtrip_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(qcheck.default_config(), gen, fn(content) {
    let assert Ok(encoded) = der.encode_sequence(content)
    let assert Ok(parsed) = p.run(der.sequence(b.rest()), on: encoded)
    assert parsed == content
  })
}

pub fn sequence_large_content_test() {
  let content = bit_array.concat(list.repeat(<<0xaa>>, 1000))
  let assert Ok(encoded) = der.encode_sequence(content)
  let assert Ok(parsed) = p.run(der.sequence(b.rest()), on: encoded)
  assert parsed == content
}

pub fn encode_set_tag_test() {
  assert der.encode_set(<<0x01, 0x02>>) == Ok(<<0x31, 0x02, 0x01, 0x02>>)
}

pub fn encode_set_empty_test() {
  assert der.encode_set(<<>>) == Ok(<<0x31, 0x00>>)
}

pub fn parse_set_valid_test() {
  let assert Ok(<<0x01, 0x02, 0x03>>) =
    p.run(der.set(b.rest()), on: <<0x31, 0x03, 0x01, 0x02, 0x03>>)
}

pub fn parse_set_empty_test() {
  let assert Ok(<<>>) = p.run(der.set(b.rest()), on: <<0x31, 0x00>>)
}

pub fn parse_set_wrong_tag_test() {
  assert p.run(der.set(b.rest()), on: <<
      0x30,
      0x03,
      0x01,
      0x02,
      0x03,
    >>)
    |> result.is_error
}

pub fn set_roundtrip_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(qcheck.default_config(), gen, fn(content) {
    let assert Ok(encoded) = der.encode_set(content)
    let assert Ok(parsed) = p.run(der.set(b.rest()), on: encoded)
    assert parsed == content
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
  let assert Ok(<<0xaa, 0xbb, 0xcc>>) =
    p.run(der.bit_string(), on: <<0x03, 0x04, 0x00, 0xaa, 0xbb, 0xcc>>)
}

pub fn parse_bit_string_rejects_nonzero_unused_test() {
  assert p.run(der.bit_string(), on: <<0x03, 0x04, 0x01, 0xaa, 0xbb, 0xcc>>)
    |> result.is_error
}

pub fn parse_bit_string_rejects_empty_test() {
  assert p.run(der.bit_string(), on: <<0x03, 0x00>>) |> result.is_error
}

pub fn parse_bit_string_preserves_remaining_test() {
  let assert Ok(#(<<0xaa, 0xbb>>, <<0xcc, 0xdd>>)) =
    p.run_partial(der.bit_string(), on: <<
      0x03,
      0x03,
      0x00,
      0xaa,
      0xbb,
      0xcc,
      0xdd,
    >>)
}

pub fn parse_bit_string_wrong_tag_test() {
  assert p.run(der.bit_string(), on: <<0x04, 0x04, 0x00, 0xaa, 0xbb, 0xcc>>)
    |> result.is_error
}

pub fn parse_bit_string_empty_content_test() {
  let assert Ok(<<>>) = p.run(der.bit_string(), on: <<0x03, 0x01, 0x00>>)
}

pub fn bit_string_roundtrip_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(qcheck.default_config(), gen, fn(content) {
    let assert Ok(encoded) = der.encode_bit_string(content)
    let assert Ok(parsed) = p.run(der.bit_string(), on: encoded)
    assert parsed == content
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
  let assert Ok(<<0xaa, 0xbb, 0xcc>>) =
    p.run(der.octet_string(), on: <<0x04, 0x03, 0xaa, 0xbb, 0xcc>>)
}

pub fn parse_octet_string_empty_test() {
  let assert Ok(<<>>) = p.run(der.octet_string(), on: <<0x04, 0x00>>)
}

pub fn parse_octet_string_wrong_tag_test() {
  assert p.run(der.octet_string(), on: <<0x03, 0x03, 0xaa, 0xbb, 0xcc>>)
    |> result.is_error
}

pub fn parse_octet_string_with_remaining_test() {
  let assert Ok(#(<<0xaa, 0xbb>>, <<0xcc, 0xdd>>)) =
    p.run_partial(der.octet_string(), on: <<
      0x04,
      0x02,
      0xaa,
      0xbb,
      0xcc,
      0xdd,
    >>)
}

pub fn parse_octet_string_truncated_test() {
  assert p.run(der.octet_string(), on: <<0x04, 0x05, 0xaa, 0xbb>>)
    |> result.is_error
}

pub fn octet_string_roundtrip_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(qcheck.default_config(), gen, fn(content) {
    let assert Ok(encoded) = der.encode_octet_string(content)
    let assert Ok(parsed) = p.run(der.octet_string(), on: encoded)
    assert parsed == content
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
  let assert Ok("hello") =
    p.run(der.utf8_string(), on: <<
      0x0c,
      0x05,
      0x68,
      0x65,
      0x6c,
      0x6c,
      0x6f,
    >>)
}

pub fn parse_utf8_string_unicode_test() {
  let assert Ok("🔑") =
    p.run(der.utf8_string(), on: <<0x0c, 0x04, 0xf0, 0x9f, 0x94, 0x91>>)
}

pub fn parse_utf8_string_empty_test() {
  let assert Ok("") = p.run(der.utf8_string(), on: <<0x0c, 0x00>>)
}

pub fn parse_utf8_string_invalid_utf8_test() {
  assert p.run(der.utf8_string(), on: <<0x0c, 0x02, 0xff, 0xfe>>)
    |> result.is_error
}

pub fn parse_utf8_string_with_remaining_test() {
  let assert Ok(#("hi", <<0xaa, 0xbb>>)) =
    p.run_partial(der.utf8_string(), on: <<
      0x0c,
      0x02,
      0x68,
      0x69,
      0xaa,
      0xbb,
    >>)
}

pub fn utf8_string_roundtrip_property_test() {
  let gen = qcheck.string_from(qcheck.printable_ascii_codepoint())

  qcheck.run(qcheck.default_config(), gen, fn(s) {
    let assert Ok(encoded) = der.encode_utf8_string(s)
    let assert Ok(parsed) = p.run(der.utf8_string(), on: encoded)
    assert parsed == s
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
  let assert Ok("Test") =
    p.run(der.printable_string(), on: <<0x13, 0x04, 0x54, 0x65, 0x73, 0x74>>)
}

pub fn parse_printable_string_empty_test() {
  let assert Ok("") = p.run(der.printable_string(), on: <<0x13, 0x00>>)
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
    let assert Ok(parsed) = p.run(der.printable_string(), on: encoded)
    assert parsed == s
  })
}

pub fn encode_ia5_string_tag_test() {
  let assert Ok(<<0x16, _:bits>>) = der.encode_ia5_string("test")
}

pub fn parse_ia5_string_valid_test() {
  let assert Ok("hello") =
    p.run(der.ia5_string(), on: <<0x16, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f>>)
}

pub fn parse_ia5_string_empty_test() {
  let assert Ok("") = p.run(der.ia5_string(), on: <<0x16, 0x00>>)
}

pub fn ia5_string_roundtrip_property_test() {
  let gen = qcheck.string_from(qcheck.printable_ascii_codepoint())

  qcheck.run(qcheck.default_config(), gen, fn(s) {
    let assert Ok(encoded) = der.encode_ia5_string(s)
    let assert Ok(parsed) = p.run(der.ia5_string(), on: encoded)
    assert parsed == s
  })
}

pub fn encode_string_empty_test() {
  assert der.encode_utf8_string("") == Ok(<<0x0c, 0x00>>)
  assert der.encode_printable_string("") == Ok(<<0x13, 0x00>>)
  assert der.encode_ia5_string("") == Ok(<<0x16, 0x00>>)
}

pub fn parse_teletex_string_ascii_test() {
  let assert Ok("hello") =
    p.run(der.teletex_string(), on: <<
      0x14,
      0x05,
      0x68,
      0x65,
      0x6c,
      0x6c,
      0x6f,
    >>)
}

pub fn parse_teletex_string_latin1_test() {
  let assert Ok("café") =
    p.run(der.teletex_string(), on: <<0x14, 0x04, 0x63, 0x61, 0x66, 0xe9>>)
}

pub fn parse_teletex_string_empty_test() {
  let assert Ok("") = p.run(der.teletex_string(), on: <<0x14, 0x00>>)
}

pub fn parse_teletex_string_with_remaining_test() {
  let assert Ok(#("hi", <<0xaa, 0xbb>>)) =
    p.run_partial(der.teletex_string(), on: <<
      0x14,
      0x02,
      0x68,
      0x69,
      0xaa,
      0xbb,
    >>)
}

pub fn parse_teletex_string_wrong_tag_test() {
  assert p.run(der.teletex_string(), on: <<
      0x0c,
      0x05,
      0x68,
      0x65,
      0x6c,
      0x6c,
      0x6f,
    >>)
    |> result.is_error
}

pub fn parse_bmp_string_ascii_test() {
  let assert Ok("hi") =
    p.run(der.bmp_string(), on: <<0x1e, 0x04, 0x00, 0x68, 0x00, 0x69>>)
}

pub fn parse_bmp_string_unicode_test() {
  let assert Ok("€") = p.run(der.bmp_string(), on: <<0x1e, 0x02, 0x20, 0xac>>)
}

pub fn parse_bmp_string_empty_test() {
  let assert Ok("") = p.run(der.bmp_string(), on: <<0x1e, 0x00>>)
}

pub fn parse_bmp_string_odd_length_rejected_test() {
  assert p.run(der.bmp_string(), on: <<0x1e, 0x03, 0x00, 0x68, 0x00>>)
    |> result.is_error
}

pub fn parse_bmp_string_with_remaining_test() {
  let assert Ok(#("hi", <<0xcc, 0xdd>>)) =
    p.run_partial(der.bmp_string(), on: <<
      0x1e,
      0x04,
      0x00,
      0x68,
      0x00,
      0x69,
      0xcc,
      0xdd,
    >>)
}

pub fn parse_bmp_string_wrong_tag_test() {
  assert p.run(der.bmp_string(), on: <<0x0c, 0x04, 0x00, 0x68, 0x00, 0x69>>)
    |> result.is_error
}

pub fn parse_universal_string_ascii_test() {
  let assert Ok("A") =
    p.run(der.universal_string(), on: <<0x1c, 0x04, 0x00, 0x00, 0x00, 0x41>>)
}

pub fn parse_universal_string_unicode_test() {
  let assert Ok("🔑") =
    p.run(der.universal_string(), on: <<0x1c, 0x04, 0x00, 0x01, 0xf5, 0x11>>)
}

pub fn parse_universal_string_empty_test() {
  let assert Ok("") = p.run(der.universal_string(), on: <<0x1c, 0x00>>)
}

pub fn parse_universal_string_not_multiple_of_4_rejected_test() {
  assert p.run(der.universal_string(), on: <<0x1c, 0x03, 0x00, 0x00, 0x00>>)
    |> result.is_error
}

pub fn parse_universal_string_with_remaining_test() {
  let assert Ok(#("A", <<0xee, 0xff>>)) =
    p.run_partial(der.universal_string(), on: <<
      0x1c,
      0x04,
      0x00,
      0x00,
      0x00,
      0x41,
      0xee,
      0xff,
    >>)
}

pub fn parse_universal_string_wrong_tag_test() {
  assert p.run(der.universal_string(), on: <<
      0x0c,
      0x04,
      0x00,
      0x00,
      0x00,
      0x41,
    >>)
    |> result.is_error
}

pub fn parse_bool_valid_test() {
  let assert Ok(True) = p.run(der.boolean(), on: <<0x01, 0x01, 0xff>>)
  let assert Ok(False) = p.run(der.boolean(), on: <<0x01, 0x01, 0x00>>)
  let assert Ok(True) = p.run(der.boolean(), on: <<0x01, 0x01, 0x01>>)
}

pub fn parse_bool_with_remaining_test() {
  let assert Ok(#(True, <<0xaa, 0xbb>>)) =
    p.run_partial(der.boolean(), on: <<0x01, 0x01, 0xff, 0xaa, 0xbb>>)
}

pub fn parse_bool_invalid_test() {
  assert p.run(der.boolean(), on: <<0x02, 0x01, 0xff>>) |> result.is_error
  assert p.run(der.boolean(), on: <<0x01, 0x02, 0xff, 0x00>>)
    |> result.is_error
  assert p.run(der.boolean(), on: <<>>) |> result.is_error
}

pub fn bool_roundtrip_test() {
  let assert Ok(True) = p.run(der.boolean(), on: der.encode_bool(True))
  let assert Ok(False) = p.run(der.boolean(), on: der.encode_bool(False))
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
  let assert Ok([1, 2, 840, 113_549]) =
    p.run(der.oid(), on: <<0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d>>)
}

pub fn parse_oid_with_remaining_test() {
  let assert Ok(#([2, 5, 4, 3], <<0xaa, 0xbb>>)) =
    p.run_partial(der.oid(), on: <<
      0x06,
      0x03,
      0x55,
      0x04,
      0x03,
      0xaa,
      0xbb,
    >>)
}

pub fn parse_oid_rejects_unterminated_base128_test() {
  assert p.run(der.oid(), on: <<0x06, 0x02, 0x2a, 0x81>>)
    |> result.is_error
}

pub fn parse_oid_rejects_multiple_unterminated_bytes_test() {
  assert p.run(der.oid(), on: <<0x06, 0x03, 0x2a, 0x81, 0x82>>)
    |> result.is_error
}

pub fn parse_oid_accepts_multibyte_component_test() {
  let assert Ok([1, 2, 128, 1]) =
    p.run(der.oid(), on: <<0x06, 0x04, 0x2a, 0x81, 0x00, 0x01>>)
}

pub fn parse_oid_common_name_test() {
  let assert Ok([2, 5, 4, 3]) =
    p.run(der.oid(), on: <<0x06, 0x03, 0x55, 0x04, 0x03>>)
}

pub fn parse_oid_rsa_encryption_test() {
  let assert Ok([1, 2, 840, 113_549, 1, 1, 1]) =
    p.run(der.oid(), on: <<
      0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    >>)
}

pub fn parse_oid_sha256_test() {
  let assert Ok([2, 16, 840, 1, 101, 3, 4, 2, 1]) =
    p.run(der.oid(), on: <<
      0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    >>)
}

pub fn encode_oid_large_first_component_180_test() {
  let result = der.encode_oid([2, 100])
  assert result == Ok(<<0x06, 0x02, 0x81, 0x34>>)
}

pub fn parse_oid_large_first_component_180_test() {
  let assert Ok([2, 100]) = p.run(der.oid(), on: <<0x06, 0x02, 0x81, 0x34>>)
}

pub fn encode_oid_large_first_component_1079_test() {
  let result = der.encode_oid([2, 999])
  assert result == Ok(<<0x06, 0x02, 0x88, 0x37>>)
}

pub fn parse_oid_large_first_component_1079_test() {
  let assert Ok([2, 999]) = p.run(der.oid(), on: <<0x06, 0x02, 0x88, 0x37>>)
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
      let assert Ok(parsed) = p.run(der.oid(), on: encoded)
      assert parsed == components
    },
  )
}

pub fn parse_oid_empty_test() {
  assert p.run(der.oid(), on: <<0x06, 0x00>>) |> result.is_error
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
      let assert Ok(parsed) = p.run(der.oid(), on: encoded)
      assert parsed == components
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
  let assert Ok(<<0x01, 0x02, 0x03>>) =
    p.run(der.context_tag(0, b.rest()), on: <<
      0xa0,
      0x03,
      0x01,
      0x02,
      0x03,
    >>)
}

pub fn parse_context_tag_1_test() {
  let assert Ok(<<0x01, 0x02, 0x03>>) =
    p.run(der.context_tag(1, b.rest()), on: <<
      0xa1,
      0x03,
      0x01,
      0x02,
      0x03,
    >>)
}

pub fn parse_context_tag_2_test() {
  let assert Ok(<<0xaa, 0xbb>>) =
    p.run(der.context_tag(2, b.rest()), on: <<
      0xa2,
      0x02,
      0xaa,
      0xbb,
    >>)
}

pub fn parse_context_tag_wrong_tag_test() {
  assert p.run(der.context_tag(1, b.rest()), on: <<
      0xa0,
      0x03,
      0x01,
      0x02,
      0x03,
    >>)
    |> result.is_error
}

pub fn parse_context_tag_with_remaining_test() {
  let assert Ok(#(<<0xaa, 0xbb>>, <<0xcc, 0xdd>>)) =
    p.run_partial(der.context_tag(0, b.rest()), on: <<
      0xa0,
      0x02,
      0xaa,
      0xbb,
      0xcc,
      0xdd,
    >>)
}

pub fn parse_context_tag_form_mismatch_test() {
  assert p.run(der.context_tag(0, b.rest()), on: <<
      0x80,
      0x02,
      0xaa,
      0xbb,
    >>)
    |> result.is_error
}

pub fn context_tag_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(qcheck.bounded_int(0, 30), qcheck.byte_aligned_bit_array())

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(tag, content) = input
    let assert Ok(encoded) = der.encode_context_tag(tag, content)
    let assert Ok(parsed) = p.run(der.context_tag(tag, b.rest()), on: encoded)
    assert parsed == content
  })
}

pub fn encode_context_primitive_tag_test() {
  assert der.encode_context_primitive_tag(0, <<0x01, 0x02>>)
    == Ok(<<0x80, 0x02, 0x01, 0x02>>)
  assert der.encode_context_primitive_tag(2, <<0xaa>>)
    == Ok(<<0x82, 0x01, 0xaa>>)
}

pub fn parse_content_valid_test() {
  let assert Ok(#(<<0x01, 0x02>>, <<0x03, 0x04>>)) =
    p.run_partial(b.take(bytes: 2), on: <<0x01, 0x02, 0x03, 0x04>>)
  let assert Ok(<<0xaa, 0xbb>>) = p.run(b.take(bytes: 2), on: <<0xaa, 0xbb>>)
  let assert Ok(#(<<>>, <<0xaa, 0xbb, 0xcc>>)) =
    p.run_partial(b.take(bytes: 0), on: <<0xaa, 0xbb, 0xcc>>)
}

pub fn parse_content_truncated_test() {
  assert p.run(b.take(bytes: 5), on: <<0x01, 0x02>>)
    |> result.is_error
  assert p.run(b.take(bytes: 1), on: <<>>) |> result.is_error
}

pub fn parse_tlv_valid_test() {
  let assert Ok(#(0x02, <<0x42>>)) = p.run(der.tlv(), on: <<0x02, 0x01, 0x42>>)
  let assert Ok(#(#(0x30, <<0x01, 0x02, 0x03>>), <<0xaa>>)) =
    p.run_partial(der.tlv(), on: <<0x30, 0x03, 0x01, 0x02, 0x03, 0xaa>>)
}

pub fn parse_tlv_empty_content_test() {
  let assert Ok(#(0x30, <<>>)) = p.run(der.tlv(), on: <<0x30, 0x00>>)
}

pub fn parse_tlv_empty_input_test() {
  assert p.run(der.tlv(), on: <<>>) |> result.is_error
}

pub fn parse_tlv_truncated_test() {
  assert p.run(der.tlv(), on: <<0x02, 0x05, 0x01, 0x02>>)
    |> result.is_error
}

pub fn parse_tlv_long_form_length_test() {
  let content = bit_array.concat(list.repeat(<<0xaa>>, 130))
  let tlv = bit_array.concat([<<0x04, 0x81, 130>>, content])
  let assert Ok(#(0x04, parsed_content)) = p.run(der.tlv(), on: tlv)
  assert parsed_content == content
}

pub fn parse_tlv_with_remaining_test() {
  let assert Ok(#(#(0x02, <<0x42>>), <<0x04, 0x02, 0xaa, 0xbb>>)) =
    p.run_partial(der.tlv(), on: <<
      0x02,
      0x01,
      0x42,
      0x04,
      0x02,
      0xaa,
      0xbb,
    >>)
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
      let assert Ok(#(parsed_tag, parsed_content)) = p.run(der.tlv(), on: tlv)
      assert parsed_tag == tag
      assert parsed_content == content
    },
  )
}

pub fn nested_sequence_test() {
  let assert Ok(inner) = der.encode_sequence(<<0x01, 0x02>>)
  let assert Ok(outer) = der.encode_sequence(inner)

  let assert Ok(<<0x01, 0x02>>) =
    p.run(der.sequence(der.sequence(b.rest())), on: outer)
}

pub fn sequence_with_integer_test() {
  let assert Ok(int_encoded) = der.encode_integer(<<0x42>>)
  let assert Ok(seq) = der.encode_sequence(int_encoded)

  let assert Ok(<<0x42>>) = p.run(der.sequence(der.integer()), on: seq)
}

pub fn sequence_with_multiple_elements_test() {
  let assert Ok(oid_enc) = der.encode_oid([1, 2, 3])
  let assert Ok(int_enc) = der.encode_integer(<<0xff>>)
  let assert Ok(seq) = der.encode_sequence(bit_array.concat([oid_enc, int_enc]))

  let parser =
    der.sequence({
      use oid_val <- p.then(der.oid())
      use int_val <- p.then(der.integer())
      p.success(#(oid_val, int_val))
    })
  let assert Ok(#([1, 2, 3], int_value)) = p.run(parser, on: seq)
  assert int_value == <<0x00, 0xff>>
}

pub fn set_with_utf8_string_test() {
  let assert Ok(str) = der.encode_utf8_string("test")
  let assert Ok(set) = der.encode_set(str)

  let assert Ok("test") = p.run(der.set(der.utf8_string()), on: set)
}

pub fn context_tag_with_octet_string_test() {
  let assert Ok(octet) = der.encode_octet_string(<<0xde, 0xad, 0xbe, 0xef>>)
  let assert Ok(tagged) = der.encode_context_tag(0, octet)

  let assert Ok(<<0xde, 0xad, 0xbe, 0xef>>) =
    p.run(der.context_tag(0, der.octet_string()), on: tagged)
}

pub fn bit_string_containing_sequence_test() {
  let assert Ok(seq) = der.encode_sequence(<<0x01, 0x02, 0x03>>)
  let assert Ok(bit_str) = der.encode_bit_string(seq)

  let assert Ok(bit_content) = p.run(der.bit_string(), on: bit_str)
  let assert Ok(<<0x01, 0x02, 0x03>>) =
    p.run(der.sequence(b.rest()), on: bit_content)
}

pub fn parse_utc_time_test() {
  let input = <<0x17, 13, "250615143000Z":utf8>>
  let assert Ok(ts) = p.run(der.utc_time(), on: input)
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
  let assert Ok(ts) = p.run(der.generalized_time(), on: input)
  let expected = make_timestamp(2050, 12, 31, 23, 59, 59)
  assert ts == expected
}

pub fn utc_time_handles_y2k_window_test() {
  let input_2000 = <<0x17, 13, "000101000000Z":utf8>>
  let assert Ok(ts_2000) = p.run(der.utc_time(), on: input_2000)
  let expected_2000 = make_timestamp(2000, 1, 1, 0, 0, 0)
  assert ts_2000 == expected_2000

  let input_1999 = <<0x17, 13, "991231235959Z":utf8>>
  let assert Ok(ts_1999) = p.run(der.utc_time(), on: input_1999)
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
      let assert Ok(parsed_ts) = p.run(der.utc_time(), on: encoded)
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
      let assert Ok(parsed_ts) = p.run(der.generalized_time(), on: encoded)
      assert parsed_ts == ts
    },
  )
}

pub fn parse_utc_time_with_remaining_test() {
  let input = <<0x17, 13, "250615143000Z":utf8, 0xaa, 0xbb>>
  let assert Ok(#(ts, <<0xaa, 0xbb>>)) =
    p.run_partial(der.utc_time(), on: input)
  let expected = make_timestamp(2025, 6, 15, 14, 30, 0)
  assert ts == expected
}

pub fn parse_generalized_time_with_remaining_test() {
  let input = <<0x18, 15, "20501231235959Z":utf8, 0xcc, 0xdd>>
  let assert Ok(#(ts, <<0xcc, 0xdd>>)) =
    p.run_partial(der.generalized_time(), on: input)
  let expected = make_timestamp(2050, 12, 31, 23, 59, 59)
  assert ts == expected
}

pub fn parse_utc_time_wrong_tag_test() {
  let input = <<0x18, 13, "250615143000Z":utf8>>
  assert p.run(der.utc_time(), on: input) |> result.is_error
}

pub fn parse_generalized_time_wrong_tag_test() {
  let input = <<0x17, 15, "20501231235959Z":utf8>>
  assert p.run(der.generalized_time(), on: input) |> result.is_error
}

pub fn parse_utc_time_invalid_length_test() {
  let input = <<0x17, 12, "25061514300Z":utf8>>
  assert p.run(der.utc_time(), on: input) |> result.is_error
}

pub fn parse_generalized_time_invalid_length_test() {
  let input = <<0x18, 14, "2050123123595Z":utf8>>
  assert p.run(der.generalized_time(), on: input) |> result.is_error
}

pub fn parse_utc_time_missing_z_suffix_test() {
  let input = <<0x17, 13, "2506151430001":utf8>>
  assert p.run(der.utc_time(), on: input) |> result.is_error
}

pub fn parse_generalized_time_missing_z_suffix_test() {
  let input = <<0x18, 15, "205012312359591":utf8>>
  assert p.run(der.generalized_time(), on: input) |> result.is_error
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
