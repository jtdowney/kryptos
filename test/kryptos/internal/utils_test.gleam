import gleam/list
import gleam/string
import kryptos/internal/utils
import qcheck

pub fn count_trailing_zeros_byte_test() {
  assert utils.count_trailing_zeros(<<0b00110100:8>>) == 2
  assert utils.count_trailing_zeros(<<0b00110000:8>>) == 4
  assert utils.count_trailing_zeros(<<0b00000001:8>>) == 0
  assert utils.count_trailing_zeros(<<0:8>>) == 8
}

pub fn count_trailing_zeros_multi_byte_test() {
  assert utils.count_trailing_zeros(<<0b00000001, 0b00000000:8>>) == 8
  assert utils.count_trailing_zeros(<<0b00000001, 0b10000000:8>>) == 7
  assert utils.count_trailing_zeros(<<0b11111111, 0b11110000:8>>) == 4
  assert utils.count_trailing_zeros(<<0b00000000, 0b00000001:8>>) == 0
}

pub fn int_to_padded_string_basic_test() {
  assert utils.int_to_padded_string(1, 2) == "01"
  assert utils.int_to_padded_string(42, 4) == "0042"
  assert utils.int_to_padded_string(123, 5) == "00123"
}

pub fn int_to_padded_string_no_padding_needed_test() {
  assert utils.int_to_padded_string(10, 2) == "10"
  assert utils.int_to_padded_string(100, 3) == "100"
  assert utils.int_to_padded_string(1234, 4) == "1234"
}

pub fn int_to_padded_string_already_wider_test() {
  assert utils.int_to_padded_string(12_345, 3) == "12345"
  assert utils.int_to_padded_string(100, 2) == "100"
}

pub fn int_to_padded_string_zero_test() {
  assert utils.int_to_padded_string(0, 3) == "000"
  assert utils.int_to_padded_string(0, 1) == "0"
}

pub fn is_ascii_accepts_empty_string_test() {
  assert utils.is_ascii("")
}

pub fn is_ascii_accepts_printable_ascii_test() {
  assert utils.is_ascii("Hello, World!")
  assert utils.is_ascii("test@example.com")
  assert utils.is_ascii("0123456789")
}

pub fn is_ascii_accepts_control_characters_test() {
  assert utils.is_ascii("\t\n\r")
}

pub fn is_ascii_rejects_non_ascii_test() {
  assert !utils.is_ascii("café")
  assert !utils.is_ascii("日本語")
  assert !utils.is_ascii("tëst")
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
    assert utils.is_ascii(s)
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
    assert !utils.is_ascii(s)
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

pub fn parse_ip_ipv4_basic_test() {
  assert utils.parse_ip("192.168.1.1") == Ok(<<192, 168, 1, 1>>)
  assert utils.parse_ip("10.0.0.1") == Ok(<<10, 0, 0, 1>>)
  assert utils.parse_ip("127.0.0.1") == Ok(<<127, 0, 0, 1>>)
}

pub fn parse_ip_ipv4_boundaries_test() {
  assert utils.parse_ip("0.0.0.0") == Ok(<<0, 0, 0, 0>>)
  assert utils.parse_ip("255.255.255.255") == Ok(<<255, 255, 255, 255>>)
}

pub fn parse_ip_ipv4_invalid_test() {
  assert utils.parse_ip("256.1.1.1") == Error(Nil)
  assert utils.parse_ip("1.2.3") == Error(Nil)
  assert utils.parse_ip("1.2.3.4.5") == Error(Nil)
  assert utils.parse_ip("1.2.3.abc") == Error(Nil)
  assert utils.parse_ip("-1.2.3.4") == Error(Nil)
  assert utils.parse_ip("") == Error(Nil)
}

pub fn parse_ip_ipv6_full_test() {
  assert utils.parse_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    == Ok(<<
      0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e,
      0x03, 0x70, 0x73, 0x34,
    >>)
  assert utils.parse_ip("0000:0000:0000:0000:0000:0000:0000:0001")
    == Ok(<<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>)
}

pub fn parse_ip_ipv6_compressed_test() {
  // ::1 (loopback)
  assert utils.parse_ip("::1")
    == Ok(<<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>)
  // :: (all zeros)
  assert utils.parse_ip("::")
    == Ok(<<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>)
  // fe80::1 (link-local)
  assert utils.parse_ip("fe80::1")
    == Ok(<<0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>)
  // 2001:db8::1
  assert utils.parse_ip("2001:db8::1")
    == Ok(<<0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>)
  // ::ffff:192.0.2.1 style not supported, but 1::2 should work
  assert utils.parse_ip("1::2")
    == Ok(<<0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2>>)
}

pub fn parse_ip_ipv6_compressed_middle_test() {
  // 2001:db8::8a2e:370:7334
  assert utils.parse_ip("2001:db8::8a2e:370:7334")
    == Ok(<<
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73,
      0x34,
    >>)
}

pub fn parse_ip_ipv6_invalid_test() {
  // Too many groups
  assert utils.parse_ip("1:2:3:4:5:6:7:8:9") == Error(Nil)
  // Too few groups without compression
  assert utils.parse_ip("1:2:3:4:5:6:7") == Error(Nil)
  // Invalid hex
  assert utils.parse_ip("gggg::1") == Error(Nil)
  // Multiple :: (only one allowed)
  assert utils.parse_ip("1::2::3") == Error(Nil)
}
