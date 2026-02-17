import bitty as p
import bitty/bytes as b
import bitty/num
import gleam/bit_array
import gleam/bool
import gleam/bytes_tree
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/timestamp.{type Timestamp}
import kryptos/internal/utils

const boolean_tag = 0x01

const integer_tag = 0x02

const bit_string_tag = 0x03

const octet_string_tag = 0x04

const oid_tag = 0x06

const utf8_string_tag = 0x0c

const numeric_string_tag = 0x12

const printable_string_tag = 0x13

const teletex_string_tag = 0x14

const ia5_string_tag = 0x16

const utc_time_tag = 0x17

const generalized_time_tag = 0x18

const universal_string_tag = 0x1c

const bmp_string_tag = 0x1e

const sequence_tag = 0x30

const set_tag = 0x31

/// Parser combinator for DER length encoding.
pub fn length() -> p.Parser(Int) {
  use first <- p.then(num.u8())
  case first {
    len if len < 128 -> p.success(len)
    0x81 -> canonical_length(num.u8(), min: 128)
    0x82 -> canonical_length(num.u16(num.BigEndian), min: 256)
    _ -> p.fail("unsupported DER length form")
  }
}

fn canonical_length(parser: p.Parser(Int), min min: Int) -> p.Parser(Int) {
  use len <- p.then(parser)
  case len >= min {
    True -> p.success(len)
    False -> p.fail("non-canonical DER length")
  }
}

fn container(tag: Int, inner: p.Parser(a)) -> p.Parser(a) {
  use _ <- p.then(b.tag(<<tag:8>>))
  use len <- p.then(length())
  p.within_bytes(len, run: inner)
}

fn string_combinator(tag: Int) -> p.Parser(String) {
  use _ <- p.then(b.tag(<<tag:8>>))
  use len <- p.then(length())
  use content <- p.then(b.take(bytes: len))
  p.from_result(bit_array.to_string(content))
}

/// Parser combinator for a DER SEQUENCE.
///
/// Runs `inner` on the bounded content of the sequence.
pub fn sequence(inner: p.Parser(a)) -> p.Parser(a) {
  container(sequence_tag, inner)
}

/// Parser combinator for a DER SET.
///
/// Runs `inner` on the bounded content of the set.
pub fn set(inner: p.Parser(a)) -> p.Parser(a) {
  container(set_tag, inner)
}

/// Parser combinator for a context-specific constructed tag.
///
/// Runs `inner` on the bounded content of the tagged element.
pub fn context_tag(tag: Int, inner: p.Parser(a)) -> p.Parser(a) {
  let tag_byte = int.bitwise_or(0xa0, tag)
  container(tag_byte, inner)
}

/// Parser combinator for a DER SEQUENCE that also captures raw bytes.
///
/// Returns `#(raw_sequence_bytes, parsed_result)`.
pub fn sequence_with_raw(inner: p.Parser(a)) -> p.Parser(#(BitArray, a)) {
  use _ <- p.then(b.tag(<<sequence_tag:8>>))
  use len <- p.then(length())
  use content <- p.then(b.take(bytes: len))
  let assert Ok(len_encoding) = encode_length(len)
  let raw = bit_array.concat([<<sequence_tag:8>>, len_encoding, content])
  use parsed <- p.then(p.from_result(
    p.run(inner, on: content) |> result.replace_error(Nil),
  ))
  p.success(#(raw, parsed))
}

/// Parser combinator for a DER BOOLEAN.
///
/// Accepts any non-zero value as TRUE for BER interoperability.
pub fn boolean() -> p.Parser(Bool) {
  use _ <- p.then(b.tag(<<boolean_tag:8>>))
  use len <- p.then(length())
  use <- bool.lazy_guard(when: len != 1, return: fn() {
    p.fail("invalid boolean length")
  })
  use byte <- p.then(num.u8())
  p.success(byte != 0x00)
}

/// Parser combinator for a DER INTEGER.
///
/// Returns the raw value bytes (may include leading 0x00 for high-bit values).
/// Rejects zero-length integers and non-minimal leading zero padding.
pub fn integer() -> p.Parser(BitArray) {
  use _ <- p.then(b.tag(<<integer_tag:8>>))
  use len <- p.then(length())
  use <- bool.lazy_guard(when: len == 0, return: fn() {
    p.fail("empty integer")
  })
  use value <- p.then(b.take(bytes: len))
  case value {
    <<0x00, second:8, _:bits>> if second < 128 ->
      p.fail("non-minimal integer encoding")
    _ -> p.success(value)
  }
}

/// Parser combinator for a DER BIT STRING.
///
/// Only accepts 0 unused bits; strips the unused-bits byte.
pub fn bit_string() -> p.Parser(BitArray) {
  use _ <- p.then(b.tag(<<bit_string_tag:8>>))
  use len <- p.then(length())
  use <- bool.lazy_guard(when: len == 0, return: fn() {
    p.fail("empty bit string")
  })
  use unused_bits <- p.then(num.u8())
  case unused_bits {
    0 -> b.take(bytes: len - 1)
    _ -> p.fail("non-zero unused bits")
  }
}

/// Parser combinator for a DER OCTET STRING.
pub fn octet_string() -> p.Parser(BitArray) {
  use _ <- p.then(b.tag(<<octet_string_tag:8>>))
  use len <- p.then(length())
  b.take(bytes: len)
}

/// Parser combinator for a DER OID.
pub fn oid() -> p.Parser(List(Int)) {
  use _ <- p.then(b.tag(<<oid_tag:8>>))
  use len <- p.then(length())
  use <- bool.lazy_guard(when: len == 0, return: fn() { p.fail("empty OID") })
  use oid_bytes <- p.then(b.take(bytes: len))
  p.from_result(decode_oid_components(oid_bytes))
}

/// Parser combinator for a DER UTF8String.
pub fn utf8_string() -> p.Parser(String) {
  string_combinator(utf8_string_tag)
}

/// Parser combinator for a DER NumericString.
pub fn numeric_string() -> p.Parser(String) {
  string_combinator(numeric_string_tag)
}

/// Parser combinator for a DER PrintableString.
pub fn printable_string() -> p.Parser(String) {
  string_combinator(printable_string_tag)
}

/// Parser combinator for a DER IA5String.
pub fn ia5_string() -> p.Parser(String) {
  string_combinator(ia5_string_tag)
}

/// Parser combinator for a DER TeletexString (T61String).
///
/// Converts from ISO 8859-1 (Latin-1) to UTF-8.
pub fn teletex_string() -> p.Parser(String) {
  use _ <- p.then(b.tag(<<teletex_string_tag:8>>))
  use len <- p.then(length())
  use content <- p.then(b.take(bytes: len))
  p.from_result(latin1_to_utf8(content))
}

/// Parser combinator for a DER BMPString.
///
/// Converts from UCS-2 big-endian to UTF-8.
pub fn bmp_string() -> p.Parser(String) {
  use _ <- p.then(b.tag(<<bmp_string_tag:8>>))
  use len <- p.then(length())
  use content <- p.then(b.take(bytes: len))
  case bit_array.byte_size(content) % 2 {
    0 -> p.from_result(ucs2_to_utf8(content))
    _ -> p.fail("odd BMP string length")
  }
}

/// Parser combinator for a DER UniversalString.
///
/// Converts from UCS-4 big-endian to UTF-8.
pub fn universal_string() -> p.Parser(String) {
  use _ <- p.then(b.tag(<<universal_string_tag:8>>))
  use len <- p.then(length())
  use content <- p.then(b.take(bytes: len))
  case bit_array.byte_size(content) % 4 {
    0 -> p.from_result(ucs4_to_utf8(content))
    _ -> p.fail("invalid UniversalString length")
  }
}

/// Parser combinator for a DER UTCTime.
pub fn utc_time() -> p.Parser(Timestamp) {
  use _ <- p.then(b.tag(<<utc_time_tag:8>>))
  use len <- p.then(length())
  use <- bool.lazy_guard(when: len != 13, return: fn() {
    p.fail("invalid UTC time length")
  })
  use time_bytes <- p.then(b.take(bytes: len))
  p.from_result(bits_to_utc_timestamp(time_bytes))
}

/// Parser combinator for a DER GeneralizedTime.
pub fn generalized_time() -> p.Parser(Timestamp) {
  use _ <- p.then(b.tag(<<generalized_time_tag:8>>))
  use len <- p.then(length())
  use <- bool.lazy_guard(when: len != 15, return: fn() {
    p.fail("invalid GeneralizedTime length")
  })
  use time_bytes <- p.then(b.take(bytes: len))
  p.from_result(bits_to_generalized_timestamp(time_bytes))
}

/// Parser combinator for any DER TLV element.
///
/// Returns `#(tag, value_bytes)`.
pub fn tlv() -> p.Parser(#(Int, BitArray)) {
  use tag <- p.then(num.u8())
  use len <- p.then(length())
  use content <- p.then(b.take(bytes: len))
  p.success(#(tag, content))
}

/// Encode a length in DER format.
///
/// Supports lengths up to 65,535 bytes (sufficient for X.509 structures).
/// Returns Error(Nil) for lengths exceeding this limit.
pub fn encode_length(len: Int) -> Result(BitArray, Nil) {
  case len {
    l if l < 0 -> Error(Nil)
    l if l < 128 -> Ok(<<l:8>>)
    l if l < 256 -> Ok(<<0x81, l:8>>)
    l if l <= 65_535 -> Ok(<<0x82, l:16>>)
    _ -> Error(Nil)
  }
}

/// Encode a boolean as a DER BOOLEAN.
pub fn encode_bool(value: Bool) -> BitArray {
  case value {
    True -> <<boolean_tag, 0x01, 0xff>>
    False -> <<boolean_tag, 0x01, 0x00>>
  }
}

/// Encode bytes as a DER INTEGER.
///
/// Strips leading zeros and adds 0x00 prefix if high bit is set (to keep positive).
pub fn encode_integer(value: BitArray) -> Result(BitArray, Nil) {
  let stripped = utils.strip_leading_zeros(value)

  let int_bytes = case stripped {
    <<high:8, _:bits>> if high >= 128 -> bit_array.concat([<<0x00>>, stripped])
    <<>> -> <<0x00>>
    _ -> stripped
  }

  use len_bytes <- result.try(encode_length(bit_array.byte_size(int_bytes)))
  Ok(bit_array.concat([<<integer_tag>>, len_bytes, int_bytes]))
}

/// Encode a non-negative Int as a DER INTEGER.
///
/// Supports values from 0 to 0xFFFFFFFF (4 bytes).
/// Returns Error(Nil) for negative values or values exceeding 32 bits.
pub fn encode_small_int(n: Int) -> Result(BitArray, Nil) {
  case n {
    _ if n < 0 -> Error(Nil)
    _ if n < 0x100 -> encode_integer(<<n:8>>)
    _ if n < 0x10000 -> encode_integer(<<n:16>>)
    _ if n < 0x1000000 -> encode_integer(<<n:24>>)
    _ if n < 0x1_0000_0000 -> encode_integer(<<n:32>>)
    _ -> Error(Nil)
  }
}

/// Wrap content in a DER SEQUENCE.
pub fn encode_sequence(content: BitArray) -> Result(BitArray, Nil) {
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<sequence_tag>>, len_bytes, content]))
}

/// Wrap content in a DER SET.
pub fn encode_set(content: BitArray) -> Result(BitArray, Nil) {
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<set_tag>>, len_bytes, content]))
}

/// Encode a BIT STRING.
///
/// Handles non-byte-aligned bit arrays by calculating and encoding
/// the appropriate padding bits.
pub fn encode_bit_string(value: BitArray) -> Result(BitArray, Nil) {
  let bit_size = bit_array.bit_size(value)
  let unused_bits = case bit_size % 8 {
    0 -> 0
    remainder -> 8 - remainder
  }
  let padded = bit_array.pad_to_bytes(value)
  let content = <<unused_bits:8, padded:bits>>
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<bit_string_tag>>, len_bytes, content]))
}

/// Encode an OCTET STRING.
pub fn encode_octet_string(value: BitArray) -> Result(BitArray, Nil) {
  use len_bytes <- result.try(encode_length(bit_array.byte_size(value)))
  Ok(bit_array.concat([<<octet_string_tag>>, len_bytes, value]))
}

/// Encode a UTF8String.
pub fn encode_utf8_string(value: String) -> Result(BitArray, Nil) {
  let content = bit_array.from_string(value)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<utf8_string_tag>>, len_bytes, content]))
}

/// Encode a PrintableString (ASCII subset per RFC 5280).
/// Returns Error(Nil) if the string contains characters not allowed
/// in PrintableString.
pub fn encode_printable_string(value: String) -> Result(BitArray, Nil) {
  let content = bit_array.from_string(value)
  use <- bool.guard(
    when: !is_valid_printable_string(content),
    return: Error(Nil),
  )
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<printable_string_tag>>, len_bytes, content]))
}

/// Encode an IA5String (ASCII).
pub fn encode_ia5_string(value: String) -> Result(BitArray, Nil) {
  let content = bit_array.from_string(value)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<ia5_string_tag>>, len_bytes, content]))
}

/// Encode a DER Timestamp, returning a BitArray.
pub fn encode_timestamp(timestamp: Timestamp) -> Result(BitArray, Nil) {
  let #(date, _time) = timestamp.to_calendar(timestamp, calendar.utc_offset)
  case date.year >= 1950 && date.year < 2050 {
    True -> encode_utc_time(timestamp)
    False -> encode_generalized_time(timestamp)
  }
}

/// Format: YYMMDDHHMMSSZ
fn encode_utc_time(timestamp: Timestamp) -> Result(BitArray, Nil) {
  let #(date, time) = timestamp.to_calendar(timestamp, calendar.utc_offset)
  let yy = date.year % 100
  let pad2 = utils.int_to_padded_string(_, 2)
  let content =
    pad2(yy)
    <> pad2(calendar.month_to_int(date.month))
    <> pad2(date.day)
    <> pad2(time.hours)
    <> pad2(time.minutes)
    <> pad2(time.seconds)
    <> "Z"
  let bytes = bit_array.from_string(content)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(bytes)))
  Ok(bit_array.concat([<<utc_time_tag>>, len_bytes, bytes]))
}

/// Format: YYYYMMDDHHMMSSZ
pub fn encode_generalized_time(timestamp: Timestamp) -> Result(BitArray, Nil) {
  let #(date, time) = timestamp.to_calendar(timestamp, calendar.utc_offset)
  let pad2 = utils.int_to_padded_string(_, 2)
  let pad4 = utils.int_to_padded_string(_, 4)
  let content =
    pad4(date.year)
    <> pad2(calendar.month_to_int(date.month))
    <> pad2(date.day)
    <> pad2(time.hours)
    <> pad2(time.minutes)
    <> pad2(time.seconds)
    <> "Z"
  let bytes = bit_array.from_string(content)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(bytes)))
  Ok(bit_array.concat([<<generalized_time_tag>>, len_bytes, bytes]))
}

/// Encode an OID (Object Identifier).
///
/// OID components are encoded as: first*40 + second for the first byte,
/// then base-128 with continuation bits for remaining components.
/// Returns Error(Nil) for invalid OIDs (fewer than 2 components).
pub fn encode_oid(components: List(Int)) -> Result(BitArray, Nil) {
  case components {
    [first, second, ..rest] -> {
      let first_value = first * 40 + second
      let first_bytes = encode_oid_component(first_value)
      let rest_bytes = list.flat_map(rest, encode_oid_component)
      let content =
        bit_array.concat([
          bytes_from_list(first_bytes),
          bytes_from_list(rest_bytes),
        ])
      use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
      Ok(bit_array.concat([<<oid_tag>>, len_bytes, content]))
    }
    _ -> Error(Nil)
  }
}

/// Encode a context-specific tag (e.g., [0], [1]).
///
/// Uses constructed form (tag | 0xA0).
pub fn encode_context_tag(tag: Int, content: BitArray) -> Result(BitArray, Nil) {
  let tag_byte = int.bitwise_or(0xa0, tag)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<tag_byte:8>>, len_bytes, content]))
}

/// Encode a context-specific primitive tag (e.g., [0], [2] for SANs).
///
/// Uses primitive form (tag | 0x80).
pub fn encode_context_primitive_tag(
  tag: Int,
  content: BitArray,
) -> Result(BitArray, Nil) {
  let tag_byte = int.bitwise_or(0x80, tag)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<tag_byte:8>>, len_bytes, content]))
}

fn bytes_from_list(bytes: List(Int)) -> BitArray {
  bytes
  |> list.fold(bytes_tree.new(), fn(tree, byte) {
    bytes_tree.append(tree, <<byte:8>>)
  })
  |> bytes_tree.to_bit_array
}

fn encode_oid_component(value: Int) -> List(Int) {
  case value < 128 {
    True -> [value]
    False -> encode_oid_component_base128(value, [])
  }
}

fn encode_oid_component_base128(value: Int, acc: List(Int)) -> List(Int) {
  case value {
    0 -> acc
    _ -> {
      let byte = int.bitwise_and(value, 0x7f)
      let next_value = int.bitwise_shift_right(value, 7)
      let new_byte = case acc {
        [] -> byte
        _ -> int.bitwise_or(byte, 0x80)
      }
      encode_oid_component_base128(next_value, [new_byte, ..acc])
    }
  }
}

/// Decode raw OID content bytes (without tag/length prefix) into components.
///
/// Used for implicitly tagged OIDs where the tag/length have already been stripped.
pub fn decode_oid_components(bytes: BitArray) -> Result(List(Int), Nil) {
  use #(first_value, rest) <- result.try(decode_first_oid_component(bytes, 0))

  let first = case first_value {
    v if v < 40 -> 0
    v if v < 80 -> 1
    _ -> 2
  }
  let second = first_value - first * 40

  use rest_components <- result.try(decode_oid_rest(rest, 0, []))
  Ok([first, second, ..rest_components])
}

fn decode_first_oid_component(
  bytes: BitArray,
  acc: Int,
) -> Result(#(Int, BitArray), Nil) {
  case bytes {
    <<>> -> Error(Nil)
    <<byte:8, rest:bits>> -> {
      let value =
        int.bitwise_or(
          int.bitwise_shift_left(acc, 7),
          int.bitwise_and(byte, 0x7f),
        )
      let is_continuation = int.bitwise_and(byte, 0x80) != 0
      case is_continuation {
        True -> decode_first_oid_component(rest, value)
        False -> Ok(#(value, rest))
      }
    }
    _ -> Error(Nil)
  }
}

fn decode_oid_rest(
  bytes: BitArray,
  acc: Int,
  components: List(Int),
) -> Result(List(Int), Nil) {
  case bytes {
    <<>> if acc == 0 -> Ok(list.reverse(components))
    <<>> -> Error(Nil)
    <<byte:8, rest:bits>> -> {
      let value =
        int.bitwise_or(
          int.bitwise_shift_left(acc, 7),
          int.bitwise_and(byte, 0x7f),
        )
      let is_continuation = int.bitwise_and(byte, 0x80) != 0
      case is_continuation {
        True -> decode_oid_rest(rest, value, components)
        False -> decode_oid_rest(rest, 0, [value, ..components])
      }
    }
    _ -> Error(Nil)
  }
}

fn bits_to_utc_timestamp(time_bytes: BitArray) -> Result(Timestamp, Nil) {
  use time_str <- result.try(bit_array.to_string(time_bytes))
  use <- bool.guard(when: !string.ends_with(time_str, "Z"), return: Error(Nil))

  use yy <- result.try(int.parse(string.slice(time_str, 0, 2)))
  use month_int <- result.try(int.parse(string.slice(time_str, 2, 2)))
  use month <- result.try(calendar.month_from_int(month_int))
  use day <- result.try(int.parse(string.slice(time_str, 4, 2)))
  use hour <- result.try(int.parse(string.slice(time_str, 6, 2)))
  use minute <- result.try(int.parse(string.slice(time_str, 8, 2)))
  use second <- result.try(int.parse(string.slice(time_str, 10, 2)))

  let year = case yy >= 50 {
    True -> 1900 + yy
    False -> 2000 + yy
  }

  Ok(timestamp.from_calendar(
    calendar.Date(year:, month:, day:),
    calendar.TimeOfDay(
      hours: hour,
      minutes: minute,
      seconds: second,
      nanoseconds: 0,
    ),
    calendar.utc_offset,
  ))
}

fn bits_to_generalized_timestamp(time_bytes: BitArray) -> Result(Timestamp, Nil) {
  use time_str <- result.try(bit_array.to_string(time_bytes))
  use <- bool.guard(when: !string.ends_with(time_str, "Z"), return: Error(Nil))

  use year <- result.try(int.parse(string.slice(time_str, 0, 4)))
  use month_int <- result.try(int.parse(string.slice(time_str, 4, 2)))
  use month <- result.try(calendar.month_from_int(month_int))
  use day <- result.try(int.parse(string.slice(time_str, 6, 2)))
  use hour <- result.try(int.parse(string.slice(time_str, 8, 2)))
  use minute <- result.try(int.parse(string.slice(time_str, 10, 2)))
  use second <- result.try(int.parse(string.slice(time_str, 12, 2)))

  Ok(timestamp.from_calendar(
    calendar.Date(year:, month:, day:),
    calendar.TimeOfDay(
      hours: hour,
      minutes: minute,
      seconds: second,
      nanoseconds: 0,
    ),
    calendar.utc_offset,
  ))
}

/// Check if a codepoint is valid for PrintableString per RFC 5280.
fn is_printable_char(codepoint: Int) -> Bool {
  case codepoint {
    c if c >= 65 && c <= 90 -> True
    c if c >= 97 && c <= 122 -> True
    c if c >= 48 && c <= 57 -> True
    32 -> True
    39 -> True
    40 | 41 -> True
    43 -> True
    44 -> True
    45 -> True
    46 -> True
    47 -> True
    58 -> True
    61 -> True
    63 -> True
    _ -> False
  }
}

fn is_valid_printable_string(value: BitArray) -> Bool {
  case value {
    <<>> -> True
    <<byte:8, rest:bits>> ->
      is_printable_char(byte) && is_valid_printable_string(rest)
    _ -> False
  }
}

/// Convert ISO 8859-1 (Latin-1) bytes to a UTF-8 string.
///
/// Each byte in Latin-1 represents a single Unicode codepoint (0x00-0xFF),
/// which maps directly to Unicode.
fn latin1_to_utf8(bytes: BitArray) -> Result(String, Nil) {
  latin1_to_utf8_loop(bytes, [])
  |> result.map(fn(codepoints) {
    codepoints |> list.reverse |> string.from_utf_codepoints
  })
}

fn latin1_to_utf8_loop(
  bytes: BitArray,
  acc: List(UtfCodepoint),
) -> Result(List(UtfCodepoint), Nil) {
  case bytes {
    <<>> -> Ok(acc)
    <<byte:8, rest:bits>> -> {
      case string.utf_codepoint(byte) {
        Ok(cp) -> latin1_to_utf8_loop(rest, [cp, ..acc])
        Error(_) -> Error(Nil)
      }
    }
    _ -> Error(Nil)
  }
}

/// Convert UCS-2 big-endian bytes to a UTF-8 string.
///
/// Each 2-byte unit represents a Unicode codepoint in the Basic Multilingual Plane.
fn ucs2_to_utf8(bytes: BitArray) -> Result(String, Nil) {
  ucs2_to_utf8_loop(bytes, [])
  |> result.map(fn(codepoints) {
    codepoints |> list.reverse |> string.from_utf_codepoints
  })
}

fn ucs2_to_utf8_loop(
  bytes: BitArray,
  acc: List(UtfCodepoint),
) -> Result(List(UtfCodepoint), Nil) {
  case bytes {
    <<>> -> Ok(acc)
    <<codepoint:16-big, rest:bits>> -> {
      case string.utf_codepoint(codepoint) {
        Ok(cp) -> ucs2_to_utf8_loop(rest, [cp, ..acc])
        Error(_) -> Error(Nil)
      }
    }
    _ -> Error(Nil)
  }
}

/// Convert UCS-4 big-endian bytes to a UTF-8 string.
///
/// Each 4-byte unit represents a Unicode codepoint.
fn ucs4_to_utf8(bytes: BitArray) -> Result(String, Nil) {
  ucs4_to_utf8_loop(bytes, [])
  |> result.map(fn(codepoints) {
    codepoints |> list.reverse |> string.from_utf_codepoints
  })
}

fn ucs4_to_utf8_loop(
  bytes: BitArray,
  acc: List(UtfCodepoint),
) -> Result(List(UtfCodepoint), Nil) {
  case bytes {
    <<>> -> Ok(acc)
    <<codepoint:32-big, rest:bits>> -> {
      case string.utf_codepoint(codepoint) {
        Ok(cp) -> ucs4_to_utf8_loop(rest, [cp, ..acc])
        Error(_) -> Error(Nil)
      }
    }
    _ -> Error(Nil)
  }
}
