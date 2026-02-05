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

const printable_string_tag = 0x13

const teletex_string_tag = 0x14

const ia5_string_tag = 0x16

const utc_time_tag = 0x17

const generalized_time_tag = 0x18

const universal_string_tag = 0x1c

const bmp_string_tag = 0x1e

const sequence_tag = 0x30

const set_tag = 0x31

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

/// Parse DER length encoding, returning (length, remaining bytes).
///
/// Supports short form (1 byte) and long form (0x81 + 1 byte, 0x82 + 2 bytes).
/// Rejects non-canonical encodings (e.g., 0x81 for values < 128).
pub fn parse_length(bytes: BitArray) -> Result(#(Int, BitArray), Nil) {
  case bytes {
    <<len:8, rest:bits>> if len < 128 -> Ok(#(len, rest))
    <<0x81, len:8, rest:bits>> if len >= 128 -> Ok(#(len, rest))
    <<0x82, len:16, rest:bits>> if len >= 256 -> Ok(#(len, rest))
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

/// Parse a DER BOOLEAN, returning (value, remaining bytes).
///
/// Accepts any non-zero value as TRUE for BER interoperability,
/// as some certificates in the wild use non-0xFF values for TRUE.
pub fn parse_bool(bytes: BitArray) -> Result(#(Bool, BitArray), Nil) {
  use rest <- require_tag(bytes, boolean_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use <- bool.guard(when: len != 1, return: Error(Nil))

  case content {
    <<0x00, remaining:bits>> -> Ok(#(False, remaining))
    <<_value:8, remaining:bits>> -> Ok(#(True, remaining))
    _ -> Error(Nil)
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
/// Returns Error(Nil) for negative values.
pub fn encode_small_int(n: Int) -> Result(BitArray, Nil) {
  case n {
    _ if n < 0 -> Error(Nil)
    _ if n < 0x100 -> encode_integer(<<n:8>>)
    _ if n < 0x10000 -> encode_integer(<<n:16>>)
    _ if n < 0x1000000 -> encode_integer(<<n:24>>)
    _ -> encode_integer(<<n:32>>)
  }
}

/// Parse a DER INTEGER, returning (value bytes, remaining bytes).
///
/// The returned value bytes may have a leading 0x00 if the high bit was set.
/// Rejects zero-length integers and non-minimal leading zero padding.
pub fn parse_integer(bytes: BitArray) -> Result(#(BitArray, BitArray), Nil) {
  use rest <- require_tag(bytes, integer_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use <- bool.guard(when: len <= 0, return: Error(Nil))

  let content_size = bit_array.byte_size(content)
  use <- bool.guard(when: content_size < len, return: Error(Nil))

  // Safety: Prior guard ensures content_size >= len, so slice succeeds
  let assert Ok(value) = bit_array.slice(content, 0, len)
  use <- reject_non_minimal_zeros(value)

  // Safety: Prior guard ensures content_size >= len, so slice succeeds
  let assert Ok(remaining) = bit_array.slice(content, len, content_size - len)
  Ok(#(value, remaining))
}

/// Wrap content in a DER SEQUENCE.
pub fn encode_sequence(content: BitArray) -> Result(BitArray, Nil) {
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<sequence_tag>>, len_bytes, content]))
}

/// Parse the content of a DER SEQUENCE, returning (inner bytes, remaining bytes).
pub fn parse_sequence(bytes: BitArray) -> Result(#(BitArray, BitArray), Nil) {
  use rest <- require_tag(bytes, sequence_tag)
  use #(len, content) <- result.try(parse_length(rest))

  let content_size = bit_array.byte_size(content)
  use <- bool.guard(when: content_size < len, return: Error(Nil))

  // Safety: Prior guard ensures content_size >= len, so slices succeed
  let assert Ok(inner) = bit_array.slice(content, 0, len)
  let assert Ok(remaining) = bit_array.slice(content, len, content_size - len)
  Ok(#(inner, remaining))
}

/// Wrap content in a DER SET.
pub fn encode_set(content: BitArray) -> Result(BitArray, Nil) {
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<set_tag>>, len_bytes, content]))
}

/// Parse the content of a DER SET, returning (inner bytes, remaining bytes).
pub fn parse_set(bytes: BitArray) -> Result(#(BitArray, BitArray), Nil) {
  use rest <- require_tag(bytes, set_tag)
  use #(len, content) <- result.try(parse_length(rest))
  parse_content(content, len)
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

/// Parse a DER BIT STRING, returning (value bytes, remaining bytes).
///
/// The first byte of a BIT STRING indicates unused bits; this function
/// only accepts 0 unused bits and strips that byte from the result.
pub fn parse_bit_string(bytes: BitArray) -> Result(#(BitArray, BitArray), Nil) {
  use rest <- require_tag(bytes, bit_string_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use <- bool.guard(when: len < 1, return: Error(Nil))

  let content_size = bit_array.byte_size(content)
  use <- bool.guard(when: content_size < len, return: Error(Nil))

  case content {
    <<0x00, value:bytes-size(len - 1), remaining:bits>> ->
      Ok(#(value, remaining))
    _ -> Error(Nil)
  }
}

/// Encode an OCTET STRING.
pub fn encode_octet_string(value: BitArray) -> Result(BitArray, Nil) {
  use len_bytes <- result.try(encode_length(bit_array.byte_size(value)))
  Ok(bit_array.concat([<<octet_string_tag>>, len_bytes, value]))
}

/// Parse a DER OCTET STRING, returning (value bytes, remaining bytes).
pub fn parse_octet_string(bytes: BitArray) -> Result(#(BitArray, BitArray), Nil) {
  use rest <- require_tag(bytes, octet_string_tag)
  use #(len, content) <- result.try(parse_length(rest))
  parse_content(content, len)
}

/// Encode a UTF8String.
pub fn encode_utf8_string(value: String) -> Result(BitArray, Nil) {
  let content = bit_array.from_string(value)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<utf8_string_tag>>, len_bytes, content]))
}

/// Parse a DER UTF8String, returning (string value, remaining bytes).
pub fn parse_utf8_string(bytes: BitArray) -> Result(#(String, BitArray), Nil) {
  use rest <- require_tag(bytes, utf8_string_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use #(value_bytes, remaining) <- result.try(parse_content(content, len))
  use value <- result.try(bit_array.to_string(value_bytes))
  Ok(#(value, remaining))
}

/// Check if a codepoint is valid for PrintableString per RFC 5280.
fn is_printable_char(codepoint: Int) -> Bool {
  case codepoint {
    // A-Z
    c if c >= 65 && c <= 90 -> True
    // a-z
    c if c >= 97 && c <= 122 -> True
    // 0-9
    c if c >= 48 && c <= 57 -> True
    // space
    32 -> True
    // '
    39 -> True
    // ( )
    40 | 41 -> True
    // +
    43 -> True
    // ,
    44 -> True
    // -
    45 -> True
    // .
    46 -> True
    // /
    47 -> True
    // :
    58 -> True
    // =
    61 -> True
    // ?
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

/// Parse a DER PrintableString, returning (string value, remaining bytes).
pub fn parse_printable_string(
  bytes: BitArray,
) -> Result(#(String, BitArray), Nil) {
  use rest <- require_tag(bytes, printable_string_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use #(value_bytes, remaining) <- result.try(parse_content(content, len))
  use value <- result.try(bit_array.to_string(value_bytes))
  Ok(#(value, remaining))
}

/// Encode an IA5String (ASCII).
pub fn encode_ia5_string(value: String) -> Result(BitArray, Nil) {
  let content = bit_array.from_string(value)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<ia5_string_tag>>, len_bytes, content]))
}

/// Parse a DER IA5String, returning (string value, remaining bytes).
pub fn parse_ia5_string(bytes: BitArray) -> Result(#(String, BitArray), Nil) {
  use rest <- require_tag(bytes, ia5_string_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use #(value_bytes, remaining) <- result.try(parse_content(content, len))
  use value <- result.try(bit_array.to_string(value_bytes))
  Ok(#(value, remaining))
}

/// Parse a DER TeletexString (T61String), returning (string value, remaining bytes).
///
/// TeletexString uses ISO 8859-1 (Latin-1) encoding, where each byte represents
/// one character. This is a decode-only function for legacy certificate compatibility.
pub fn parse_teletex_string(bytes: BitArray) -> Result(#(String, BitArray), Nil) {
  use rest <- require_tag(bytes, teletex_string_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use #(value_bytes, remaining) <- result.try(parse_content(content, len))
  use value <- result.try(latin1_to_utf8(value_bytes))
  Ok(#(value, remaining))
}

/// Parse a DER BMPString, returning (string value, remaining bytes).
///
/// BMPString uses UCS-2 big-endian encoding (2 bytes per character).
/// This is a decode-only function for legacy certificate compatibility.
pub fn parse_bmp_string(bytes: BitArray) -> Result(#(String, BitArray), Nil) {
  use rest <- require_tag(bytes, bmp_string_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use <- bool.guard(when: len % 2 != 0, return: Error(Nil))
  use #(value_bytes, remaining) <- result.try(parse_content(content, len))
  use value <- result.try(ucs2_to_utf8(value_bytes))
  Ok(#(value, remaining))
}

/// Parse a DER UniversalString, returning (string value, remaining bytes).
///
/// UniversalString uses UCS-4 big-endian encoding (4 bytes per character).
/// This is a decode-only function for legacy certificate compatibility.
pub fn parse_universal_string(
  bytes: BitArray,
) -> Result(#(String, BitArray), Nil) {
  use rest <- require_tag(bytes, universal_string_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use <- bool.guard(when: len % 4 != 0, return: Error(Nil))
  use #(value_bytes, remaining) <- result.try(parse_content(content, len))
  use value <- result.try(ucs4_to_utf8(value_bytes))
  Ok(#(value, remaining))
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

/// Parse a UTCTime, returning (Timestamp, remaining).
/// UTCTime uses 2-digit years: 00-49 = 2000-2049, 50-99 = 1950-1999.
pub fn parse_utc_time(bytes: BitArray) -> Result(#(Timestamp, BitArray), Nil) {
  use rest <- require_tag(bytes, utc_time_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use <- bool.guard(when: len != 13, return: Error(Nil))
  use #(time_bytes, remaining) <- result.try(parse_content(content, len))
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

  let ts =
    timestamp.from_calendar(
      calendar.Date(year:, month:, day:),
      calendar.TimeOfDay(
        hours: hour,
        minutes: minute,
        seconds: second,
        nanoseconds: 0,
      ),
      calendar.utc_offset,
    )

  Ok(#(ts, remaining))
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

/// Parse a GeneralizedTime, returning (Timestamp, remaining).
pub fn parse_generalized_time(
  bytes: BitArray,
) -> Result(#(Timestamp, BitArray), Nil) {
  use rest <- require_tag(bytes, generalized_time_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use <- bool.guard(when: len != 15, return: Error(Nil))
  use #(time_bytes, remaining) <- result.try(parse_content(content, len))
  use time_str <- result.try(bit_array.to_string(time_bytes))
  use <- bool.guard(when: !string.ends_with(time_str, "Z"), return: Error(Nil))

  use year <- result.try(int.parse(string.slice(time_str, 0, 4)))
  use month_int <- result.try(int.parse(string.slice(time_str, 4, 2)))
  use month <- result.try(calendar.month_from_int(month_int))
  use day <- result.try(int.parse(string.slice(time_str, 6, 2)))
  use hour <- result.try(int.parse(string.slice(time_str, 8, 2)))
  use minute <- result.try(int.parse(string.slice(time_str, 10, 2)))
  use second <- result.try(int.parse(string.slice(time_str, 12, 2)))

  let timestamp =
    timestamp.from_calendar(
      calendar.Date(year:, month:, day:),
      calendar.TimeOfDay(
        hours: hour,
        minutes: minute,
        seconds: second,
        nanoseconds: 0,
      ),
      calendar.utc_offset,
    )

  Ok(#(timestamp, remaining))
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

/// Parse a DER OID, returning (components list, remaining bytes).
pub fn parse_oid(bytes: BitArray) -> Result(#(List(Int), BitArray), Nil) {
  use rest <- require_tag(bytes, oid_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use <- bool.guard(when: len < 1, return: Error(Nil))

  let content_size = bit_array.byte_size(content)
  use <- bool.guard(when: content_size < len, return: Error(Nil))

  // Safety: Prior guard ensures content_size >= len, so slices succeed
  let assert Ok(oid_bytes) = bit_array.slice(content, 0, len)
  let assert Ok(remaining) = bit_array.slice(content, len, content_size - len)

  use components <- result.try(decode_oid_components(oid_bytes))
  Ok(#(components, remaining))
}

/// Encode a context-specific tag (e.g., [0], [1]).
///
/// Uses constructed form (tag | 0xA0).
pub fn encode_context_tag(tag: Int, content: BitArray) -> Result(BitArray, Nil) {
  let tag_byte = int.bitwise_or(0xa0, tag)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<tag_byte:8>>, len_bytes, content]))
}

/// Parse a context-specific constructed tag (e.g., [0], [1]).
///
/// Returns (inner bytes, remaining bytes) if the tag matches.
pub fn parse_context_tag(
  bytes: BitArray,
  tag: Int,
) -> Result(#(BitArray, BitArray), Nil) {
  let tag_byte = int.bitwise_or(0xa0, tag)
  use rest <- require_tag(bytes, tag_byte)
  use #(len, content) <- result.try(parse_length(rest))
  parse_content(content, len)
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

/// Parse content of a given length, returning (value, remaining bytes).
pub fn parse_content(
  content: BitArray,
  len: Int,
) -> Result(#(BitArray, BitArray), Nil) {
  let content_size = bit_array.byte_size(content)
  use <- bool.guard(when: content_size < len, return: Error(Nil))
  // Safety: Prior guard ensures content_size >= len, so slices succeed
  let assert Ok(inner) = bit_array.slice(content, 0, len)
  let assert Ok(remaining) = bit_array.slice(content, len, content_size - len)
  Ok(#(inner, remaining))
}

/// Parse a TLV element, returning (tag, value, remaining bytes).
pub fn parse_tlv(bytes: BitArray) -> Result(#(Int, BitArray, BitArray), Nil) {
  case bytes {
    <<tag:8, rest:bits>> -> {
      use #(len, content) <- result.try(parse_length(rest))
      use #(value, remaining) <- result.try(parse_content(content, len))
      Ok(#(tag, value, remaining))
    }
    _ -> Error(Nil)
  }
}

fn require_tag(
  bytes: BitArray,
  tag: Int,
  next: fn(BitArray) -> Result(a, Nil),
) -> Result(a, Nil) {
  case bytes {
    <<t:8, rest:bits>> if t == tag -> next(rest)
    _ -> Error(Nil)
  }
}

fn reject_non_minimal_zeros(
  value: BitArray,
  next: fn() -> Result(a, Nil),
) -> Result(a, Nil) {
  case value {
    <<0x00, second:8, _:bits>> if second < 128 -> Error(Nil)
    _ -> next()
  }
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
