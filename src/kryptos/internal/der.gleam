import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/result
import kryptos/internal/utils

const sequence_tag = 0x30

const set_tag = 0x31

const integer_tag = 0x02

const bit_string_tag = 0x03

const octet_string_tag = 0x04

const oid_tag = 0x06

const utf8_string_tag = 0x0c

const printable_string_tag = 0x13

const ia5_string_tag = 0x16

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

  let assert Ok(value) = bit_array.slice(content, 0, len)
  use <- reject_non_minimal_zeros(value)

  let assert Ok(remaining) = bit_array.slice(content, len, content_size - len)
  Ok(#(value, remaining))
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

  let assert Ok(inner) = bit_array.slice(content, 0, len)
  let assert Ok(remaining) = bit_array.slice(content, len, content_size - len)
  Ok(#(inner, remaining))
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

/// Wrap content in a DER SET.
pub fn encode_set(content: BitArray) -> Result(BitArray, Nil) {
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<set_tag>>, len_bytes, content]))
}

/// Encode an OID (Object Identifier).
///
/// OID components are encoded as: first*40 + second for the first byte,
/// then base-128 with continuation bits for remaining components.
/// Returns Error(Nil) for invalid OIDs (fewer than 2 components).
pub fn encode_oid(components: List(Int)) -> Result(BitArray, Nil) {
  case components {
    [first, second, ..rest] -> {
      let first_byte = first * 40 + second
      let rest_bytes = list.flat_map(rest, encode_oid_component)
      let content =
        bit_array.concat([<<first_byte:8>>, bytes_from_list(rest_bytes)])
      use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
      Ok(bit_array.concat([<<oid_tag>>, len_bytes, content]))
    }
    _ -> Error(Nil)
  }
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

fn bytes_from_list(bytes: List(Int)) -> BitArray {
  list.fold(bytes, <<>>, fn(acc, byte) { bit_array.concat([acc, <<byte:8>>]) })
}

/// Encode a UTF8String.
pub fn encode_utf8_string(value: String) -> Result(BitArray, Nil) {
  let content = bit_array.from_string(value)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<utf8_string_tag>>, len_bytes, content]))
}

/// Encode a PrintableString (ASCII subset).
pub fn encode_printable_string(value: String) -> Result(BitArray, Nil) {
  let content = bit_array.from_string(value)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<printable_string_tag>>, len_bytes, content]))
}

/// Encode an IA5String (ASCII).
pub fn encode_ia5_string(value: String) -> Result(BitArray, Nil) {
  let content = bit_array.from_string(value)
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<ia5_string_tag>>, len_bytes, content]))
}

/// Encode an OCTET STRING.
pub fn encode_octet_string(value: BitArray) -> Result(BitArray, Nil) {
  use len_bytes <- result.try(encode_length(bit_array.byte_size(value)))
  Ok(bit_array.concat([<<octet_string_tag>>, len_bytes, value]))
}

/// Encode a BIT STRING.
///
/// Prepends a zero byte indicating no unused bits in the final octet.
pub fn encode_bit_string(value: BitArray) -> Result(BitArray, Nil) {
  let content = bit_array.concat([<<0x00>>, value])
  use len_bytes <- result.try(encode_length(bit_array.byte_size(content)))
  Ok(bit_array.concat([<<bit_string_tag>>, len_bytes, content]))
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

/// Parse the content of a DER SET, returning (inner bytes, remaining bytes).
pub fn parse_set(bytes: BitArray) -> Result(#(BitArray, BitArray), Nil) {
  use rest <- require_tag(bytes, set_tag)
  use #(len, content) <- result.try(parse_length(rest))
  parse_content(content, len)
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

/// Parse a DER OCTET STRING, returning (value bytes, remaining bytes).
pub fn parse_octet_string(bytes: BitArray) -> Result(#(BitArray, BitArray), Nil) {
  use rest <- require_tag(bytes, octet_string_tag)
  use #(len, content) <- result.try(parse_length(rest))
  parse_content(content, len)
}

/// Parse a DER OID, returning (components list, remaining bytes).
pub fn parse_oid(bytes: BitArray) -> Result(#(List(Int), BitArray), Nil) {
  use rest <- require_tag(bytes, oid_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use <- bool.guard(when: len < 1, return: Error(Nil))

  let content_size = bit_array.byte_size(content)
  use <- bool.guard(when: content_size < len, return: Error(Nil))

  let assert Ok(oid_bytes) = bit_array.slice(content, 0, len)
  let assert Ok(remaining) = bit_array.slice(content, len, content_size - len)

  use components <- result.try(decode_oid_components(oid_bytes))
  Ok(#(components, remaining))
}

fn decode_oid_components(bytes: BitArray) -> Result(List(Int), Nil) {
  case bytes {
    <<first_byte:8, rest:bits>> -> {
      let first = first_byte / 40
      let second = first_byte % 40
      use rest_components <- result.try(decode_oid_rest(rest, 0, []))
      Ok([first, second, ..rest_components])
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

/// Parse a DER UTF8String, returning (string value, remaining bytes).
pub fn parse_utf8_string(bytes: BitArray) -> Result(#(String, BitArray), Nil) {
  use rest <- require_tag(bytes, utf8_string_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use #(value_bytes, remaining) <- result.try(parse_content(content, len))
  use value <- result.try(bit_array.to_string(value_bytes))
  Ok(#(value, remaining))
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

/// Parse a DER IA5String, returning (string value, remaining bytes).
pub fn parse_ia5_string(bytes: BitArray) -> Result(#(String, BitArray), Nil) {
  use rest <- require_tag(bytes, ia5_string_tag)
  use #(len, content) <- result.try(parse_length(rest))
  use #(value_bytes, remaining) <- result.try(parse_content(content, len))
  use value <- result.try(bit_array.to_string(value_bytes))
  Ok(#(value, remaining))
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

/// Parse a context-specific primitive tag (e.g., [0], [2] for SANs).
///
/// Returns (inner bytes, remaining bytes) if the tag matches.
pub fn parse_context_primitive_tag(
  bytes: BitArray,
  tag: Int,
) -> Result(#(BitArray, BitArray), Nil) {
  let tag_byte = int.bitwise_or(0x80, tag)
  use rest <- require_tag(bytes, tag_byte)
  use #(len, content) <- result.try(parse_length(rest))
  parse_content(content, len)
}

/// Try to peek at the next tag without consuming it.
pub fn peek_tag(bytes: BitArray) -> Result(Int, Nil) {
  case bytes {
    <<tag:8, _:bits>> -> Ok(tag)
    _ -> Error(Nil)
  }
}

/// Parse content of a given length, returning (value, remaining bytes).
pub fn parse_content(
  content: BitArray,
  len: Int,
) -> Result(#(BitArray, BitArray), Nil) {
  let content_size = bit_array.byte_size(content)
  use <- bool.guard(when: content_size < len, return: Error(Nil))
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
