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
/// Supports lengths up to 2^32 - 1 bytes.
pub fn encode_length(len: Int) -> BitArray {
  case len {
    l if l < 128 -> <<l:8>>
    l if l < 256 -> <<0x81, l:8>>
    l if l < 65_536 -> <<0x82, l:16>>
    l if l < 16_777_216 -> <<0x83, l:24>>
    l -> <<0x84, l:32>>
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
pub fn encode_integer(value: BitArray) -> BitArray {
  let stripped = utils.strip_leading_zeros(value)

  let int_bytes = case stripped {
    <<high:8, _:bits>> if high >= 128 -> bit_array.concat([<<0x00>>, stripped])
    <<>> -> <<0x00>>
    _ -> stripped
  }

  bit_array.concat([
    <<integer_tag>>,
    encode_length(bit_array.byte_size(int_bytes)),
    int_bytes,
  ])
}

/// Wrap content in a DER SEQUENCE.
pub fn encode_sequence(content: BitArray) -> BitArray {
  bit_array.concat([
    <<sequence_tag>>,
    encode_length(bit_array.byte_size(content)),
    content,
  ])
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
pub fn encode_set(content: BitArray) -> BitArray {
  bit_array.concat([
    <<set_tag>>,
    encode_length(bit_array.byte_size(content)),
    content,
  ])
}

/// Encode an OID (Object Identifier).
///
/// OID components are encoded as: first*40 + second for the first byte,
/// then base-128 with continuation bits for remaining components.
pub fn encode_oid(components: List(Int)) -> BitArray {
  case components {
    [first, second, ..rest] -> {
      let first_byte = first * 40 + second
      let rest_bytes = list.flat_map(rest, encode_oid_component)
      let content =
        bit_array.concat([<<first_byte:8>>, bytes_from_list(rest_bytes)])
      bit_array.concat([
        <<oid_tag>>,
        encode_length(bit_array.byte_size(content)),
        content,
      ])
    }
    _ -> <<>>
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
pub fn encode_utf8_string(value: String) -> BitArray {
  let content = bit_array.from_string(value)
  bit_array.concat([
    <<utf8_string_tag>>,
    encode_length(bit_array.byte_size(content)),
    content,
  ])
}

/// Encode a PrintableString (ASCII subset).
pub fn encode_printable_string(value: String) -> BitArray {
  let content = bit_array.from_string(value)
  bit_array.concat([
    <<printable_string_tag>>,
    encode_length(bit_array.byte_size(content)),
    content,
  ])
}

/// Encode an IA5String (ASCII).
pub fn encode_ia5_string(value: String) -> BitArray {
  let content = bit_array.from_string(value)
  bit_array.concat([
    <<ia5_string_tag>>,
    encode_length(bit_array.byte_size(content)),
    content,
  ])
}

/// Encode an OCTET STRING.
pub fn encode_octet_string(value: BitArray) -> BitArray {
  bit_array.concat([
    <<octet_string_tag>>,
    encode_length(bit_array.byte_size(value)),
    value,
  ])
}

/// Encode a BIT STRING.
///
/// Prepends a zero byte indicating no unused bits in the final octet.
pub fn encode_bit_string(value: BitArray) -> BitArray {
  let content = bit_array.concat([<<0x00>>, value])
  bit_array.concat([
    <<bit_string_tag>>,
    encode_length(bit_array.byte_size(content)),
    content,
  ])
}

/// Encode a context-specific tag (e.g., [0], [1]).
///
/// Uses constructed form (tag | 0xA0).
pub fn encode_context_tag(tag: Int, content: BitArray) -> BitArray {
  let tag_byte = int.bitwise_or(0xa0, tag)
  bit_array.concat([
    <<tag_byte:8>>,
    encode_length(bit_array.byte_size(content)),
    content,
  ])
}

/// Encode a context-specific primitive tag (e.g., [0], [2] for SANs).
///
/// Uses primitive form (tag | 0x80).
pub fn encode_context_primitive_tag(tag: Int, content: BitArray) -> BitArray {
  let tag_byte = int.bitwise_or(0x80, tag)
  bit_array.concat([
    <<tag_byte:8>>,
    encode_length(bit_array.byte_size(content)),
    content,
  ])
}
