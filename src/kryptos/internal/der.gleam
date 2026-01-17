import gleam/bit_array
import gleam/bool
import gleam/result
import kryptos/internal/utils

const sequence_tag = 0x30

const integer_tag = 0x02

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
pub fn encode_length(len: Int) -> BitArray {
  case len {
    l if l < 128 -> <<l:8>>
    l if l < 256 -> <<0x81, l:8>>
    l -> <<0x82, l:16>>
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
