import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/result
import gleam/string

/// Count the number of trailing zero bits in a byte-aligned BitArray.
pub fn count_trailing_zeros(bits: BitArray) -> Int {
  let size = bit_array.byte_size(bits)
  do_count_trailing_zeros(bits, size - 1, 0)
}

fn do_count_trailing_zeros(bits: BitArray, byte_pos: Int, count: Int) -> Int {
  case byte_pos < 0 {
    True -> count
    False -> {
      let assert Ok(<<byte>>) = bit_array.slice(bits, byte_pos, 1)
      case byte {
        0 -> do_count_trailing_zeros(bits, byte_pos - 1, count + 8)
        _ -> count + trailing_zeros_in_byte(byte, 0)
      }
    }
  }
}

fn trailing_zeros_in_byte(byte: Int, count: Int) -> Int {
  case int.bitwise_and(byte, 1) {
    0 -> trailing_zeros_in_byte(int.bitwise_shift_right(byte, 1), count + 1)
    _ -> count
  }
}

/// Strip leading zero bytes from a BitArray, preserving at least one byte.
///
/// For example: `<<0, 0, 1, 2>>` becomes `<<1, 2>>`
/// But: `<<0, 0>>` becomes `<<0>>` (preserves at least one byte)
pub fn strip_leading_zeros(bytes: BitArray) -> BitArray {
  case bytes {
    <<0x00, rest:bits>> -> {
      case bit_array.byte_size(rest) > 0 {
        True -> strip_leading_zeros(rest)
        False -> bytes
      }
    }
    _ -> bytes
  }
}

/// Strip trailing zero bytes from a BitArray.
///
/// For example: `<<1, 2, 0, 0>>` becomes `<<1, 2>>`
/// An all-zeros input returns `<<>>`.
pub fn strip_trailing_zeros(data: BitArray) -> BitArray {
  let len = bit_array.byte_size(data)
  strip_trailing_zeros_loop(data, len)
}

fn strip_trailing_zeros_loop(data: BitArray, len: Int) -> BitArray {
  case len {
    0 -> <<>>
    _ -> {
      let assert Ok(<<last_byte>>) = bit_array.slice(data, len - 1, 1)
      case last_byte {
        0 -> strip_trailing_zeros_loop(data, len - 1)
        _ -> {
          let assert Ok(result) = bit_array.slice(data, 0, len)
          result
        }
      }
    }
  }
}

/// Left-pad a BitArray with zeros to reach the specified size.
///
/// If the input is already at least `size` bytes, it is returned unchanged.
pub fn pad_left(value: BitArray, size: Int) -> BitArray {
  let current_size = bit_array.byte_size(value)
  case current_size >= size {
    True -> value
    False -> {
      let padding_size = size - current_size
      let padding = list.repeat(<<0>>, padding_size) |> bit_array.concat
      bit_array.concat([padding, value])
    }
  }
}

/// Convert an integer to a zero-padded string of the specified width.
///
/// For example: `int_to_padded_string(42, 4)` returns `"0042"`
pub fn int_to_padded_string(n: Int, width: Int) -> String {
  let s = int.to_string(n)
  let padding = string.repeat("0", int.max(0, width - string.length(s)))
  padding <> s
}

/// Check if a string contains only ASCII characters (codepoints 0-127).
pub fn is_ascii(s: String) -> Bool {
  s
  |> string.to_utf_codepoints
  |> list.all(fn(cp) { string.utf_codepoint_to_int(cp) <= 127 })
}

/// Split a string into chunks of the specified size.
pub fn chunk_string(s: String, size: Int) -> List(String) {
  case string.length(s) <= size {
    True -> [s]
    False -> {
      let chunk = string.slice(s, 0, size)
      let rest = string.slice(s, size, string.length(s) - size)
      [chunk, ..chunk_string(rest, size)]
    }
  }
}

/// Parses an IP address string into bytes (4 for IPv4, 16 for IPv6).
pub fn parse_ip(ip: String) -> Result(BitArray, Nil) {
  case string.contains(ip, ":") {
    True -> parse_ipv6(ip)
    False -> parse_ipv4(ip)
  }
}

fn parse_ipv4(ip: String) -> Result(BitArray, Nil) {
  let parts = string.split(ip, ".")
  use <- bool.guard(when: list.length(parts) != 4, return: Error(Nil))
  use bytes <- result.try(list.try_map(parts, parse_ipv4_octet))
  Ok(bit_array.concat(list.map(bytes, fn(b) { <<b:8>> })))
}

fn parse_ipv4_octet(s: String) -> Result(Int, Nil) {
  use n <- result.try(int.parse(s))
  use <- bool.guard(when: n < 0 || n > 255, return: Error(Nil))
  Ok(n)
}

fn parse_ipv6(ip: String) -> Result(BitArray, Nil) {
  let ip = case string.starts_with(ip, "::") {
    True -> "0" <> ip
    False -> ip
  }
  let ip = case string.ends_with(ip, "::") {
    True -> ip <> "0"
    False -> ip
  }

  case string.contains(ip, "::") {
    True -> parse_ipv6_compressed(ip)
    False -> parse_ipv6_full(ip)
  }
}

fn parse_ipv6_full(ip: String) -> Result(BitArray, Nil) {
  let parts = string.split(ip, ":")
  use <- bool.guard(when: list.length(parts) != 8, return: Error(Nil))
  use words <- result.try(list.try_map(parts, parse_ipv6_word))
  Ok(bit_array.concat(list.map(words, fn(w) { <<w:16>> })))
}

fn parse_ipv6_compressed(ip: String) -> Result(BitArray, Nil) {
  use #(left, right) <- result.try(case string.split(ip, "::") {
    [l, r] -> Ok(#(l, r))
    _ -> Error(Nil)
  })

  let left_parts = case left {
    "" -> []
    _ -> string.split(left, ":")
  }
  let right_parts = case right {
    "" -> []
    _ -> string.split(right, ":")
  }

  let total = list.length(left_parts) + list.length(right_parts)
  use <- bool.guard(when: total > 7, return: Error(Nil))

  let zeros = list.repeat(0, 8 - total)
  use left_words <- result.try(list.try_map(left_parts, parse_ipv6_word))
  use right_words <- result.try(list.try_map(right_parts, parse_ipv6_word))
  let all_words = list.flatten([left_words, zeros, right_words])
  Ok(bit_array.concat(list.map(all_words, fn(w) { <<w:16>> })))
}

fn parse_ipv6_word(s: String) -> Result(Int, Nil) {
  use n <- result.try(int.base_parse(s, 16))
  use <- bool.guard(when: n < 0 || n > 0xffff, return: Error(Nil))
  Ok(n)
}
