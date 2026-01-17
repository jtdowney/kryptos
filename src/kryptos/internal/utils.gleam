import gleam/bit_array
import gleam/list

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
