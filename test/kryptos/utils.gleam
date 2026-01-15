import gleam/bit_array

pub fn strip_trailing_zeros(data: BitArray) -> BitArray {
  strip_trailing_zeros_inner(data, bit_array.byte_size(data))
}

fn strip_trailing_zeros_inner(data: BitArray, len: Int) -> BitArray {
  case len {
    0 -> <<>>
    _ -> {
      let assert Ok(last_byte) = bit_array.slice(data, len - 1, 1)
      case last_byte == <<0>> {
        True -> strip_trailing_zeros_inner(data, len - 1)
        False -> {
          let assert Ok(result) = bit_array.slice(data, 0, len)
          result
        }
      }
    }
  }
}
