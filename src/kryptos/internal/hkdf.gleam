import gleam/bit_array
import gleam/bytes_tree.{type BytesTree}
import gleam/result
import kryptos/hash.{type HashAlgorithm}
import kryptos/hmac

@external(javascript, "../../kryptos_ffi.mjs", "hkdfDerive")
pub fn do_derive(
  algorithm: HashAlgorithm,
  ikm: BitArray,
  salt: BitArray,
  info: BitArray,
  length: Int,
) -> Result(BitArray, Nil) {
  // Step 1: Extract
  // PRK = HMAC-Hash(salt, IKM)
  use hmac_state <- result.try(hmac.new(algorithm, salt))
  let prk =
    hmac_state
    |> hmac.update(ikm)
    |> hmac.final()

  // Step 2: Expand
  // T = T(1) || T(2) || ... || T(N)
  // T(0) = empty
  // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
  // OKM = first length octets of T
  expand(algorithm, prk, info, length)
}

fn expand(
  algorithm: HashAlgorithm,
  prk: BitArray,
  info: BitArray,
  length: Int,
) -> Result(BitArray, Nil) {
  expand_loop(algorithm, prk, info, length, <<>>, 1, bytes_tree.new())
}

fn expand_loop(
  algorithm: HashAlgorithm,
  prk: BitArray,
  info: BitArray,
  remaining: Int,
  prev: BitArray,
  counter: Int,
  acc: BytesTree,
) -> Result(BitArray, Nil) {
  case remaining <= 0 {
    True -> Ok(bytes_tree.to_bit_array(acc))
    False -> {
      // T(i) = HMAC-Hash(PRK, T(i-1) || info || counter)
      let input = bit_array.concat([prev, info, <<counter>>])
      use hmac_state <- result.try(hmac.new(algorithm, prk))
      let t =
        hmac_state
        |> hmac.update(input)
        |> hmac.final()

      let t_len = bit_array.byte_size(t)
      case remaining <= t_len {
        True -> {
          // Final block - take what we need
          let assert Ok(final_block) = bit_array.slice(t, 0, remaining)
          bytes_tree.append(acc, final_block)
          |> bytes_tree.to_bit_array
          |> Ok
        }
        False -> {
          // Accumulate and continue
          expand_loop(
            algorithm,
            prk,
            info,
            remaining - t_len,
            t,
            counter + 1,
            bytes_tree.append(acc, t),
          )
        }
      }
    }
  }
}
