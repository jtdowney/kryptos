//// Internal Concat KDF (NIST SP 800-56A) implementation.
////
//// Implements the single-step key derivation function from NIST SP 800-56A.
//// Used internally by the crypto module for deriving cryptographic keys
//// from shared secrets (e.g., from ECDH key agreement).

import gleam/bit_array
import gleam/bool
import gleam/bytes_tree.{type BytesTree}
import gleam/result
import kryptos/hash.{type HashAlgorithm}

pub fn derive_loop(
  algorithm: HashAlgorithm,
  secret: BitArray,
  info: BitArray,
  remaining: Int,
  counter: Int,
  acc: BytesTree,
) -> Result(BitArray, Nil) {
  use <- bool.guard(
    when: remaining <= 0,
    return: Ok(bytes_tree.to_bit_array(acc)),
  )

  // Hash(counter_32bit_BE || secret || OtherInfo)
  let input = bit_array.concat([<<counter:32-big>>, secret, info])
  use hasher <- result.try(hash.new(algorithm))
  let block =
    hasher
    |> hash.update(input)
    |> hash.final()

  let length = bit_array.byte_size(block)
  case remaining <= length {
    True -> {
      let assert Ok(final_block) = bit_array.slice(block, 0, remaining)
      bytes_tree.append(acc, final_block)
      |> bytes_tree.to_bit_array
      |> Ok
    }
    False -> {
      derive_loop(
        algorithm,
        secret,
        info,
        remaining - length,
        counter + 1,
        bytes_tree.append(acc, block),
      )
    }
  }
}
