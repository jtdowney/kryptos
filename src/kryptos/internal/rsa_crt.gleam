import bigi.{type BigInt}
import gleam/bit_array
import gleam/order
import gleam/result
import kryptos/crypto

/// Compute CRT parameters from minimal RSA components. This is used for
/// loading RSA keys where only the modulus, public exponent, and private
/// exponent are known. The JS implementation requires the precomputed
/// parameters to be provided as well.
pub fn compute_crt_params(
  n_bytes: BitArray,
  e_bytes: BitArray,
  d_bytes: BitArray,
) -> Result(#(BitArray, BitArray, BitArray, BitArray, BitArray), Nil) {
  use n <- result.try(bigi.from_bytes(n_bytes, bigi.BigEndian, bigi.Unsigned))
  use e <- result.try(bigi.from_bytes(e_bytes, bigi.BigEndian, bigi.Unsigned))
  use d <- result.try(bigi.from_bytes(d_bytes, bigi.BigEndian, bigi.Unsigned))

  let byte_len = bit_array.byte_size(n_bytes)

  use #(p, q) <- result.try(factor_rsa_modulus(n, e, d, byte_len, 500))

  let one = bigi.from_int(1)
  let dp = bigi.modulo(d, bigi.subtract(p, one))
  let dq = bigi.modulo(d, bigi.subtract(q, one))

  use qi <- result.try(mod_inverse(q, p))

  use p_bytes <- result.try(to_bytes_trimmed(p, byte_len))
  use q_bytes <- result.try(to_bytes_trimmed(q, byte_len))
  use dp_bytes <- result.try(to_bytes_trimmed(dp, byte_len))
  use dq_bytes <- result.try(to_bytes_trimmed(dq, byte_len))
  use qi_bytes <- result.try(to_bytes_trimmed(qi, byte_len))

  Ok(#(p_bytes, q_bytes, dp_bytes, dq_bytes, qi_bytes))
}

@external(erlang, "kryptos_ffi", "mod_pow")
@external(javascript, "../../kryptos_ffi.mjs", "modPow")
fn mod_pow_ffi(base: BitArray, exp: BitArray, mod: BitArray) -> BitArray

fn mod_pow(
  base: BigInt,
  exp: BigInt,
  mod: BigInt,
  byte_len: Int,
) -> Result(BigInt, Nil) {
  use base_bytes <- result.try(bigi.to_bytes(
    base,
    bigi.BigEndian,
    bigi.Unsigned,
    byte_len,
  ))
  use exp_bytes <- result.try(to_bytes_minimal(exp))
  use mod_bytes <- result.try(bigi.to_bytes(
    mod,
    bigi.BigEndian,
    bigi.Unsigned,
    byte_len,
  ))

  let result_bytes = mod_pow_ffi(base_bytes, exp_bytes, mod_bytes)
  bigi.from_bytes(result_bytes, bigi.BigEndian, bigi.Unsigned)
}

fn to_bytes_trimmed(value: BigInt, max_byte_len: Int) -> Result(BitArray, Nil) {
  use bytes <- result.try(bigi.to_bytes(
    value,
    bigi.BigEndian,
    bigi.Unsigned,
    max_byte_len,
  ))
  Ok(trim_leading_zeros(bytes))
}

fn trim_leading_zeros(bytes: BitArray) -> BitArray {
  case bytes {
    <<0, rest:bytes>> ->
      case bit_array.byte_size(rest) > 0 {
        True -> trim_leading_zeros(rest)
        False -> bytes
      }
    _ -> bytes
  }
}

fn to_bytes_minimal(value: BigInt) -> Result(BitArray, Nil) {
  let zero = bigi.from_int(0)
  case value == zero {
    True -> Ok(<<0>>)
    False -> {
      let byte_len = compute_byte_length(value, 1)
      use bytes <- result.try(bigi.to_bytes(
        value,
        bigi.BigEndian,
        bigi.Unsigned,
        byte_len,
      ))
      Ok(trim_leading_zeros(bytes))
    }
  }
}

fn compute_byte_length(value: BigInt, len: Int) -> Int {
  let assert Ok(bound) = bigi.power(bigi.from_int(256), bigi.from_int(len))
  case bigi.compare(value, bound) == order.Lt {
    True -> len
    False -> compute_byte_length(value, len + 1)
  }
}

fn factor_rsa_modulus(
  n: BigInt,
  e: BigInt,
  d: BigInt,
  byte_len: Int,
  attempts_left: Int,
) -> Result(#(BigInt, BigInt), Nil) {
  case attempts_left {
    0 -> Error(Nil)
    _ -> {
      let one = bigi.from_int(1)
      let two = bigi.from_int(2)
      let three = bigi.from_int(3)

      let k = bigi.subtract(bigi.multiply(e, d), one)
      let #(t, r) = factor_out_twos(k, two, 0)

      let g_bytes = crypto.random_bytes(byte_len)
      let assert Ok(g_raw) =
        bigi.from_bytes(g_bytes, bigi.BigEndian, bigi.Unsigned)

      let n_minus_3 = bigi.subtract(n, three)
      let g = bigi.add(bigi.modulo(g_raw, n_minus_3), two)

      use x <- result.try(mod_pow(g, r, n, byte_len))

      case try_factor(n, t, x, byte_len) {
        Ok(#(p, q)) -> Ok(#(p, q))
        Error(Nil) -> factor_rsa_modulus(n, e, d, byte_len, attempts_left - 1)
      }
    }
  }
}

fn factor_out_twos(k: BigInt, two: BigInt, count: Int) -> #(Int, BigInt) {
  case bigi.modulo(k, two) == bigi.from_int(0) {
    True -> {
      let assert Ok(next) = bigi.floor_divide(dividend: k, divisor: two)
      factor_out_twos(next, two, count + 1)
    }
    False -> #(count, k)
  }
}

fn try_factor(
  n: BigInt,
  t: Int,
  x: BigInt,
  byte_len: Int,
) -> Result(#(BigInt, BigInt), Nil) {
  let one = bigi.from_int(1)
  let n_minus_1 = bigi.subtract(n, one)

  case x == one || x == n_minus_1 {
    True -> Error(Nil)
    False -> try_factor_loop(n, t, x, 1, byte_len)
  }
}

fn try_factor_loop(
  n: BigInt,
  t: Int,
  x: BigInt,
  i: Int,
  byte_len: Int,
) -> Result(#(BigInt, BigInt), Nil) {
  case i > t {
    True -> Error(Nil)
    False -> {
      let one = bigi.from_int(1)
      let two = bigi.from_int(2)
      let n_minus_1 = bigi.subtract(n, one)

      use y <- result.try(mod_pow(x, two, n, byte_len))

      case y == one {
        True -> {
          let p = gcd(bigi.subtract(x, one), n)
          case
            bigi.compare(p, one) == order.Gt && bigi.compare(p, n) == order.Lt
          {
            True -> {
              let assert Ok(q) = bigi.floor_divide(dividend: n, divisor: p)
              case bigi.compare(p, q) == order.Lt {
                True -> Ok(#(p, q))
                False -> Ok(#(q, p))
              }
            }
            False -> Error(Nil)
          }
        }
        False ->
          case y == n_minus_1 {
            True -> Error(Nil)
            False -> try_factor_loop(n, t, y, i + 1, byte_len)
          }
      }
    }
  }
}

fn gcd(a: BigInt, b: BigInt) -> BigInt {
  let zero = bigi.from_int(0)
  case b == zero {
    True -> bigi.absolute(a)
    False -> gcd(b, bigi.modulo(a, b))
  }
}

fn mod_inverse(a: BigInt, mod: BigInt) -> Result(BigInt, Nil) {
  let zero = bigi.from_int(0)
  let one = bigi.from_int(1)

  let #(old_r, old_s, _) = extended_gcd_loop(a, mod, one, zero, zero, one)

  case old_r == one {
    True -> {
      let result = bigi.modulo(old_s, mod)
      case bigi.compare(result, zero) == order.Lt {
        True -> Ok(bigi.add(result, mod))
        False -> Ok(result)
      }
    }
    False -> Error(Nil)
  }
}

fn extended_gcd_loop(
  old_r: BigInt,
  r: BigInt,
  old_s: BigInt,
  s: BigInt,
  old_t: BigInt,
  t: BigInt,
) -> #(BigInt, BigInt, BigInt) {
  let zero = bigi.from_int(0)
  case r == zero {
    True -> #(old_r, old_s, old_t)
    False -> {
      let assert Ok(q) = bigi.floor_divide(dividend: old_r, divisor: r)
      let new_r = bigi.subtract(old_r, bigi.multiply(q, r))
      let new_s = bigi.subtract(old_s, bigi.multiply(q, s))
      let new_t = bigi.subtract(old_t, bigi.multiply(q, t))
      extended_gcd_loop(r, new_r, s, new_s, t, new_t)
    }
  }
}
