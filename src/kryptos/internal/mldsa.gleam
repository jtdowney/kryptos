//// Internal ML-DSA (FIPS 204) constants, types, and polynomial arithmetic.
////
//// Erlang's `crypto:generate_key/2` and Node's `crypto.generateKeyPairSync`
//// do not accept a 32-byte seed; importing a seed-form PKCS#8 key therefore
//// requires deriving the public key from the seed. The JavaScript target
//// handles this natively, so the code here is only reachable on Erlang.

import gleam/bit_array
import gleam/bool
import gleam/bytes_tree
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/pair
import gleam/result
import kryptos/hash
import kryptos/mldsa

const q = 8_380_417

const n = 256

const inv_ntt_scale = 8_347_681

type Eta {
  Eta2
  Eta4
}

type Config {
  Config(k: Int, l: Int, eta: Eta)
}

fn param_config(param: mldsa.ParameterSet) -> Config {
  case param {
    mldsa.Mldsa44 -> Config(k: 4, l: 4, eta: Eta2)
    mldsa.Mldsa65 -> Config(k: 6, l: 5, eta: Eta4)
    mldsa.Mldsa87 -> Config(k: 8, l: 7, eta: Eta2)
  }
}

// FIPS 204 NTT twiddle factors: zetas[i] = 1753^bitrev8(i) mod 8380417
fn zetas() -> Dict(Int, Int) {
  [
    1,
    4_808_194,
    3_765_607,
    3_761_513,
    5_178_923,
    5_496_691,
    5_234_739,
    5_178_987,
    7_778_734,
    3_542_485,
    2_682_288,
    2_129_892,
    3_764_867,
    7_375_178,
    557_458,
    7_159_240,
    5_010_068,
    4_317_364,
    2_663_378,
    6_705_802,
    4_855_975,
    7_946_292,
    676_590,
    7_044_481,
    5_152_541,
    1_714_295,
    2_453_983,
    1_460_718,
    7_737_789,
    4_795_319,
    2_815_639,
    2_283_733,
    3_602_218,
    3_182_878,
    2_740_543,
    4_793_971,
    5_269_599,
    2_101_410,
    3_704_823,
    1_159_875,
    394_148,
    928_749,
    1_095_468,
    4_874_037,
    2_071_829,
    4_361_428,
    3_241_972,
    2_156_050,
    3_415_069,
    1_759_347,
    7_562_881,
    4_805_951,
    3_756_790,
    6_444_618,
    6_663_429,
    4_430_364,
    5_483_103,
    3_192_354,
    556_856,
    3_870_317,
    2_917_338,
    1_853_806,
    3_345_963,
    1_858_416,
    3_073_009,
    1_277_625,
    5_744_944,
    3_852_015,
    4_183_372,
    5_157_610,
    5_258_977,
    8_106_357,
    2_508_980,
    2_028_118,
    1_937_570,
    4_564_692,
    2_811_291,
    5_396_636,
    7_270_901,
    4_158_088,
    1_528_066,
    482_649,
    1_148_858,
    5_418_153,
    7_814_814,
    169_688,
    2_462_444,
    5_046_034,
    4_213_992,
    4_892_034,
    1_987_814,
    5_183_169,
    1_736_313,
    235_407,
    5_130_263,
    3_258_457,
    5_801_164,
    1_787_943,
    5_989_328,
    6_125_690,
    3_482_206,
    4_197_502,
    7_080_401,
    6_018_354,
    7_062_739,
    2_461_387,
    3_035_980,
    621_164,
    3_901_472,
    7_153_756,
    2_925_816,
    3_374_250,
    1_356_448,
    5_604_662,
    2_683_270,
    5_601_629,
    4_912_752,
    2_312_838,
    7_727_142,
    7_921_254,
    348_812,
    8_052_569,
    1_011_223,
    6_026_202,
    4_561_790,
    6_458_164,
    6_143_691,
    1_744_507,
    1753,
    6_444_997,
    5_720_892,
    6_924_527,
    2_660_408,
    6_600_190,
    8_321_269,
    2_772_600,
    1_182_243,
    87_208,
    636_927,
    4_415_111,
    4_423_672,
    6_084_020,
    5_095_502,
    4_663_471,
    8_352_605,
    822_541,
    1_009_365,
    5_926_272,
    6_400_920,
    1_596_822,
    4_423_473,
    4_620_952,
    6_695_264,
    4_969_849,
    2_678_278,
    4_611_469,
    4_829_411,
    635_956,
    8_129_971,
    5_925_040,
    4_234_153,
    6_607_829,
    2_192_938,
    6_653_329,
    2_387_513,
    4_768_667,
    8_111_961,
    5_199_961,
    3_747_250,
    2_296_099,
    1_239_911,
    4_541_938,
    3_195_676,
    2_642_980,
    1_254_190,
    8_368_000,
    2_998_219,
    141_835,
    8_291_116,
    2_513_018,
    7_025_525,
    613_238,
    7_070_156,
    6_161_950,
    7_921_677,
    6_458_423,
    4_040_196,
    4_908_348,
    2_039_144,
    6_500_539,
    7_561_656,
    6_201_452,
    6_757_063,
    2_105_286,
    6_006_015,
    6_346_610,
    586_241,
    7_200_804,
    527_981,
    5_637_006,
    6_903_432,
    1_994_046,
    2_491_325,
    6_987_258,
    507_927,
    7_192_532,
    7_655_613,
    6_545_891,
    5_346_675,
    8_041_997,
    2_647_994,
    3_009_748,
    5_767_564,
    4_148_469,
    749_577,
    4_357_667,
    3_980_599,
    2_569_011,
    6_764_887,
    1_723_229,
    1_665_318,
    2_028_038,
    1_163_598,
    5_011_144,
    3_994_671,
    8_368_538,
    7_009_900,
    3_020_393,
    3_363_542,
    214_880,
    545_376,
    7_609_976,
    3_105_558,
    7_277_073,
    508_145,
    7_826_699,
    860_144,
    3_430_436,
    140_244,
    6_866_265,
    6_195_333,
    3_123_762,
    2_358_373,
    6_187_330,
    5_365_997,
    6_663_603,
    2_926_054,
    7_987_710,
    8_077_412,
    3_531_229,
    4_405_932,
    4_606_686,
    1_900_052,
    7_598_542,
    1_054_478,
    7_648_983,
  ]
  |> list.index_map(fn(x, i) { #(i, x) })
  |> dict.from_list
}

fn mod_q(x: Int) -> Int {
  let r = x % q
  case r < 0 {
    True -> r + q
    False -> r
  }
}

fn poly_add(a: List(Int), b: List(Int)) -> List(Int) {
  list.map2(a, b, fn(ai, bi) { mod_q(ai + bi) })
}

fn poly_to_dict(poly: List(Int)) -> Dict(Int, Int) {
  poly
  |> list.index_map(fn(x, i) { #(i, x) })
  |> dict.from_list
}

fn dict_to_poly(d: Dict(Int, Int)) -> List(Int) {
  int.range(from: n - 1, to: -1, with: [], run: fn(acc, i) {
    let assert Ok(v) = dict.get(d, i)
    [v, ..acc]
  })
}

fn ntt_outer(
  coeffs: Dict(Int, Int),
  z: Dict(Int, Int),
  k: Int,
  length: Int,
) -> #(Dict(Int, Int), Int) {
  use <- bool.guard(when: length < 1, return: #(coeffs, k))
  let #(coeffs, k) = ntt_middle(coeffs, z, k, length, 0)
  ntt_outer(coeffs, z, k, length / 2)
}

fn ntt_middle(
  coeffs: Dict(Int, Int),
  z: Dict(Int, Int),
  k: Int,
  length: Int,
  start: Int,
) -> #(Dict(Int, Int), Int) {
  use <- bool.guard(when: start >= n, return: #(coeffs, k))
  let k = k + 1
  let assert Ok(zeta) = dict.get(z, k)
  let coeffs = ntt_inner(coeffs, zeta, length, start, start)
  ntt_middle(coeffs, z, k, length, start + 2 * length)
}

fn ntt_inner(
  coeffs: Dict(Int, Int),
  zeta: Int,
  length: Int,
  end: Int,
  j: Int,
) -> Dict(Int, Int) {
  use <- bool.guard(when: j >= end + length, return: coeffs)
  let assert Ok(cj) = dict.get(coeffs, j)
  let assert Ok(cjl) = dict.get(coeffs, j + length)
  let t = mod_q(zeta * cjl)
  let coeffs =
    coeffs
    |> dict.insert(j + length, mod_q(cj - t))
    |> dict.insert(j, mod_q(cj + t))

  ntt_inner(coeffs, zeta, length, end, j + 1)
}

fn intt_outer(
  coeffs: Dict(Int, Int),
  z: Dict(Int, Int),
  k: Int,
  length: Int,
) -> #(Dict(Int, Int), Int) {
  use <- bool.guard(when: length >= n, return: #(coeffs, k))
  let #(coeffs, k) = intt_middle(coeffs, z, k, length, 0)
  intt_outer(coeffs, z, k, length * 2)
}

fn intt_middle(
  coeffs: Dict(Int, Int),
  z: Dict(Int, Int),
  k: Int,
  length: Int,
  start: Int,
) -> #(Dict(Int, Int), Int) {
  use <- bool.guard(when: start >= n, return: #(coeffs, k))
  let k = k - 1
  let assert Ok(zeta) = dict.get(z, k)
  let neg_zeta = q - zeta
  let coeffs = intt_inner(coeffs, neg_zeta, length, start, start)
  intt_middle(coeffs, z, k, length, start + 2 * length)
}

fn intt_inner(
  coeffs: Dict(Int, Int),
  neg_zeta: Int,
  length: Int,
  end: Int,
  j: Int,
) -> Dict(Int, Int) {
  use <- bool.guard(when: j >= end + length, return: coeffs)
  let assert Ok(cj) = dict.get(coeffs, j)
  let assert Ok(cjl) = dict.get(coeffs, j + length)
  let coeffs =
    coeffs
    |> dict.insert(j, mod_q(cj + cjl))
    |> dict.insert(j + length, mod_q(neg_zeta * { cj - cjl }))
  intt_inner(coeffs, neg_zeta, length, end, j + 1)
}

fn ntt_from_dict(coeffs: Dict(Int, Int), z: Dict(Int, Int)) -> Dict(Int, Int) {
  let #(result, _k) = ntt_outer(coeffs, z, 0, 128)
  result
}

fn intt_to_list(coeffs: Dict(Int, Int), z: Dict(Int, Int)) -> List(Int) {
  let #(result, _k) = intt_outer(coeffs, z, n, 1)
  result
  |> dict_to_poly
  |> list.map(fn(v) { mod_q(v * inv_ntt_scale) })
}

fn poly_zero_dict() -> Dict(Int, Int) {
  int.range(from: 0, to: n, with: dict.new(), run: fn(acc, i) {
    dict.insert(acc, i, 0)
  })
}

fn dict_zip_with(
  a: Dict(Int, Int),
  b: Dict(Int, Int),
  op: fn(Int, Int) -> Int,
) -> Dict(Int, Int) {
  dict.map_values(a, fn(i, ai) {
    let assert Ok(bi) = dict.get(b, i)
    mod_q(op(ai, bi))
  })
}

fn poly_add_dict(a: Dict(Int, Int), b: Dict(Int, Int)) -> Dict(Int, Int) {
  dict_zip_with(a, b, int.add)
}

fn poly_pointwise_mul_dict(
  a: Dict(Int, Int),
  b: Dict(Int, Int),
) -> Dict(Int, Int) {
  dict_zip_with(a, b, int.multiply)
}

fn expand_a(
  rho: BitArray,
  config: Config,
) -> Result(List(List(List(Int))), Nil) {
  int.range(from: config.k - 1, to: -1, with: [], run: list.prepend)
  |> list.try_map(fn(i) {
    int.range(from: config.l - 1, to: -1, with: [], run: list.prepend)
    |> list.try_map(fn(j) { rej_ntt_poly(rho, j, i) })
  })
}

fn rej_ntt_poly(rho: BitArray, j: Int, i: Int) -> Result(List(Int), Nil) {
  let assert Ok(algo) = hash.shake_128(output_length: 1024)
  let assert Ok(h) = hash.new(algo)
  let output =
    h
    |> hash.update(rho)
    |> hash.update(<<j:8, i:8>>)
    |> hash.final()
  rejection_sample(output, [], 0)
}

fn rejection_sample(
  bytes: BitArray,
  acc: List(Int),
  count: Int,
) -> Result(List(Int), Nil) {
  use <- bool.guard(when: count >= n, return: Ok(list.reverse(acc)))
  case bytes {
    <<val:24-little, rest:bits>> -> {
      let val = int.bitwise_and(val, 0x7FFFFF)
      case val < q {
        True -> rejection_sample(rest, [val, ..acc], count + 1)
        False -> rejection_sample(rest, acc, count)
      }
    }
    _ -> Error(Nil)
  }
}

fn expand_s(
  rho_prime: BitArray,
  config: Config,
) -> Result(#(List(List(Int)), List(List(Int))), Nil) {
  use s1 <- result.try(
    list.try_map(
      int.range(from: config.l - 1, to: -1, with: [], run: list.prepend),
      fn(nonce) { rej_bounded_poly(rho_prime, nonce, config.eta) },
    ),
  )
  use s2 <- result.try(
    list.try_map(
      int.range(from: config.k - 1, to: -1, with: [], run: list.prepend),
      fn(i) { rej_bounded_poly(rho_prime, config.l + i, config.eta) },
    ),
  )
  Ok(#(s1, s2))
}

fn rej_bounded_poly(
  rho_prime: BitArray,
  nonce: Int,
  eta: Eta,
) -> Result(List(Int), Nil) {
  let assert Ok(algo) = hash.shake_256(output_length: 512)
  let assert Ok(h) = hash.new(algo)
  let output =
    h
    |> hash.update(rho_prime)
    |> hash.update(<<nonce:16-little>>)
    |> hash.final()
  half_byte_sample(output, eta, [], 0)
}

fn half_byte_sample(
  bytes: BitArray,
  eta: Eta,
  acc: List(Int),
  count: Int,
) -> Result(List(Int), Nil) {
  use <- bool.guard(when: count >= n, return: Ok(list.reverse(acc)))
  case bytes {
    <<byte:8, rest:bits>> -> {
      let lo = byte % 16
      let hi = byte / 16
      let #(acc, count) = push_coeff(acc, count, lo, eta)
      case count >= n {
        True -> Ok(list.reverse(acc))
        False -> {
          let #(acc, count) = push_coeff(acc, count, hi, eta)
          half_byte_sample(rest, eta, acc, count)
        }
      }
    }
    _ -> Error(Nil)
  }
}

fn push_coeff(
  acc: List(Int),
  count: Int,
  nibble: Int,
  eta: Eta,
) -> #(List(Int), Int) {
  case coeff_from_half_byte(nibble, eta) {
    Ok(c) -> #([c, ..acc], count + 1)
    Error(Nil) -> #(acc, count)
  }
}

fn coeff_from_half_byte(nibble: Int, eta: Eta) -> Result(Int, Nil) {
  case eta {
    Eta2 ->
      case nibble < 15 {
        True -> Ok(mod_q(2 - nibble % 5))
        False -> Error(Nil)
      }
    Eta4 ->
      case nibble < 9 {
        True -> Ok(mod_q(4 - nibble))
        False -> Error(Nil)
      }
  }
}

fn power2round(r: Int) -> #(Int, Int) {
  let r_pos = mod_q(r)
  let two_d = 8192
  let r0 = r_pos % two_d
  let r0_centered = case r0 > two_d / 2 {
    True -> r0 - two_d
    False -> r0
  }
  let r1 = { r_pos - r0_centered } / two_d
  #(r1, r0_centered)
}

fn simple_bit_pack_t1(coeffs: List(Int)) -> BitArray {
  simple_bit_pack_t1_loop(coeffs, 0, 0, <<>>)
}

fn simple_bit_pack_t1_loop(
  coeffs: List(Int),
  bit_buffer: Int,
  bits_in_buffer: Int,
  acc: BitArray,
) -> BitArray {
  case coeffs {
    // t1 is 256 coeffs x 10 bits = 320 bytes exactly, so the buffer is always
    // byte-aligned (empty) here — no partial byte to flush.
    [] -> acc
    [c, ..rest] -> {
      let bit_buffer =
        bit_buffer + c * int.bitwise_shift_left(1, bits_in_buffer)
      let bits_in_buffer = bits_in_buffer + 10
      let #(bit_buffer, bits_in_buffer, acc) =
        emit_full_bytes(bit_buffer, bits_in_buffer, acc)
      simple_bit_pack_t1_loop(rest, bit_buffer, bits_in_buffer, acc)
    }
  }
}

fn emit_full_bytes(
  bit_buffer: Int,
  bits_in_buffer: Int,
  acc: BitArray,
) -> #(Int, Int, BitArray) {
  case bits_in_buffer >= 8 {
    True -> {
      let byte = bit_buffer % 256
      emit_full_bytes(bit_buffer / 256, bits_in_buffer - 8, <<
        acc:bits,
        byte:8,
      >>)
    }
    False -> #(bit_buffer, bits_in_buffer, acc)
  }
}

pub fn public_key_from_seed(
  param: mldsa.ParameterSet,
  seed: BitArray,
) -> Result(BitArray, Nil) {
  use <- bool.guard(when: bit_array.byte_size(seed) != 32, return: Error(Nil))
  let config = param_config(param)

  let assert Ok(algo) = hash.shake_256(output_length: 96)
  let assert Ok(h) = hash.new(algo)
  let expanded =
    h
    |> hash.update(seed)
    |> hash.update(<<config.k:8, config.l:8>>)
    |> hash.final()
  let assert <<rho:bytes-size(32), rho_prime:bytes>> = expanded

  use a_hat <- result.try(expand_a(rho, config))
  use #(s1, s2) <- result.try(expand_s(rho_prime, config))

  let z = zetas()
  let s1_hat =
    list.map(s1, fn(p) {
      p
      |> poly_to_dict
      |> ntt_from_dict(z)
    })

  let t =
    list.map2(a_hat, s2, fn(a_row, s2_i) {
      let product =
        list.map2(a_row, s1_hat, fn(a_poly, s1_hat_i) {
          a_poly
          |> poly_to_dict
          |> poly_pointwise_mul_dict(s1_hat_i)
        })
        |> list.fold(poly_zero_dict(), poly_add_dict)
      poly_add(intt_to_list(product, z), s2_i)
    })

  let t1 = list.map(t, list.map(_, fn(c) { pair.first(power2round(c)) }))

  let public_key =
    bytes_tree.new()
    |> bytes_tree.append(rho)
    |> bytes_tree.append_tree(
      list.map(t1, simple_bit_pack_t1)
      |> bytes_tree.concat_bit_arrays,
    )
    |> bytes_tree.to_bit_array

  Ok(public_key)
}
