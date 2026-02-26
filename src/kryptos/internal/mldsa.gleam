//// Internal ML-DSA (FIPS 204) constants, types, and polynomial arithmetic.

import gleam/bit_array
import gleam/bool
import gleam/bytes_tree
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/pair
import kryptos/hash
import kryptos/mldsa.{type ParameterSet, Mldsa44, Mldsa65, Mldsa87}

pub const q = 8_380_417

pub const n = 256

const inv_ntt_scale = 8_347_681

pub type Config {
  Config(k: Int, l: Int, eta: Int)
}

pub fn param_config(param: ParameterSet) -> Config {
  case param {
    Mldsa44 -> Config(k: 4, l: 4, eta: 2)
    Mldsa65 -> Config(k: 6, l: 5, eta: 4)
    Mldsa87 -> Config(k: 8, l: 7, eta: 2)
  }
}

pub fn zetas() -> Dict(Int, Int) {
  [
    #(0, 1),
    #(1, 4_808_194),
    #(2, 3_765_607),
    #(3, 3_761_513),
    #(4, 5_178_923),
    #(5, 5_496_691),
    #(6, 5_234_739),
    #(7, 5_178_987),
    #(8, 7_778_734),
    #(9, 3_542_485),
    #(10, 2_682_288),
    #(11, 2_129_892),
    #(12, 3_764_867),
    #(13, 7_375_178),
    #(14, 557_458),
    #(15, 7_159_240),
    #(16, 5_010_068),
    #(17, 4_317_364),
    #(18, 2_663_378),
    #(19, 6_705_802),
    #(20, 4_855_975),
    #(21, 7_946_292),
    #(22, 676_590),
    #(23, 7_044_481),
    #(24, 5_152_541),
    #(25, 1_714_295),
    #(26, 2_453_983),
    #(27, 1_460_718),
    #(28, 7_737_789),
    #(29, 4_795_319),
    #(30, 2_815_639),
    #(31, 2_283_733),
    #(32, 3_602_218),
    #(33, 3_182_878),
    #(34, 2_740_543),
    #(35, 4_793_971),
    #(36, 5_269_599),
    #(37, 2_101_410),
    #(38, 3_704_823),
    #(39, 1_159_875),
    #(40, 394_148),
    #(41, 928_749),
    #(42, 1_095_468),
    #(43, 4_874_037),
    #(44, 2_071_829),
    #(45, 4_361_428),
    #(46, 3_241_972),
    #(47, 2_156_050),
    #(48, 3_415_069),
    #(49, 1_759_347),
    #(50, 7_562_881),
    #(51, 4_805_951),
    #(52, 3_756_790),
    #(53, 6_444_618),
    #(54, 6_663_429),
    #(55, 4_430_364),
    #(56, 5_483_103),
    #(57, 3_192_354),
    #(58, 556_856),
    #(59, 3_870_317),
    #(60, 2_917_338),
    #(61, 1_853_806),
    #(62, 3_345_963),
    #(63, 1_858_416),
    #(64, 3_073_009),
    #(65, 1_277_625),
    #(66, 5_744_944),
    #(67, 3_852_015),
    #(68, 4_183_372),
    #(69, 5_157_610),
    #(70, 5_258_977),
    #(71, 8_106_357),
    #(72, 2_508_980),
    #(73, 2_028_118),
    #(74, 1_937_570),
    #(75, 4_564_692),
    #(76, 2_811_291),
    #(77, 5_396_636),
    #(78, 7_270_901),
    #(79, 4_158_088),
    #(80, 1_528_066),
    #(81, 482_649),
    #(82, 1_148_858),
    #(83, 5_418_153),
    #(84, 7_814_814),
    #(85, 169_688),
    #(86, 2_462_444),
    #(87, 5_046_034),
    #(88, 4_213_992),
    #(89, 4_892_034),
    #(90, 1_987_814),
    #(91, 5_183_169),
    #(92, 1_736_313),
    #(93, 235_407),
    #(94, 5_130_263),
    #(95, 3_258_457),
    #(96, 5_801_164),
    #(97, 1_787_943),
    #(98, 5_989_328),
    #(99, 6_125_690),
    #(100, 3_482_206),
    #(101, 4_197_502),
    #(102, 7_080_401),
    #(103, 6_018_354),
    #(104, 7_062_739),
    #(105, 2_461_387),
    #(106, 3_035_980),
    #(107, 621_164),
    #(108, 3_901_472),
    #(109, 7_153_756),
    #(110, 2_925_816),
    #(111, 3_374_250),
    #(112, 1_356_448),
    #(113, 5_604_662),
    #(114, 2_683_270),
    #(115, 5_601_629),
    #(116, 4_912_752),
    #(117, 2_312_838),
    #(118, 7_727_142),
    #(119, 7_921_254),
    #(120, 348_812),
    #(121, 8_052_569),
    #(122, 1_011_223),
    #(123, 6_026_202),
    #(124, 4_561_790),
    #(125, 6_458_164),
    #(126, 6_143_691),
    #(127, 1_744_507),
    #(128, 1753),
    #(129, 6_444_997),
    #(130, 5_720_892),
    #(131, 6_924_527),
    #(132, 2_660_408),
    #(133, 6_600_190),
    #(134, 8_321_269),
    #(135, 2_772_600),
    #(136, 1_182_243),
    #(137, 87_208),
    #(138, 636_927),
    #(139, 4_415_111),
    #(140, 4_423_672),
    #(141, 6_084_020),
    #(142, 5_095_502),
    #(143, 4_663_471),
    #(144, 8_352_605),
    #(145, 822_541),
    #(146, 1_009_365),
    #(147, 5_926_272),
    #(148, 6_400_920),
    #(149, 1_596_822),
    #(150, 4_423_473),
    #(151, 4_620_952),
    #(152, 6_695_264),
    #(153, 4_969_849),
    #(154, 2_678_278),
    #(155, 4_611_469),
    #(156, 4_829_411),
    #(157, 635_956),
    #(158, 8_129_971),
    #(159, 5_925_040),
    #(160, 4_234_153),
    #(161, 6_607_829),
    #(162, 2_192_938),
    #(163, 6_653_329),
    #(164, 2_387_513),
    #(165, 4_768_667),
    #(166, 8_111_961),
    #(167, 5_199_961),
    #(168, 3_747_250),
    #(169, 2_296_099),
    #(170, 1_239_911),
    #(171, 4_541_938),
    #(172, 3_195_676),
    #(173, 2_642_980),
    #(174, 1_254_190),
    #(175, 8_368_000),
    #(176, 2_998_219),
    #(177, 141_835),
    #(178, 8_291_116),
    #(179, 2_513_018),
    #(180, 7_025_525),
    #(181, 613_238),
    #(182, 7_070_156),
    #(183, 6_161_950),
    #(184, 7_921_677),
    #(185, 6_458_423),
    #(186, 4_040_196),
    #(187, 4_908_348),
    #(188, 2_039_144),
    #(189, 6_500_539),
    #(190, 7_561_656),
    #(191, 6_201_452),
    #(192, 6_757_063),
    #(193, 2_105_286),
    #(194, 6_006_015),
    #(195, 6_346_610),
    #(196, 586_241),
    #(197, 7_200_804),
    #(198, 527_981),
    #(199, 5_637_006),
    #(200, 6_903_432),
    #(201, 1_994_046),
    #(202, 2_491_325),
    #(203, 6_987_258),
    #(204, 507_927),
    #(205, 7_192_532),
    #(206, 7_655_613),
    #(207, 6_545_891),
    #(208, 5_346_675),
    #(209, 8_041_997),
    #(210, 2_647_994),
    #(211, 3_009_748),
    #(212, 5_767_564),
    #(213, 4_148_469),
    #(214, 749_577),
    #(215, 4_357_667),
    #(216, 3_980_599),
    #(217, 2_569_011),
    #(218, 6_764_887),
    #(219, 1_723_229),
    #(220, 1_665_318),
    #(221, 2_028_038),
    #(222, 1_163_598),
    #(223, 5_011_144),
    #(224, 3_994_671),
    #(225, 8_368_538),
    #(226, 7_009_900),
    #(227, 3_020_393),
    #(228, 3_363_542),
    #(229, 214_880),
    #(230, 545_376),
    #(231, 7_609_976),
    #(232, 3_105_558),
    #(233, 7_277_073),
    #(234, 508_145),
    #(235, 7_826_699),
    #(236, 860_144),
    #(237, 3_430_436),
    #(238, 140_244),
    #(239, 6_866_265),
    #(240, 6_195_333),
    #(241, 3_123_762),
    #(242, 2_358_373),
    #(243, 6_187_330),
    #(244, 5_365_997),
    #(245, 6_663_603),
    #(246, 2_926_054),
    #(247, 7_987_710),
    #(248, 8_077_412),
    #(249, 3_531_229),
    #(250, 4_405_932),
    #(251, 4_606_686),
    #(252, 1_900_052),
    #(253, 7_598_542),
    #(254, 1_054_478),
    #(255, 7_648_983),
  ]
  |> dict.from_list
}

pub fn mod_q(x: Int) -> Int {
  let r = x % q
  case r < 0 {
    True -> r + q
    False -> r
  }
}

pub fn poly_add(a: List(Int), b: List(Int)) -> List(Int) {
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

pub fn ntt(poly: List(Int), z: Dict(Int, Int)) -> List(Int) {
  let #(result, _k) = ntt_outer(poly_to_dict(poly), z, 0, 128)
  dict_to_poly(result)
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

pub fn intt(poly: List(Int), z: Dict(Int, Int)) -> List(Int) {
  poly
  |> poly_to_dict
  |> intt_to_list(z)
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

fn poly_add_dict(a: Dict(Int, Int), b: Dict(Int, Int)) -> Dict(Int, Int) {
  dict.map_values(a, fn(i, ai) {
    let assert Ok(bi) = dict.get(b, i)
    mod_q(ai + bi)
  })
}

fn poly_pointwise_mul_dict(
  a: Dict(Int, Int),
  b: Dict(Int, Int),
) -> Dict(Int, Int) {
  dict.map_values(a, fn(i, ai) {
    let assert Ok(bi) = dict.get(b, i)
    mod_q(ai * bi)
  })
}

pub fn expand_a(rho: BitArray, config: Config) -> List(List(List(Int))) {
  list.repeat(Nil, config.k)
  |> list.index_map(fn(_, i) {
    list.repeat(Nil, config.l)
    |> list.index_map(fn(_, j) { rej_ntt_poly(rho, j, i) })
  })
}

fn rej_ntt_poly(rho: BitArray, j: Int, i: Int) -> List(Int) {
  let assert Ok(algo) = hash.shake_128(output_length: 1024)
  let assert Ok(h) = hash.new(algo)
  let output =
    h
    |> hash.update(rho)
    |> hash.update(<<j:8, i:8>>)
    |> hash.final()
  let assert Ok(coeffs) = rejection_sample(output, [], 0)
  coeffs
}

fn rejection_sample(
  bytes: BitArray,
  acc: List(Int),
  count: Int,
) -> Result(List(Int), Nil) {
  use <- bool.guard(when: count >= n, return: Ok(list.reverse(acc)))
  case bytes {
    <<b0:8, b1:8, b2:8, rest:bits>> -> {
      let val = int.bitwise_and(b0 + b1 * 256 + b2 * 65_536, 0x7FFFFF)
      case val < q {
        True -> rejection_sample(rest, [val, ..acc], count + 1)
        False -> rejection_sample(rest, acc, count)
      }
    }
    _ -> Error(Nil)
  }
}

pub fn expand_s(
  rho_prime: BitArray,
  config: Config,
) -> #(List(List(Int)), List(List(Int))) {
  let s1 =
    list.repeat(Nil, config.l)
    |> list.index_map(fn(_, nonce) {
      rej_bounded_poly(rho_prime, nonce, config.eta)
    })
  let s2 =
    list.repeat(Nil, config.k)
    |> list.index_map(fn(_, i) {
      rej_bounded_poly(rho_prime, config.l + i, config.eta)
    })
  #(s1, s2)
}

fn rej_bounded_poly(rho_prime: BitArray, nonce: Int, eta: Int) -> List(Int) {
  let assert Ok(algo) = hash.shake_256(output_length: 512)
  let assert Ok(h) = hash.new(algo)
  let output =
    h
    |> hash.update(rho_prime)
    |> hash.update(<<nonce:16-little>>)
    |> hash.final()
  let assert Ok(coeffs) = half_byte_sample(output, eta, [], 0)
  coeffs
}

fn half_byte_sample(
  bytes: BitArray,
  eta: Int,
  acc: List(Int),
  count: Int,
) -> Result(List(Int), Nil) {
  use <- bool.guard(when: count >= n, return: Ok(list.reverse(acc)))
  case bytes {
    <<byte:8, rest:bits>> -> {
      let lo = byte % 16
      let hi = byte / 16
      let #(acc, count) = case coeff_from_half_byte(lo, eta) {
        Ok(c) -> #([c, ..acc], count + 1)
        Error(Nil) -> #(acc, count)
      }
      case count >= n {
        True -> Ok(list.reverse(acc))
        False -> {
          let #(acc, count) = case coeff_from_half_byte(hi, eta) {
            Ok(c) -> #([c, ..acc], count + 1)
            Error(Nil) -> #(acc, count)
          }
          half_byte_sample(rest, eta, acc, count)
        }
      }
    }
    _ -> Error(Nil)
  }
}

fn coeff_from_half_byte(nibble: Int, eta: Int) -> Result(Int, Nil) {
  case eta {
    2 ->
      case nibble < 15 {
        True -> Ok(mod_q(eta - nibble % 5))
        False -> Error(Nil)
      }
    4 ->
      case nibble < 9 {
        True -> Ok(mod_q(eta - nibble))
        False -> Error(Nil)
      }
    _ -> Error(Nil)
  }
}

pub fn power2round(r: Int) -> #(Int, Int) {
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

pub fn simple_bit_pack_t1(coeffs: List(Int)) -> BitArray {
  simple_bit_pack_t1_loop(coeffs, 0, 0, <<>>)
}

fn simple_bit_pack_t1_loop(
  coeffs: List(Int),
  bit_buffer: Int,
  bits_in_buffer: Int,
  acc: BitArray,
) -> BitArray {
  case coeffs {
    [] -> flush_remaining_bits(bit_buffer, bits_in_buffer, acc)
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

fn flush_remaining_bits(
  bit_buffer: Int,
  bits_in_buffer: Int,
  acc: BitArray,
) -> BitArray {
  case bits_in_buffer > 0 {
    True -> <<acc:bits, bit_buffer:8>>
    False -> acc
  }
}

pub fn public_key_from_seed(
  param: ParameterSet,
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
  let assert <<rho:bytes-size(32), rho_prime:bytes-size(64)>> = expanded

  let a_hat = expand_a(rho, config)
  let #(s1, s2) = expand_s(rho_prime, config)

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

  bytes_tree.new()
  |> bytes_tree.append(rho)
  |> bytes_tree.append_tree(
    list.map(t1, simple_bit_pack_t1)
    |> bytes_tree.concat_bit_arrays,
  )
  |> bytes_tree.to_bit_array
  |> Ok
}
