import gleam/bit_array
import gleam/list
import kryptos/internal/mldsa as mldsa_internal
import kryptos/mldsa.{Mldsa44, Mldsa65, Mldsa87}
import qcheck

pub fn expand_a_dimensions_and_bounds_test() {
  let rho = <<0:size(256)>>
  let config = mldsa_internal.param_config(Mldsa44)
  let matrix = mldsa_internal.expand_a(rho, config)
  assert list.length(matrix) == 4
  list.each(matrix, fn(row) {
    assert list.length(row) == 4
    list.each(row, fn(poly) {
      assert list.length(poly) == 256
      list.each(poly, fn(coeff) {
        assert coeff >= 0
        assert coeff < mldsa_internal.q
      })
    })
  })
}

pub fn expand_a_deterministic_test() {
  let rho = <<1:size(256)>>
  let config = mldsa_internal.param_config(Mldsa44)
  let a1 = mldsa_internal.expand_a(rho, config)
  let a2 = mldsa_internal.expand_a(rho, config)
  assert a1 == a2
}

pub fn expand_s_dimensions_and_bounds_eta2_test() {
  let rho_prime = <<0:size(512)>>
  let config = mldsa_internal.param_config(Mldsa44)
  let #(s1, s2) = mldsa_internal.expand_s(rho_prime, config)
  assert list.length(s1) == 4
  assert list.length(s2) == 4
  let valid = fn(c) { c <= 2 || c >= mldsa_internal.q - 2 }
  list.each(list.flatten([s1, s2]), fn(poly) {
    assert list.length(poly) == 256
    list.each(poly, fn(coeff) {
      assert valid(coeff)
    })
  })
}

pub fn expand_s_dimensions_and_bounds_eta4_test() {
  let rho_prime = <<0:size(512)>>
  let config = mldsa_internal.param_config(Mldsa65)
  let #(s1, s2) = mldsa_internal.expand_s(rho_prime, config)
  assert list.length(s1) == 5
  assert list.length(s2) == 6
  let valid = fn(c) { c <= 4 || c >= mldsa_internal.q - 4 }
  list.each(list.flatten([s1, s2]), fn(poly) {
    assert list.length(poly) == 256
    list.each(poly, fn(coeff) {
      assert valid(coeff)
    })
  })
}

pub fn expand_s_deterministic_test() {
  let rho_prime = <<42:size(512)>>
  let config = mldsa_internal.param_config(Mldsa44)
  let r1 = mldsa_internal.expand_s(rho_prime, config)
  let r2 = mldsa_internal.expand_s(rho_prime, config)
  assert r1 == r2
}

// --- Property-based tests ---

fn coeff_gen() -> qcheck.Generator(Int) {
  qcheck.bounded_int(0, mldsa_internal.q - 1)
}

fn poly_gen() -> qcheck.Generator(List(Int)) {
  qcheck.fixed_length_list_from(coeff_gen(), mldsa_internal.n)
}

fn t1_coeff_gen() -> qcheck.Generator(Int) {
  qcheck.bounded_int(0, 1023)
}

fn t1_poly_gen() -> qcheck.Generator(List(Int)) {
  qcheck.fixed_length_list_from(t1_coeff_gen(), mldsa_internal.n)
}

fn int_gen() -> qcheck.Generator(Int) {
  qcheck.bounded_int(-10 * mldsa_internal.q, 10 * mldsa_internal.q)
}

pub fn mod_q_range_property_test() {
  qcheck.run(qcheck.default_config(), int_gen(), fn(x) {
    let r = mldsa_internal.mod_q(x)
    assert r >= 0
    assert r < mldsa_internal.q
  })
}

pub fn mod_q_idempotent_property_test() {
  qcheck.run(qcheck.default_config(), int_gen(), fn(x) {
    assert mldsa_internal.mod_q(mldsa_internal.mod_q(x))
      == mldsa_internal.mod_q(x)
  })
}

pub fn power2round_reconstruct_property_test() {
  qcheck.run(qcheck.default_config(), coeff_gen(), fn(r) {
    let #(r1, r0) = mldsa_internal.power2round(r)
    let reconstructed = mldsa_internal.mod_q(r1 * 8192 + r0)
    assert reconstructed == r
  })
}

pub fn power2round_bounds_property_test() {
  qcheck.run(qcheck.default_config(), coeff_gen(), fn(r) {
    let #(r1, r0) = mldsa_internal.power2round(r)
    assert r1 >= 0
    assert r1 <= 1023
    assert r0 >= -4096
    assert r0 <= 4096
  })
}

pub fn poly_add_commutative_property_test() {
  let gen = qcheck.tuple2(poly_gen(), poly_gen())
  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(a, b) = input
    assert mldsa_internal.poly_add(a, b) == mldsa_internal.poly_add(b, a)
  })
}

pub fn ntt_roundtrip_property_test() {
  let z = mldsa_internal.zetas()
  let config = qcheck.default_config() |> qcheck.with_test_count(10)
  qcheck.run(config, poly_gen(), fn(f) {
    let xs =
      f
      |> mldsa_internal.ntt(z)
      |> mldsa_internal.intt(z)
    assert f == xs
  })
}

pub fn simple_bit_pack_t1_length_property_test() {
  qcheck.run(qcheck.default_config(), t1_poly_gen(), fn(coeffs) {
    let packed = mldsa_internal.simple_bit_pack_t1(coeffs)
    assert bit_array.byte_size(packed) == 320
  })
}

pub fn expand_a_dimensions_mldsa87_test() {
  let rho = <<0:size(256)>>
  let config = mldsa_internal.param_config(Mldsa87)
  let matrix = mldsa_internal.expand_a(rho, config)
  assert list.length(matrix) == 8
  list.each(matrix, fn(row) {
    assert list.length(row) == 7
    list.each(row, fn(poly) {
      assert list.length(poly) == 256
      list.each(poly, fn(coeff) {
        assert coeff >= 0
        assert coeff < mldsa_internal.q
      })
    })
  })
}

pub fn expand_s_dimensions_and_bounds_mldsa87_test() {
  let rho_prime = <<0:size(512)>>
  let config = mldsa_internal.param_config(Mldsa87)
  let #(s1, s2) = mldsa_internal.expand_s(rho_prime, config)
  assert list.length(s1) == 7
  assert list.length(s2) == 8
  let valid = fn(c) { c <= 2 || c >= mldsa_internal.q - 2 }
  list.each(list.flatten([s1, s2]), fn(poly) {
    assert list.length(poly) == 256
    list.each(poly, fn(coeff) {
      assert valid(coeff)
    })
  })
}
