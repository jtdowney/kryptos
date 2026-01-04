import gleam/bit_array
import kryptos/crypto

pub fn random_bytes_test() {
  let bytes = crypto.random_bytes(16)
  assert bit_array.byte_size(bytes) == 16
}

pub fn random_bytes_zero_test() {
  let bytes = crypto.random_bytes(0)
  assert bit_array.byte_size(bytes) == 0
}

pub fn random_bytes_negative_test() {
  let bytes = crypto.random_bytes(-1)
  assert bit_array.byte_size(bytes) == 0
}

pub fn random_bytes_large_test() {
  let bytes = crypto.random_bytes(100_000)
  assert bit_array.byte_size(bytes) == 100_000
}

pub fn constant_time_equal_test() {
  let a = <<"hello":utf8>>
  let b = <<"hello":utf8>>
  let c = <<"world":utf8>>

  assert crypto.constant_time_equal(a, b)
  assert !crypto.constant_time_equal(a, c)
}

pub fn constant_time_equal_empty_test() {
  assert crypto.constant_time_equal(<<>>, <<>>)
}

pub fn constant_time_equal_length_mismatch_test() {
  assert !crypto.constant_time_equal(<<"short":utf8>>, <<"longer":utf8>>)
  assert !crypto.constant_time_equal(<<>>, <<"nonempty":utf8>>)
}
