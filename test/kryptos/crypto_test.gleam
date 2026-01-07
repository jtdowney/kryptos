import gleam/bit_array
import gleam/list
import gleam/set
import gleam/string
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

pub fn random_uuid_format_test() {
  let uuid = crypto.random_uuid()
  assert string.length(uuid) == 36

  let parts = string.split(uuid, "-")
  assert list.length(parts) == 5

  let assert [p1, p2, p3, p4, p5] = parts
  assert string.length(p1) == 8
  assert string.length(p2) == 4
  assert string.length(p3) == 4
  assert string.length(p4) == 4
  assert string.length(p5) == 12
}

pub fn random_uuid_version_test() {
  let uuid = crypto.random_uuid()
  let assert Ok(version_char) = string.first(string.drop_start(uuid, 14))
  assert version_char == "4"
}

pub fn random_uuid_variant_test() {
  let uuid = crypto.random_uuid()
  let assert Ok(variant_char) = string.first(string.drop_start(uuid, 19))
  assert variant_char == "8"
    || variant_char == "9"
    || variant_char == "a"
    || variant_char == "b"
}

pub fn random_uuid_uniqueness_test() {
  let uuids = list.map(list.range(1, 100), fn(_) { crypto.random_uuid() })
  let unique = set.from_list(uuids)
  assert set.size(unique) == 100
}
