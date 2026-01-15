import gleam/bit_array
import gleam/list
import gleam/set
import gleam/string
import kryptos/crypto
import qcheck

// Property: random_bytes(n) always returns exactly n bytes
pub fn random_bytes_length_property_test() {
  qcheck.run(qcheck.default_config(), qcheck.bounded_int(0, 1000), fn(size) {
    let bytes = crypto.random_bytes(size)
    assert bit_array.byte_size(bytes) == size
  })
}

// Edge case: negative sizes are handled gracefully
pub fn random_bytes_negative_test() {
  let bytes = crypto.random_bytes(-1)
  assert bit_array.byte_size(bytes) == 0
}

// Property: constant_time_equal is reflexive (a == a)
pub fn constant_time_equal_reflexive_property_test() {
  qcheck.run(qcheck.default_config(), qcheck.byte_aligned_bit_array(), fn(data) {
    assert crypto.constant_time_equal(data, data)
  })
}

// Property: constant_time_equal is symmetric (a == b implies b == a)
pub fn constant_time_equal_symmetric_property_test() {
  qcheck.run(
    qcheck.default_config(),
    qcheck.tuple2(
      qcheck.byte_aligned_bit_array(),
      qcheck.byte_aligned_bit_array(),
    ),
    fn(input) {
      let #(a, b) = input
      assert crypto.constant_time_equal(a, b)
        == crypto.constant_time_equal(b, a)
    },
  )
}

// Edge case: length mismatch always returns false
pub fn constant_time_equal_length_mismatch_test() {
  assert !crypto.constant_time_equal(<<"short":utf8>>, <<"longer":utf8>>)
  assert !crypto.constant_time_equal(<<>>, <<"nonempty":utf8>>)
}

// Property: UUIDs are always unique
pub fn uuid_uniqueness_property_test() {
  qcheck.run(qcheck.default_config(), qcheck.bounded_int(10, 100), fn(count) {
    let uuids = list.map(list.range(1, count), fn(_) { crypto.random_uuid() })
    let unique = set.from_list(uuids)
    assert set.size(unique) == count
  })
}

// Property: UUID format is always valid (version 4, correct structure)
pub fn uuid_format_property_test() {
  // Run 100 times to test format consistency
  list.each(list.range(1, 100), fn(_) {
    let uuid = crypto.random_uuid()

    // Length check
    assert string.length(uuid) == 36

    // Structure check (8-4-4-4-12)
    let parts = string.split(uuid, "-")
    assert list.length(parts) == 5

    let assert [p1, p2, p3, p4, p5] = parts
    assert string.length(p1) == 8
    assert string.length(p2) == 4
    assert string.length(p3) == 4
    assert string.length(p4) == 4
    assert string.length(p5) == 12

    // Version check (must be "4")
    let assert Ok(version_char) = string.first(string.drop_start(uuid, 14))
    assert version_char == "4"

    // Variant check (must be 8, 9, a, or b)
    let assert Ok(variant_char) = string.first(string.drop_start(uuid, 19))
    assert variant_char == "8"
      || variant_char == "9"
      || variant_char == "a"
      || variant_char == "b"
  })
}
