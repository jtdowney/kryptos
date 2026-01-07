import birdie
import gleam/bit_array
import kryptos/xdh.{X25519, X448}

// Test key: 32 bytes of deterministic data for X25519
const test_x25519_private_bytes = <<
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
  0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
  0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
>>

// Test key: 56 bytes of deterministic data for X448
const test_x448_private_bytes = <<
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
  0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
  0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
  0x35, 0x36, 0x37, 0x38,
>>

pub fn x25519_shared_secret_test() {
  let #(alice_private, alice_public) = xdh.generate_key_pair(X25519)
  let #(bob_private, bob_public) = xdh.generate_key_pair(X25519)

  let assert Ok(alice_shared) =
    xdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(bob_shared) =
    xdh.compute_shared_secret(bob_private, alice_public)

  assert alice_shared == bob_shared
}

pub fn x448_shared_secret_test() {
  let #(alice_private, alice_public) = xdh.generate_key_pair(X448)
  let #(bob_private, bob_public) = xdh.generate_key_pair(X448)

  let assert Ok(alice_shared) =
    xdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(bob_shared) =
    xdh.compute_shared_secret(bob_private, alice_public)

  assert alice_shared == bob_shared
}

pub fn x25519_deterministic_shared_secret_test() {
  let #(alice_private, _) = xdh.generate_key_pair(X25519)
  let #(_, bob_public) = xdh.generate_key_pair(X25519)

  let assert Ok(shared1) = xdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(shared2) = xdh.compute_shared_secret(alice_private, bob_public)

  assert shared1 == shared2
}

pub fn x448_deterministic_shared_secret_test() {
  let #(alice_private, _) = xdh.generate_key_pair(X448)
  let #(_, bob_public) = xdh.generate_key_pair(X448)

  let assert Ok(shared1) = xdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(shared2) = xdh.compute_shared_secret(alice_private, bob_public)

  assert shared1 == shared2
}

pub fn x25519_different_keys_different_secrets_test() {
  let #(alice_private, _) = xdh.generate_key_pair(X25519)
  let #(_, bob_public) = xdh.generate_key_pair(X25519)
  let #(_, charlie_public) = xdh.generate_key_pair(X25519)

  let assert Ok(with_bob) = xdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(with_charlie) =
    xdh.compute_shared_secret(alice_private, charlie_public)

  assert with_bob != with_charlie
}

pub fn x448_different_keys_different_secrets_test() {
  let #(alice_private, _) = xdh.generate_key_pair(X448)
  let #(_, bob_public) = xdh.generate_key_pair(X448)
  let #(_, charlie_public) = xdh.generate_key_pair(X448)

  let assert Ok(with_bob) = xdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(with_charlie) =
    xdh.compute_shared_secret(alice_private, charlie_public)

  assert with_bob != with_charlie
}

pub fn curve_mismatch_x25519_x448_test() {
  let #(alice_private, _) = xdh.generate_key_pair(X25519)
  let #(_, bob_public) = xdh.generate_key_pair(X448)

  assert xdh.compute_shared_secret(alice_private, bob_public) == Error(Nil)
}

pub fn curve_mismatch_x448_x25519_test() {
  let #(alice_private, _) = xdh.generate_key_pair(X448)
  let #(_, bob_public) = xdh.generate_key_pair(X25519)

  assert xdh.compute_shared_secret(alice_private, bob_public) == Error(Nil)
}

pub fn x25519_shared_secret_size_test() {
  let #(alice_private, _) = xdh.generate_key_pair(X25519)
  let #(_, bob_public) = xdh.generate_key_pair(X25519)

  let assert Ok(shared) = xdh.compute_shared_secret(alice_private, bob_public)

  assert bit_array.byte_size(shared) == 32
}

pub fn x448_shared_secret_size_test() {
  let #(alice_private, _) = xdh.generate_key_pair(X448)
  let #(_, bob_public) = xdh.generate_key_pair(X448)

  let assert Ok(shared) = xdh.compute_shared_secret(alice_private, bob_public)

  assert bit_array.byte_size(shared) == 56
}

pub fn x25519_invalid_public_key_length_test() {
  let short_key = <<0:size(31)-unit(8)>>
  assert xdh.public_key_from_bytes(X25519, short_key) == Error(Nil)

  let long_key = <<0:size(33)-unit(8)>>
  assert xdh.public_key_from_bytes(X25519, long_key) == Error(Nil)
}

pub fn x448_invalid_public_key_length_test() {
  let short_key = <<0:size(55)-unit(8)>>
  assert xdh.public_key_from_bytes(X448, short_key) == Error(Nil)

  let long_key = <<0:size(57)-unit(8)>>
  assert xdh.public_key_from_bytes(X448, long_key) == Error(Nil)
}

pub fn x25519_invalid_private_key_length_test() {
  let short_key = <<0:size(31)-unit(8)>>
  assert xdh.from_bytes(X25519, short_key) == Error(Nil)

  let long_key = <<0:size(33)-unit(8)>>
  assert xdh.from_bytes(X25519, long_key) == Error(Nil)
}

pub fn x448_invalid_private_key_length_test() {
  let short_key = <<0:size(55)-unit(8)>>
  assert xdh.from_bytes(X448, short_key) == Error(Nil)

  let long_key = <<0:size(57)-unit(8)>>
  assert xdh.from_bytes(X448, long_key) == Error(Nil)
}

// PEM/DER export tests with birdie snapshots

pub fn x25519_export_private_key_pem_test() {
  let assert Ok(#(private_key, _public_key)) =
    xdh.from_bytes(X25519, test_x25519_private_bytes)
  let assert Ok(pem) = xdh.to_pem(private_key)

  birdie.snap(pem, title: "xdh x25519 private key pem")
}

pub fn x448_export_private_key_pem_test() {
  let assert Ok(#(private_key, _public_key)) =
    xdh.from_bytes(X448, test_x448_private_bytes)
  let assert Ok(pem) = xdh.to_pem(private_key)

  birdie.snap(pem, title: "xdh x448 private key pem")
}

pub fn x25519_export_public_key_pem_test() {
  let assert Ok(#(_private_key, public_key)) =
    xdh.from_bytes(X25519, test_x25519_private_bytes)
  let assert Ok(pem) = xdh.public_key_to_pem(public_key)

  birdie.snap(pem, title: "xdh x25519 public key pem")
}

pub fn x448_export_public_key_pem_test() {
  let assert Ok(#(_private_key, public_key)) =
    xdh.from_bytes(X448, test_x448_private_bytes)
  let assert Ok(pem) = xdh.public_key_to_pem(public_key)

  birdie.snap(pem, title: "xdh x448 public key pem")
}

pub fn x25519_export_private_key_der_test() {
  let assert Ok(#(private_key, _public_key)) =
    xdh.from_bytes(X25519, test_x25519_private_bytes)
  let assert Ok(der) = xdh.to_der(private_key)

  birdie.snap(bit_array.base16_encode(der), title: "xdh x25519 private key der")
}

pub fn x448_export_private_key_der_test() {
  let assert Ok(#(private_key, _public_key)) =
    xdh.from_bytes(X448, test_x448_private_bytes)
  let assert Ok(der) = xdh.to_der(private_key)

  birdie.snap(bit_array.base16_encode(der), title: "xdh x448 private key der")
}

pub fn x25519_export_public_key_der_test() {
  let assert Ok(#(_private_key, public_key)) =
    xdh.from_bytes(X25519, test_x25519_private_bytes)
  let assert Ok(der) = xdh.public_key_to_der(public_key)

  birdie.snap(bit_array.base16_encode(der), title: "xdh x25519 public key der")
}

pub fn x448_export_public_key_der_test() {
  let assert Ok(#(_private_key, public_key)) =
    xdh.from_bytes(X448, test_x448_private_bytes)
  let assert Ok(der) = xdh.public_key_to_der(public_key)

  birdie.snap(bit_array.base16_encode(der), title: "xdh x448 public key der")
}

// Import roundtrip tests

pub fn x25519_import_private_key_pem_roundtrip_test() {
  let assert Ok(#(private_key, _original_public)) =
    xdh.from_bytes(X25519, test_x25519_private_bytes)
  let assert Ok(pem) = xdh.to_pem(private_key)
  let assert Ok(#(imported_private, imported_public)) = xdh.from_pem(pem)

  let #(other_private, other_public) = xdh.generate_key_pair(X25519)
  let assert Ok(shared1) =
    xdh.compute_shared_secret(imported_private, other_public)
  let assert Ok(shared2) =
    xdh.compute_shared_secret(other_private, imported_public)
  assert shared1 == shared2
}

pub fn x448_import_private_key_pem_roundtrip_test() {
  let assert Ok(#(private_key, _original_public)) =
    xdh.from_bytes(X448, test_x448_private_bytes)
  let assert Ok(pem) = xdh.to_pem(private_key)
  let assert Ok(#(imported_private, imported_public)) = xdh.from_pem(pem)

  let #(other_private, other_public) = xdh.generate_key_pair(X448)
  let assert Ok(shared1) =
    xdh.compute_shared_secret(imported_private, other_public)
  let assert Ok(shared2) =
    xdh.compute_shared_secret(other_private, imported_public)
  assert shared1 == shared2
}

pub fn x25519_import_public_key_pem_roundtrip_test() {
  let assert Ok(#(_private_key, public_key)) =
    xdh.from_bytes(X25519, test_x25519_private_bytes)
  let assert Ok(pem) = xdh.public_key_to_pem(public_key)
  let assert Ok(_imported_public) = xdh.public_key_from_pem(pem)
}

pub fn public_key_from_private_key_test() {
  let assert Ok(#(private_key, public_key)) =
    xdh.from_bytes(X25519, test_x25519_private_bytes)
  let derived_public = xdh.public_key_from_private_key(private_key)

  let #(other_private, _other_public) = xdh.generate_key_pair(X25519)
  let assert Ok(shared1) = xdh.compute_shared_secret(other_private, public_key)
  let assert Ok(shared2) =
    xdh.compute_shared_secret(other_private, derived_public)
  assert shared1 == shared2
}
