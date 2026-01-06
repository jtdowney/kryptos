import gleam/bit_array
import kryptos/xdh.{X25519, X448}

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
  assert xdh.private_key_from_bytes(X25519, short_key) == Error(Nil)

  let long_key = <<0:size(33)-unit(8)>>
  assert xdh.private_key_from_bytes(X25519, long_key) == Error(Nil)
}

pub fn x448_invalid_private_key_length_test() {
  let short_key = <<0:size(55)-unit(8)>>
  assert xdh.private_key_from_bytes(X448, short_key) == Error(Nil)

  let long_key = <<0:size(57)-unit(8)>>
  assert xdh.private_key_from_bytes(X448, long_key) == Error(Nil)
}
