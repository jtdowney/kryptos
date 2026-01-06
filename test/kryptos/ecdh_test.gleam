import gleam/bit_array
import kryptos/ec.{P256, P384, P521, Secp256k1}
import kryptos/ecdh

pub fn p256_shared_secret_test() {
  let #(alice_private, alice_public) = ec.generate_key_pair(P256)
  let #(bob_private, bob_public) = ec.generate_key_pair(P256)

  let assert Ok(alice_shared) =
    ecdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(bob_shared) =
    ecdh.compute_shared_secret(bob_private, alice_public)

  assert alice_shared == bob_shared
}

pub fn p384_shared_secret_test() {
  let #(alice_private, alice_public) = ec.generate_key_pair(P384)
  let #(bob_private, bob_public) = ec.generate_key_pair(P384)

  let assert Ok(alice_shared) =
    ecdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(bob_shared) =
    ecdh.compute_shared_secret(bob_private, alice_public)

  assert alice_shared == bob_shared
}

pub fn p521_shared_secret_test() {
  let #(alice_private, alice_public) = ec.generate_key_pair(P521)
  let #(bob_private, bob_public) = ec.generate_key_pair(P521)

  let assert Ok(alice_shared) =
    ecdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(bob_shared) =
    ecdh.compute_shared_secret(bob_private, alice_public)

  assert alice_shared == bob_shared
}

pub fn secp256k1_shared_secret_test() {
  let #(alice_private, alice_public) = ec.generate_key_pair(Secp256k1)
  let #(bob_private, bob_public) = ec.generate_key_pair(Secp256k1)

  let assert Ok(alice_shared) =
    ecdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(bob_shared) =
    ecdh.compute_shared_secret(bob_private, alice_public)

  assert alice_shared == bob_shared
}

pub fn deterministic_shared_secret_test() {
  let #(alice_private, _) = ec.generate_key_pair(P256)
  let #(_, bob_public) = ec.generate_key_pair(P256)

  let assert Ok(shared1) = ecdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(shared2) = ecdh.compute_shared_secret(alice_private, bob_public)

  assert shared1 == shared2
}

pub fn different_keys_different_secrets_test() {
  let #(alice_private, _) = ec.generate_key_pair(P256)
  let #(_, bob_public) = ec.generate_key_pair(P256)
  let #(_, charlie_public) = ec.generate_key_pair(P256)

  let assert Ok(with_bob) =
    ecdh.compute_shared_secret(alice_private, bob_public)
  let assert Ok(with_charlie) =
    ecdh.compute_shared_secret(alice_private, charlie_public)

  assert with_bob != with_charlie
}

pub fn curve_mismatch_p256_p384_test() {
  let #(alice_private, _) = ec.generate_key_pair(P256)
  let #(_, bob_public) = ec.generate_key_pair(P384)

  assert ecdh.compute_shared_secret(alice_private, bob_public) == Error(Nil)
}

pub fn curve_mismatch_p256_secp256k1_test() {
  let #(alice_private, _) = ec.generate_key_pair(P256)
  let #(_, bob_public) = ec.generate_key_pair(Secp256k1)

  assert ecdh.compute_shared_secret(alice_private, bob_public) == Error(Nil)
}

pub fn p256_shared_secret_size_test() {
  let #(alice_private, _) = ec.generate_key_pair(P256)
  let #(_, bob_public) = ec.generate_key_pair(P256)

  let assert Ok(shared) = ecdh.compute_shared_secret(alice_private, bob_public)

  assert bit_array.byte_size(shared) == 32
}

pub fn p384_shared_secret_size_test() {
  let #(alice_private, _) = ec.generate_key_pair(P384)
  let #(_, bob_public) = ec.generate_key_pair(P384)

  let assert Ok(shared) = ecdh.compute_shared_secret(alice_private, bob_public)

  assert bit_array.byte_size(shared) == 48
}

pub fn p521_shared_secret_size_test() {
  let #(alice_private, _) = ec.generate_key_pair(P521)
  let #(_, bob_public) = ec.generate_key_pair(P521)

  let assert Ok(shared) = ecdh.compute_shared_secret(alice_private, bob_public)

  assert bit_array.byte_size(shared) == 66
}

pub fn secp256k1_shared_secret_size_test() {
  let #(alice_private, _) = ec.generate_key_pair(Secp256k1)
  let #(_, bob_public) = ec.generate_key_pair(Secp256k1)

  let assert Ok(shared) = ecdh.compute_shared_secret(alice_private, bob_public)

  assert bit_array.byte_size(shared) == 32
}
