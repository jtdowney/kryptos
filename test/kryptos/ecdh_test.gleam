import gleam/bit_array
import kryptos/ec.{P256, P384, P521, Secp256k1}
import kryptos/ecdh
import qcheck

// Property: ECDH is commutative - Alice with Bob's public == Bob with Alice's public
pub fn ecdh_commutativity_property_test() {
  let gen =
    qcheck.from_generators(qcheck.return(P256), [
      qcheck.return(P384),
      qcheck.return(P521),
      qcheck.return(Secp256k1),
    ])

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    gen,
    fn(curve) {
      let #(alice_private, alice_public) = ec.generate_key_pair(curve)
      let #(bob_private, bob_public) = ec.generate_key_pair(curve)

      let assert Ok(alice_shared) =
        ecdh.compute_shared_secret(alice_private, bob_public)
      let assert Ok(bob_shared) =
        ecdh.compute_shared_secret(bob_private, alice_public)

      assert alice_shared == bob_shared
    },
  )
}

// Property: shared secret size matches expected curve output size
pub fn ecdh_shared_secret_size_property_test() {
  let gen =
    qcheck.from_generators(qcheck.return(#(P256, 32)), [
      qcheck.return(#(P384, 48)),
      qcheck.return(#(P521, 66)),
      qcheck.return(#(Secp256k1, 32)),
    ])

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    gen,
    fn(input) {
      let #(curve, expected_size) = input
      let #(alice_private, _) = ec.generate_key_pair(curve)
      let #(_, bob_public) = ec.generate_key_pair(curve)

      let assert Ok(shared) =
        ecdh.compute_shared_secret(alice_private, bob_public)

      assert bit_array.byte_size(shared) == expected_size
    },
  )
}

// Property: same inputs always produce same shared secret
pub fn ecdh_deterministic_property_test() {
  let gen =
    qcheck.from_generators(qcheck.return(P256), [
      qcheck.return(P384),
    ])

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    gen,
    fn(curve) {
      let #(alice_private, _) = ec.generate_key_pair(curve)
      let #(_, bob_public) = ec.generate_key_pair(curve)

      let assert Ok(shared1) =
        ecdh.compute_shared_secret(alice_private, bob_public)
      let assert Ok(shared2) =
        ecdh.compute_shared_secret(alice_private, bob_public)

      assert shared1 == shared2
    },
  )
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
