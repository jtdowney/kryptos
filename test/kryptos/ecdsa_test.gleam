import gleam/int
import kryptos/ec.{P256, P384, P521, Secp256k1}
import kryptos/ecdsa
import kryptos/hash.{Sha256, Sha384, Sha512}
import qcheck

// Property: sign then verify returns true for all curve/hash combinations
pub fn ecdsa_sign_verify_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(#(P256, Sha256)), [
        qcheck.return(#(P256, Sha384)),
        qcheck.return(#(P256, Sha512)),
        qcheck.return(#(P384, Sha384)),
        qcheck.return(#(P521, Sha512)),
        qcheck.return(#(Secp256k1, Sha256)),
      ]),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(#(curve, hash_alg), message) = input
    let #(private_key, public_key) = ec.generate_key_pair(curve)
    let signature = ecdsa.sign(private_key, message, hash_alg)
    assert ecdsa.verify(public_key, message, signature, hash_alg)
  })
}

// Property: wrong public key fails verification
pub fn ecdsa_wrong_public_key_fails_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(qcheck.default_config(), gen, fn(message) {
    let #(private_key, _) = ec.generate_key_pair(P256)
    let #(_, other_public_key) = ec.generate_key_pair(P256)
    let signature = ecdsa.sign(private_key, message, Sha256)
    assert !ecdsa.verify(other_public_key, message, signature, Sha256)
  })
}

// Property: tampered message fails verification
pub fn ecdsa_tampered_message_fails_property_test() {
  let gen = qcheck.non_empty_byte_aligned_bit_array()

  qcheck.run(qcheck.default_config(), gen, fn(message) {
    let #(private_key, public_key) = ec.generate_key_pair(P256)
    let signature = ecdsa.sign(private_key, message, Sha256)

    // Flip first bit
    let assert <<first_byte:8, rest:bits>> = message
    let tampered = <<
      { int.bitwise_exclusive_or(first_byte, 1) }:8,
      rest:bits,
    >>

    assert !ecdsa.verify(public_key, tampered, signature, Sha256)
  })
}

pub fn verify_tampered_signature_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P256)
  let message = <<"message":utf8>>
  let signature = ecdsa.sign(private_key, message, Sha256)

  let assert <<first_byte:8, rest:bits>> = signature
  let tampered_signature = <<{ first_byte + 1 }:8, rest:bits>>

  assert !ecdsa.verify(public_key, message, tampered_signature, Sha256)
}

pub fn verify_wrong_hash_algorithm_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P256)
  let message = <<"message":utf8>>
  let signature = ecdsa.sign(private_key, message, Sha256)
  assert !ecdsa.verify(public_key, message, signature, Sha384)
}
