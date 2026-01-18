import gleam/bit_array
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

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(20),
    gen,
    fn(input) {
      let #(#(curve, hash_alg), message) = input
      let #(private_key, public_key) = ec.generate_key_pair(curve)
      let signature = ecdsa.sign(private_key, message, hash_alg)
      assert ecdsa.verify(public_key, message, signature, hash_alg)
    },
  )
}

// Property: wrong public key fails verification
pub fn ecdsa_wrong_public_key_fails_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(20),
    gen,
    fn(message) {
      let #(private_key, _) = ec.generate_key_pair(P256)
      let #(_, other_public_key) = ec.generate_key_pair(P256)
      let signature = ecdsa.sign(private_key, message, Sha256)
      assert !ecdsa.verify(other_public_key, message, signature, Sha256)
    },
  )
}

// Property: tampered message fails verification
pub fn ecdsa_tampered_message_fails_property_test() {
  let gen = qcheck.non_empty_byte_aligned_bit_array()

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(20),
    gen,
    fn(message) {
      let #(private_key, public_key) = ec.generate_key_pair(P256)
      let signature = ecdsa.sign(private_key, message, Sha256)

      // Flip first bit
      let assert <<first_byte:8, rest:bits>> = message
      let tampered = <<
        { int.bitwise_exclusive_or(first_byte, 1) }:8,
        rest:bits,
      >>

      assert !ecdsa.verify(public_key, tampered, signature, Sha256)
    },
  )
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

// Property: sign_rs then verify_rs returns true for all curve/hash combinations
pub fn ecdsa_sign_rs_verify_rs_roundtrip_property_test() {
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

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(20),
    gen,
    fn(input) {
      let #(#(curve, hash_alg), message) = input
      let #(private_key, public_key) = ec.generate_key_pair(curve)
      let signature = ecdsa.sign_rs(private_key, message, hash_alg)

      let expected_len = ec.coordinate_size(curve) * 2
      assert bit_array.byte_size(signature) == expected_len
      assert ecdsa.verify_rs(public_key, message, signature, hash_alg)
    },
  )
}

// Property: DER -> R||S -> DER roundtrip produces verifiable signature
pub fn ecdsa_der_rs_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(#(P256, Sha256)), [
        qcheck.return(#(P384, Sha384)),
        qcheck.return(#(P521, Sha512)),
        qcheck.return(#(Secp256k1, Sha256)),
      ]),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(20),
    gen,
    fn(input) {
      let #(#(curve, hash_alg), message) = input
      let #(private_key, public_key) = ec.generate_key_pair(curve)
      let der_sig = ecdsa.sign(private_key, message, hash_alg)

      let assert Ok(rs_sig) = ecdsa.der_to_rs(der_sig, curve)
      let assert Ok(der_sig2) = ecdsa.rs_to_der(rs_sig, curve)

      assert ecdsa.verify(public_key, message, der_sig, hash_alg)
      assert ecdsa.verify(public_key, message, der_sig2, hash_alg)
    },
  )
}

// Property: R||S -> DER -> R||S roundtrip preserves signature
pub fn ecdsa_rs_der_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(#(P256, Sha256)), [
        qcheck.return(#(P384, Sha384)),
        qcheck.return(#(P521, Sha512)),
        qcheck.return(#(Secp256k1, Sha256)),
      ]),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(20),
    gen,
    fn(input) {
      let #(#(curve, hash_alg), message) = input
      let #(private_key, _public_key) = ec.generate_key_pair(curve)
      let rs_sig = ecdsa.sign_rs(private_key, message, hash_alg)

      let assert Ok(der_sig) = ecdsa.rs_to_der(rs_sig, curve)
      let assert Ok(rs_sig2) = ecdsa.der_to_rs(der_sig, curve)

      assert rs_sig == rs_sig2
    },
  )
}

pub fn ecdsa_sign_der_verify_rs_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P256)
  let message = <<"cross-format test":utf8>>

  let der_sig = ecdsa.sign(private_key, message, Sha256)
  let assert Ok(rs_sig) = ecdsa.der_to_rs(der_sig, P256)

  assert ecdsa.verify_rs(public_key, message, rs_sig, Sha256)
}

pub fn ecdsa_sign_rs_verify_der_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P256)
  let message = <<"cross-format test":utf8>>

  let rs_sig = ecdsa.sign_rs(private_key, message, Sha256)
  let assert Ok(der_sig) = ecdsa.rs_to_der(rs_sig, P256)

  assert ecdsa.verify(public_key, message, der_sig, Sha256)
}

pub fn ecdsa_p521_rs_format_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P521)
  let message = <<"P-521 test":utf8>>

  let rs_sig = ecdsa.sign_rs(private_key, message, Sha512)

  assert bit_array.byte_size(rs_sig) == 132
  assert ecdsa.verify_rs(public_key, message, rs_sig, Sha512)
}

pub fn ecdsa_rs_to_der_invalid_length_test() {
  let invalid_rs = <<0:504>>
  assert ecdsa.rs_to_der(invalid_rs, P256) == Error(Nil)
  let invalid_rs2 = <<0:520>>
  assert ecdsa.rs_to_der(invalid_rs2, P256) == Error(Nil)
}

pub fn ecdsa_verify_rs_invalid_length_test() {
  let #(_private_key, public_key) = ec.generate_key_pair(P256)
  let message = <<"test":utf8>>

  let invalid_sig = <<0:504>>
  assert !ecdsa.verify_rs(public_key, message, invalid_sig, Sha256)
}

pub fn ecdsa_der_to_rs_malformed_test() {
  let malformed1 = <<0x02, 0x01, 0x01, 0x02, 0x01, 0x01>>
  assert ecdsa.der_to_rs(malformed1, P256) == Error(Nil)

  assert ecdsa.der_to_rs(<<>>, P256) == Error(Nil)

  let truncated = <<0x30, 0x10>>
  assert ecdsa.der_to_rs(truncated, P256) == Error(Nil)
}

// Tests for canonical DER parsing enforcement

pub fn ecdsa_der_rejects_trailing_garbage_after_sequence_test() {
  let sig_with_garbage = <<
    0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0xDE, 0xAD,
  >>
  assert ecdsa.der_to_rs(sig_with_garbage, P256) == Error(Nil)
}

pub fn ecdsa_der_rejects_trailing_garbage_after_integers_test() {
  let sig_with_inner_garbage = <<
    0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0xDE, 0xAD,
  >>
  assert ecdsa.der_to_rs(sig_with_inner_garbage, P256) == Error(Nil)
}

pub fn ecdsa_der_rejects_non_canonical_length_81_test() {
  let non_canonical = <<0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01>>
  assert ecdsa.der_to_rs(non_canonical, P256) == Error(Nil)
}

pub fn ecdsa_der_rejects_non_canonical_integer_length_test() {
  let non_canonical_int_len = <<
    0x30, 0x08, 0x02, 0x81, 0x01, 0x01, 0x02, 0x01, 0x01,
  >>
  assert ecdsa.der_to_rs(non_canonical_int_len, P256) == Error(Nil)
}

pub fn ecdsa_der_rejects_non_minimal_integer_leading_zeros_test() {
  let non_minimal = <<
    0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x01,
  >>
  assert ecdsa.der_to_rs(non_minimal, P256) == Error(Nil)
}

pub fn ecdsa_der_rejects_zero_length_integer_test() {
  let zero_len_int = <<0x30, 0x04, 0x02, 0x00, 0x02, 0x01, 0x01>>
  assert ecdsa.der_to_rs(zero_len_int, P256) == Error(Nil)
}

pub fn ecdsa_der_accepts_valid_leading_zero_for_high_bit_test() {
  let valid_leading_zero = <<
    0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0x80,
  >>
  let result = ecdsa.der_to_rs(valid_leading_zero, P256)
  assert result != Error(Nil)
}
