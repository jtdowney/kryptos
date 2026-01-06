import gleam/bit_array
import kryptos/ec.{P256, P384, P521, Secp256k1}
import kryptos/ecdsa
import kryptos/hash.{Sha256, Sha384, Sha512}

pub fn p256_sign_verify_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P256)
  let message = <<"too many secrets":utf8>>
  let signature = ecdsa.sign(private_key, message, Sha256)
  assert ecdsa.verify(public_key, message, signature, Sha256)
}

pub fn p384_sign_verify_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P384)
  let message = <<"too many secrets":utf8>>
  let signature = ecdsa.sign(private_key, message, Sha384)
  assert ecdsa.verify(public_key, message, signature, Sha384)
}

pub fn p521_sign_verify_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P521)
  let message = <<"too many secrets":utf8>>
  let signature = ecdsa.sign(private_key, message, Sha512)
  assert ecdsa.verify(public_key, message, signature, Sha512)
}

pub fn secp256k1_sign_verify_test() {
  let #(private_key, public_key) = ec.generate_key_pair(Secp256k1)
  let message = <<"too many secrets":utf8>>
  let signature = ecdsa.sign(private_key, message, Sha256)
  assert ecdsa.verify(public_key, message, signature, Sha256)
}

pub fn p256_with_sha384_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P256)
  let message = <<"hash algorithm test":utf8>>
  let signature = ecdsa.sign(private_key, message, Sha384)
  assert ecdsa.verify(public_key, message, signature, Sha384)
}

pub fn p256_with_sha512_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P256)
  let message = <<"hash algorithm test":utf8>>
  let signature = ecdsa.sign(private_key, message, Sha512)
  assert ecdsa.verify(public_key, message, signature, Sha512)
}

pub fn verify_wrong_public_key_test() {
  let #(private_key, _public_key) = ec.generate_key_pair(P256)
  let #(_other_private_key, other_public_key) = ec.generate_key_pair(P256)
  let message = <<"message":utf8>>
  let signature = ecdsa.sign(private_key, message, Sha256)
  assert !ecdsa.verify(other_public_key, message, signature, Sha256)
}

pub fn verify_tampered_message_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P256)
  let message = <<"original message":utf8>>
  let tampered_message = <<"tampered message":utf8>>
  let signature = ecdsa.sign(private_key, message, Sha256)
  assert !ecdsa.verify(public_key, tampered_message, signature, Sha256)
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

pub fn sign_empty_message_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P256)
  let message = <<>>
  let signature = ecdsa.sign(private_key, message, Sha256)
  assert ecdsa.verify(public_key, message, signature, Sha256)
}

pub fn sign_large_message_test() {
  let #(private_key, public_key) = ec.generate_key_pair(P256)
  let assert Ok(large_data) =
    bit_array.base16_decode(
      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
      <> "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
      <> "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
      <> "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
      <> "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
      <> "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
      <> "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
      <> "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
    )
  let signature = ecdsa.sign(private_key, large_data, Sha256)
  assert ecdsa.verify(public_key, large_data, signature, Sha256)
}
