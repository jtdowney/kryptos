import gleam/bit_array
import gleam/int
import kryptos/eddsa.{Ed25519, Ed448}

pub fn ed25519_sign_verify_test() {
  let #(private_key, public_key) = eddsa.generate_key_pair(Ed25519)
  let message = <<"too many secrets":utf8>>
  let signature = eddsa.sign(private_key, message)
  assert eddsa.verify(public_key, message, signature)
}

pub fn ed448_sign_verify_test() {
  let #(private_key, public_key) = eddsa.generate_key_pair(Ed448)
  let message = <<"too many secrets":utf8>>
  let signature = eddsa.sign(private_key, message)
  assert eddsa.verify(public_key, message, signature)
}

pub fn ed25519_deterministic_signature_test() {
  let #(private_key, _public_key) = eddsa.generate_key_pair(Ed25519)
  let message = <<"determinism test":utf8>>
  let signature1 = eddsa.sign(private_key, message)
  let signature2 = eddsa.sign(private_key, message)
  assert signature1 == signature2
}

pub fn ed448_deterministic_signature_test() {
  let #(private_key, _public_key) = eddsa.generate_key_pair(Ed448)
  let message = <<"determinism test":utf8>>
  let signature1 = eddsa.sign(private_key, message)
  let signature2 = eddsa.sign(private_key, message)
  assert signature1 == signature2
}

pub fn verify_wrong_public_key_test() {
  let #(private_key, _public_key) = eddsa.generate_key_pair(Ed25519)
  let #(_other_private_key, other_public_key) = eddsa.generate_key_pair(Ed25519)
  let message = <<"message":utf8>>
  let signature = eddsa.sign(private_key, message)
  assert !eddsa.verify(other_public_key, message, signature)
}

pub fn verify_tampered_message_test() {
  let #(private_key, public_key) = eddsa.generate_key_pair(Ed25519)
  let message = <<"original message":utf8>>
  let tampered_message = <<"tampered message":utf8>>
  let signature = eddsa.sign(private_key, message)
  assert !eddsa.verify(public_key, tampered_message, signature)
}

pub fn verify_tampered_signature_test() {
  let #(private_key, public_key) = eddsa.generate_key_pair(Ed25519)
  let message = <<"message":utf8>>
  let signature = eddsa.sign(private_key, message)

  let assert <<first_byte:8, rest:bits>> = signature
  let tampered_byte = int.bitwise_exclusive_or(first_byte, 1)
  let tampered_signature = <<tampered_byte:8, rest:bits>>

  assert !eddsa.verify(public_key, message, tampered_signature)
}

pub fn sign_empty_message_test() {
  let #(private_key, public_key) = eddsa.generate_key_pair(Ed25519)
  let message = <<>>
  let signature = eddsa.sign(private_key, message)
  assert eddsa.verify(public_key, message, signature)
}

pub fn sign_large_message_test() {
  let #(private_key, public_key) = eddsa.generate_key_pair(Ed25519)
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
  let signature = eddsa.sign(private_key, large_data)
  assert eddsa.verify(public_key, large_data, signature)
}

pub fn ed25519_key_size_test() {
  assert eddsa.key_size(Ed25519) == 32
}

pub fn ed448_key_size_test() {
  assert eddsa.key_size(Ed448) == 57
}
