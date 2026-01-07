import birdie
import gleam/bit_array
import kryptos/ec
import kryptos/ecdsa
import kryptos/hash
import kryptos/internal/ec as internal_ec

// Test key: 32 bytes of deterministic data for P256
const test_p256_private_bytes = <<
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
  0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
  0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
>>

pub fn export_private_key_pem_test() {
  let assert Ok(#(private_key, _public_key)) =
    internal_ec.private_key_from_bytes(ec.P256, test_p256_private_bytes)
  let assert Ok(pem) = ec.to_pem(private_key)

  birdie.snap(pem, title: "ec p256 private key pem")
}

pub fn export_private_key_der_test() {
  let assert Ok(#(private_key, _public_key)) =
    internal_ec.private_key_from_bytes(ec.P256, test_p256_private_bytes)
  let assert Ok(der) = ec.to_der(private_key)

  birdie.snap(bit_array.base16_encode(der), title: "ec p256 private key der")
}

pub fn export_public_key_pem_test() {
  let assert Ok(#(_private_key, public_key)) =
    internal_ec.private_key_from_bytes(ec.P256, test_p256_private_bytes)
  let assert Ok(pem) = ec.public_key_to_pem(public_key)

  birdie.snap(pem, title: "ec p256 public key pem")
}

pub fn export_public_key_der_test() {
  let assert Ok(#(_private_key, public_key)) =
    internal_ec.private_key_from_bytes(ec.P256, test_p256_private_bytes)
  let assert Ok(der) = ec.public_key_to_der(public_key)

  birdie.snap(bit_array.base16_encode(der), title: "ec p256 public key der")
}

pub fn import_private_key_pem_roundtrip_test() {
  let assert Ok(#(private_key, original_public)) =
    internal_ec.private_key_from_bytes(ec.P256, test_p256_private_bytes)
  let assert Ok(pem) = ec.to_pem(private_key)
  let assert Ok(#(imported_private, _imported_public)) = ec.from_pem(pem)

  let message = <<"ec roundtrip test":utf8>>
  let signature = ecdsa.sign(imported_private, message, hash.Sha256)
  let valid = ecdsa.verify(original_public, message, signature, hash.Sha256)
  assert valid == True
}

pub fn import_public_key_pem_roundtrip_test() {
  let assert Ok(#(_private_key, public_key)) =
    internal_ec.private_key_from_bytes(ec.P256, test_p256_private_bytes)
  let assert Ok(pem) = ec.public_key_to_pem(public_key)
  let assert Ok(_imported_public) = ec.public_key_from_pem(pem)
}

pub fn import_private_key_der_roundtrip_test() {
  let assert Ok(#(private_key, original_public)) =
    internal_ec.private_key_from_bytes(ec.P256, test_p256_private_bytes)
  let assert Ok(der) = ec.to_der(private_key)
  let assert Ok(#(imported_private, _imported_public)) = ec.from_der(der)

  let message = <<"ec der roundtrip test":utf8>>
  let signature = ecdsa.sign(imported_private, message, hash.Sha256)
  let valid = ecdsa.verify(original_public, message, signature, hash.Sha256)
  assert valid == True
}

pub fn import_public_key_der_roundtrip_test() {
  let assert Ok(#(_private_key, public_key)) =
    internal_ec.private_key_from_bytes(ec.P256, test_p256_private_bytes)
  let assert Ok(der) = ec.public_key_to_der(public_key)
  let assert Ok(_imported_public) = ec.public_key_from_der(der)
}

pub fn public_key_from_private_key_test() {
  let assert Ok(#(private_key, public_key)) =
    internal_ec.private_key_from_bytes(ec.P256, test_p256_private_bytes)
  let derived_public = ec.public_key_from_private_key(private_key)

  let message = <<"derived public key test":utf8>>
  let signature = ecdsa.sign(private_key, message, hash.Sha256)
  let valid1 = ecdsa.verify(public_key, message, signature, hash.Sha256)
  let valid2 = ecdsa.verify(derived_public, message, signature, hash.Sha256)
  assert valid1 == True
  assert valid2 == True
}
