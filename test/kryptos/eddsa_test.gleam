import birdie
import gleam/bit_array
import gleam/int
import kryptos/eddsa.{Ed25519, Ed448}
import qcheck
import simplifile

fn load_ed25519_key() -> String {
  let assert Ok(pem) = simplifile.read("test/fixtures/ed25519_pkcs8.pem")
  pem
}

fn load_ed448_key() -> String {
  let assert Ok(pem) = simplifile.read("test/fixtures/ed448_pkcs8.pem")
  pem
}

// Property: sign then verify returns true for all curves
pub fn eddsa_sign_verify_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(Ed25519), [qcheck.return(Ed448)]),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(curve, message) = input
    let #(private_key, public_key) = eddsa.generate_key_pair(curve)
    let signature = eddsa.sign(private_key, message)
    assert eddsa.verify(public_key, message, signature)
  })
}

// Property: EdDSA signatures are deterministic
pub fn eddsa_deterministic_signature_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(Ed25519), [qcheck.return(Ed448)]),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(curve, message) = input
    let #(private_key, _) = eddsa.generate_key_pair(curve)
    let signature1 = eddsa.sign(private_key, message)
    let signature2 = eddsa.sign(private_key, message)
    assert signature1 == signature2
  })
}

// Property: wrong public key fails verification
pub fn eddsa_wrong_public_key_fails_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(Ed25519), [qcheck.return(Ed448)]),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(curve, message) = input
    let #(private_key, _) = eddsa.generate_key_pair(curve)
    let #(_, other_public_key) = eddsa.generate_key_pair(curve)
    let signature = eddsa.sign(private_key, message)
    assert !eddsa.verify(other_public_key, message, signature)
  })
}

// Property: tampered message fails verification
pub fn eddsa_tampered_message_fails_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(Ed25519), [qcheck.return(Ed448)]),
      qcheck.non_empty_byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(curve, message) = input
    let #(private_key, public_key) = eddsa.generate_key_pair(curve)
    let signature = eddsa.sign(private_key, message)

    // Flip first bit
    let assert <<first_byte:8, rest:bits>> = message
    let tampered = <<{ int.bitwise_exclusive_or(first_byte, 1) }:8, rest:bits>>

    assert !eddsa.verify(public_key, tampered, signature)
  })
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

pub fn ed25519_key_size_test() {
  assert eddsa.key_size(Ed25519) == 32
}

pub fn ed448_key_size_test() {
  assert eddsa.key_size(Ed448) == 57
}

// from_bytes import tests

pub fn ed25519_from_bytes_test() {
  let assert Ok(priv_bytes) =
    simplifile.read_bits("test/fixtures/ed25519_raw_priv.bin")
  let assert Ok(#(private, public)) = eddsa.from_bytes(Ed25519, priv_bytes)
  let message = <<"ed25519 from_bytes test":utf8>>
  let signature = eddsa.sign(private, message)
  assert eddsa.verify(public, message, signature)
}

pub fn ed25519_to_bytes_roundtrip_test() {
  let assert Ok(priv_bytes) =
    simplifile.read_bits("test/fixtures/ed25519_raw_priv.bin")
  let assert Ok(#(private, public)) = eddsa.from_bytes(Ed25519, priv_bytes)

  let exported_priv = eddsa.to_bytes(private)
  assert exported_priv == priv_bytes

  let assert Ok(pub_bytes) =
    simplifile.read_bits("test/fixtures/ed25519_raw_pub.bin")
  let exported_pub = eddsa.public_key_to_bytes(public)
  assert exported_pub == pub_bytes
}

pub fn ed25519_public_key_from_bytes_test() {
  let assert Ok(pub_bytes) =
    simplifile.read_bits("test/fixtures/ed25519_raw_pub.bin")
  let assert Ok(public) = eddsa.public_key_from_bytes(Ed25519, pub_bytes)
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/ed25519_pkcs8.pem")
  let assert Ok(#(private, _)) = eddsa.from_pem(priv_pem)
  let message = <<"ed25519 public_key_from_bytes test":utf8>>
  let signature = eddsa.sign(private, message)
  assert eddsa.verify(public, message, signature)
}

pub fn ed448_from_bytes_test() {
  let assert Ok(priv_bytes) =
    simplifile.read_bits("test/fixtures/ed448_raw_priv.bin")
  let assert Ok(#(private, public)) = eddsa.from_bytes(Ed448, priv_bytes)
  let message = <<"ed448 from_bytes test":utf8>>
  let signature = eddsa.sign(private, message)
  assert eddsa.verify(public, message, signature)
}

pub fn ed448_to_bytes_roundtrip_test() {
  let assert Ok(priv_bytes) =
    simplifile.read_bits("test/fixtures/ed448_raw_priv.bin")
  let assert Ok(#(private, public)) = eddsa.from_bytes(Ed448, priv_bytes)

  let exported_priv = eddsa.to_bytes(private)
  assert exported_priv == priv_bytes

  let assert Ok(pub_bytes) =
    simplifile.read_bits("test/fixtures/ed448_raw_pub.bin")
  let exported_pub = eddsa.public_key_to_bytes(public)
  assert exported_pub == pub_bytes
}

pub fn ed448_public_key_from_bytes_test() {
  let assert Ok(pub_bytes) =
    simplifile.read_bits("test/fixtures/ed448_raw_pub.bin")
  let assert Ok(public) = eddsa.public_key_from_bytes(Ed448, pub_bytes)
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/ed448_pkcs8.pem")
  let assert Ok(#(private, _)) = eddsa.from_pem(priv_pem)
  let message = <<"ed448 public_key_from_bytes test":utf8>>
  let signature = eddsa.sign(private, message)
  assert eddsa.verify(public, message, signature)
}

pub fn ed25519_export_private_key_pem_test() {
  let assert Ok(#(private_key, _public_key)) =
    eddsa.from_pem(load_ed25519_key())
  let assert Ok(pem) = eddsa.to_pem(private_key)

  birdie.snap(pem, title: "eddsa ed25519 private key pem")
}

pub fn ed448_export_private_key_pem_test() {
  let assert Ok(#(private_key, _public_key)) = eddsa.from_pem(load_ed448_key())
  let assert Ok(pem) = eddsa.to_pem(private_key)

  birdie.snap(pem, title: "eddsa ed448 private key pem")
}

pub fn ed25519_export_public_key_pem_test() {
  let assert Ok(#(_private_key, public_key)) =
    eddsa.from_pem(load_ed25519_key())
  let assert Ok(pem) = eddsa.public_key_to_pem(public_key)

  birdie.snap(pem, title: "eddsa ed25519 public key pem")
}

pub fn ed448_export_public_key_pem_test() {
  let assert Ok(#(_private_key, public_key)) = eddsa.from_pem(load_ed448_key())
  let assert Ok(pem) = eddsa.public_key_to_pem(public_key)

  birdie.snap(pem, title: "eddsa ed448 public key pem")
}

pub fn ed25519_export_private_key_der_test() {
  let assert Ok(#(private_key, _public_key)) =
    eddsa.from_pem(load_ed25519_key())
  let assert Ok(der) = eddsa.to_der(private_key)

  birdie.snap(
    bit_array.base16_encode(der),
    title: "eddsa ed25519 private key der",
  )
}

pub fn ed448_export_private_key_der_test() {
  let assert Ok(#(private_key, _public_key)) = eddsa.from_pem(load_ed448_key())
  let assert Ok(der) = eddsa.to_der(private_key)

  birdie.snap(
    bit_array.base16_encode(der),
    title: "eddsa ed448 private key der",
  )
}

pub fn ed25519_export_public_key_der_test() {
  let assert Ok(#(_private_key, public_key)) =
    eddsa.from_pem(load_ed25519_key())
  let assert Ok(der) = eddsa.public_key_to_der(public_key)

  birdie.snap(
    bit_array.base16_encode(der),
    title: "eddsa ed25519 public key der",
  )
}

pub fn ed448_export_public_key_der_test() {
  let assert Ok(#(_private_key, public_key)) = eddsa.from_pem(load_ed448_key())
  let assert Ok(der) = eddsa.public_key_to_der(public_key)

  birdie.snap(bit_array.base16_encode(der), title: "eddsa ed448 public key der")
}

pub fn ed25519_import_private_key_pem_roundtrip_test() {
  let assert Ok(#(private_key, original_public)) =
    eddsa.from_pem(load_ed25519_key())
  let assert Ok(pem) = eddsa.to_pem(private_key)
  let assert Ok(#(imported_private, _imported_public)) = eddsa.from_pem(pem)

  let message = <<"ed25519 roundtrip test":utf8>>
  let signature = eddsa.sign(imported_private, message)
  let valid = eddsa.verify(original_public, message, signature)
  assert valid
}

pub fn ed448_import_private_key_pem_roundtrip_test() {
  let assert Ok(#(private_key, original_public)) =
    eddsa.from_pem(load_ed448_key())
  let assert Ok(pem) = eddsa.to_pem(private_key)
  let assert Ok(#(imported_private, _imported_public)) = eddsa.from_pem(pem)

  let message = <<"ed448 roundtrip test":utf8>>
  let signature = eddsa.sign(imported_private, message)
  let valid = eddsa.verify(original_public, message, signature)
  assert valid
}

pub fn ed25519_import_public_key_pem_roundtrip_test() {
  let assert Ok(#(_private_key, public_key)) =
    eddsa.from_pem(load_ed25519_key())
  let assert Ok(pem) = eddsa.public_key_to_pem(public_key)
  let assert Ok(_imported_public) = eddsa.public_key_from_pem(pem)
}

pub fn public_key_from_private_key_test() {
  let assert Ok(#(private_key, public_key)) = eddsa.from_pem(load_ed25519_key())
  let derived_public = eddsa.public_key_from_private_key(private_key)

  let message = <<"derived public key test":utf8>>
  let signature = eddsa.sign(private_key, message)
  let valid1 = eddsa.verify(public_key, message, signature)
  let valid2 = eddsa.verify(derived_public, message, signature)
  assert valid1
  assert valid2
}

pub fn import_ed25519_pkcs8_der_test() {
  let assert Ok(der) = simplifile.read_bits("test/fixtures/ed25519_pkcs8.der")
  let assert Ok(#(private, public)) = eddsa.from_der(der)
  let signature = eddsa.sign(private, <<"too many secrets":utf8>>)
  assert eddsa.verify(public, <<"too many secrets":utf8>>, signature)
}

pub fn import_ed25519_spki_pub_pem_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/ed25519_pkcs8.pem")
  let assert Ok(#(private, _)) = eddsa.from_pem(priv_pem)
  let assert Ok(pub_pem) = simplifile.read("test/fixtures/ed25519_spki_pub.pem")
  let assert Ok(public) = eddsa.public_key_from_pem(pub_pem)
  let signature = eddsa.sign(private, <<"too many secrets":utf8>>)
  assert eddsa.verify(public, <<"too many secrets":utf8>>, signature)
}

pub fn import_ed25519_spki_pub_der_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/ed25519_pkcs8.pem")
  let assert Ok(#(private, _)) = eddsa.from_pem(priv_pem)
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/ed25519_spki_pub.der")
  let assert Ok(public) = eddsa.public_key_from_der(pub_der)
  let signature = eddsa.sign(private, <<"too many secrets":utf8>>)
  assert eddsa.verify(public, <<"too many secrets":utf8>>, signature)
}

pub fn import_ed448_pkcs8_der_test() {
  let assert Ok(der) = simplifile.read_bits("test/fixtures/ed448_pkcs8.der")
  let assert Ok(#(private, public)) = eddsa.from_der(der)
  let signature = eddsa.sign(private, <<"too many secrets":utf8>>)
  assert eddsa.verify(public, <<"too many secrets":utf8>>, signature)
}

pub fn import_ed448_spki_pub_pem_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/ed448_pkcs8.pem")
  let assert Ok(#(private, _)) = eddsa.from_pem(priv_pem)
  let assert Ok(pub_pem) = simplifile.read("test/fixtures/ed448_spki_pub.pem")
  let assert Ok(public) = eddsa.public_key_from_pem(pub_pem)
  let signature = eddsa.sign(private, <<"too many secrets":utf8>>)
  assert eddsa.verify(public, <<"too many secrets":utf8>>, signature)
}

pub fn import_ed448_spki_pub_der_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/ed448_pkcs8.pem")
  let assert Ok(#(private, _)) = eddsa.from_pem(priv_pem)
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/ed448_spki_pub.der")
  let assert Ok(public) = eddsa.public_key_from_der(pub_der)
  let signature = eddsa.sign(private, <<"too many secrets":utf8>>)
  assert eddsa.verify(public, <<"too many secrets":utf8>>, signature)
}

pub fn private_key_curve_ed25519_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/ed25519_pkcs8.pem")
  let assert Ok(#(private, _)) = eddsa.from_pem(pem)
  assert eddsa.curve(private) == eddsa.Ed25519
}

pub fn public_key_curve_ed25519_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/ed25519_spki_pub.pem")
  let assert Ok(public) = eddsa.public_key_from_pem(pem)
  assert eddsa.public_key_curve(public) == eddsa.Ed25519
}

pub fn private_key_curve_ed448_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/ed448_pkcs8.pem")
  let assert Ok(#(private, _)) = eddsa.from_pem(pem)
  assert eddsa.curve(private) == eddsa.Ed448
}

pub fn public_key_curve_ed448_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/ed448_spki_pub.pem")
  let assert Ok(public) = eddsa.public_key_from_pem(pem)
  assert eddsa.public_key_curve(public) == eddsa.Ed448
}
