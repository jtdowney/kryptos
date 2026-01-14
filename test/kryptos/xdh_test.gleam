import birdie
import gleam/bit_array
import kryptos/xdh.{X25519, X448}
import simplifile

fn load_x25519_key() -> String {
  let assert Ok(pem) = simplifile.read("test/fixtures/x25519_pkcs8.pem")
  pem
}

fn load_x448_key() -> String {
  let assert Ok(pem) = simplifile.read("test/fixtures/x448_pkcs8.pem")
  pem
}

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

pub fn x25519_from_bytes_test() {
  let assert Ok(priv_bytes) =
    simplifile.read_bits("test/fixtures/x25519_raw_priv.bin")
  let assert Ok(#(private, public)) = xdh.from_bytes(X25519, priv_bytes)
  let #(other_private, other_public) = xdh.generate_key_pair(X25519)
  let assert Ok(shared1) = xdh.compute_shared_secret(private, other_public)
  let assert Ok(shared2) = xdh.compute_shared_secret(other_private, public)
  assert shared1 == shared2
}

pub fn x25519_to_bytes_roundtrip_test() {
  let assert Ok(priv_bytes) =
    simplifile.read_bits("test/fixtures/x25519_raw_priv.bin")
  let assert Ok(#(private, public)) = xdh.from_bytes(X25519, priv_bytes)

  let exported_priv = xdh.to_bytes(private)
  assert exported_priv == priv_bytes

  let assert Ok(pub_bytes) =
    simplifile.read_bits("test/fixtures/x25519_raw_pub.bin")
  let exported_pub = xdh.public_key_to_bytes(public)
  assert exported_pub == pub_bytes
}

pub fn x25519_public_key_from_bytes_test() {
  let assert Ok(pub_bytes) =
    simplifile.read_bits("test/fixtures/x25519_raw_pub.bin")
  let assert Ok(public) = xdh.public_key_from_bytes(X25519, pub_bytes)
  let #(other_private, _) = xdh.generate_key_pair(X25519)
  let assert Ok(_shared) = xdh.compute_shared_secret(other_private, public)
}

pub fn x448_from_bytes_test() {
  let assert Ok(priv_bytes) =
    simplifile.read_bits("test/fixtures/x448_raw_priv.bin")
  let assert Ok(#(private, public)) = xdh.from_bytes(X448, priv_bytes)
  let #(other_private, other_public) = xdh.generate_key_pair(X448)
  let assert Ok(shared1) = xdh.compute_shared_secret(private, other_public)
  let assert Ok(shared2) = xdh.compute_shared_secret(other_private, public)
  assert shared1 == shared2
}

pub fn x448_to_bytes_roundtrip_test() {
  let assert Ok(priv_bytes) =
    simplifile.read_bits("test/fixtures/x448_raw_priv.bin")
  let assert Ok(#(private, public)) = xdh.from_bytes(X448, priv_bytes)

  let exported_priv = xdh.to_bytes(private)
  assert exported_priv == priv_bytes

  let assert Ok(pub_bytes) =
    simplifile.read_bits("test/fixtures/x448_raw_pub.bin")
  let exported_pub = xdh.public_key_to_bytes(public)
  assert exported_pub == pub_bytes
}

pub fn x448_public_key_from_bytes_test() {
  let assert Ok(pub_bytes) =
    simplifile.read_bits("test/fixtures/x448_raw_pub.bin")
  let assert Ok(public) = xdh.public_key_from_bytes(X448, pub_bytes)
  let #(other_private, _) = xdh.generate_key_pair(X448)
  let assert Ok(_shared) = xdh.compute_shared_secret(other_private, public)
}

pub fn x25519_export_private_key_pem_test() {
  let assert Ok(#(private_key, _public_key)) = xdh.from_pem(load_x25519_key())
  let assert Ok(pem) = xdh.to_pem(private_key)

  birdie.snap(pem, title: "xdh x25519 private key pem")
}

pub fn x448_export_private_key_pem_test() {
  let assert Ok(#(private_key, _public_key)) = xdh.from_pem(load_x448_key())
  let assert Ok(pem) = xdh.to_pem(private_key)

  birdie.snap(pem, title: "xdh x448 private key pem")
}

pub fn x25519_export_public_key_pem_test() {
  let assert Ok(#(_private_key, public_key)) = xdh.from_pem(load_x25519_key())
  let assert Ok(pem) = xdh.public_key_to_pem(public_key)

  birdie.snap(pem, title: "xdh x25519 public key pem")
}

pub fn x448_export_public_key_pem_test() {
  let assert Ok(#(_private_key, public_key)) = xdh.from_pem(load_x448_key())
  let assert Ok(pem) = xdh.public_key_to_pem(public_key)

  birdie.snap(pem, title: "xdh x448 public key pem")
}

pub fn x25519_export_private_key_der_test() {
  let assert Ok(#(private_key, _public_key)) = xdh.from_pem(load_x25519_key())
  let assert Ok(der) = xdh.to_der(private_key)

  birdie.snap(bit_array.base16_encode(der), title: "xdh x25519 private key der")
}

pub fn x448_export_private_key_der_test() {
  let assert Ok(#(private_key, _public_key)) = xdh.from_pem(load_x448_key())
  let assert Ok(der) = xdh.to_der(private_key)

  birdie.snap(bit_array.base16_encode(der), title: "xdh x448 private key der")
}

pub fn x25519_export_public_key_der_test() {
  let assert Ok(#(_private_key, public_key)) = xdh.from_pem(load_x25519_key())
  let assert Ok(der) = xdh.public_key_to_der(public_key)

  birdie.snap(bit_array.base16_encode(der), title: "xdh x25519 public key der")
}

pub fn x448_export_public_key_der_test() {
  let assert Ok(#(_private_key, public_key)) = xdh.from_pem(load_x448_key())
  let assert Ok(der) = xdh.public_key_to_der(public_key)

  birdie.snap(bit_array.base16_encode(der), title: "xdh x448 public key der")
}

pub fn x25519_import_private_key_pem_roundtrip_test() {
  let assert Ok(#(private_key, _original_public)) =
    xdh.from_pem(load_x25519_key())
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
    xdh.from_pem(load_x448_key())
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
  let assert Ok(#(_private_key, public_key)) = xdh.from_pem(load_x25519_key())
  let assert Ok(pem) = xdh.public_key_to_pem(public_key)
  let assert Ok(_imported_public) = xdh.public_key_from_pem(pem)
}

pub fn public_key_from_private_key_test() {
  let assert Ok(#(private_key, public_key)) = xdh.from_pem(load_x25519_key())
  let derived_public = xdh.public_key_from_private_key(private_key)

  let #(other_private, _other_public) = xdh.generate_key_pair(X25519)
  let assert Ok(shared1) = xdh.compute_shared_secret(other_private, public_key)
  let assert Ok(shared2) =
    xdh.compute_shared_secret(other_private, derived_public)
  assert shared1 == shared2
}

pub fn import_x25519_pkcs8_der_test() {
  let assert Ok(der) = simplifile.read_bits("test/fixtures/x25519_pkcs8.der")
  let assert Ok(#(private, public)) = xdh.from_der(der)
  let #(other_private, other_public) = xdh.generate_key_pair(X25519)
  let assert Ok(shared1) = xdh.compute_shared_secret(private, other_public)
  let assert Ok(shared2) = xdh.compute_shared_secret(other_private, public)
  assert shared1 == shared2
}

pub fn import_x25519_spki_pub_pem_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/x25519_pkcs8.pem")
  let assert Ok(#(private, _)) = xdh.from_pem(priv_pem)
  let assert Ok(pub_pem) = simplifile.read("test/fixtures/x25519_spki_pub.pem")
  let assert Ok(public) = xdh.public_key_from_pem(pub_pem)
  let #(other_private, _) = xdh.generate_key_pair(X25519)
  let assert Ok(shared1) = xdh.compute_shared_secret(private, public)
  let assert Ok(shared2) = xdh.compute_shared_secret(other_private, public)
  assert shared1 != shared2
}

pub fn import_x25519_spki_pub_der_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/x25519_pkcs8.pem")
  let assert Ok(#(private, _)) = xdh.from_pem(priv_pem)
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/x25519_spki_pub.der")
  let assert Ok(public) = xdh.public_key_from_der(pub_der)
  let #(other_private, _) = xdh.generate_key_pair(X25519)
  let assert Ok(shared1) = xdh.compute_shared_secret(private, public)
  let assert Ok(shared2) = xdh.compute_shared_secret(other_private, public)
  assert shared1 != shared2
}

pub fn import_x448_pkcs8_der_test() {
  let assert Ok(der) = simplifile.read_bits("test/fixtures/x448_pkcs8.der")
  let assert Ok(#(private, public)) = xdh.from_der(der)
  let #(other_private, other_public) = xdh.generate_key_pair(X448)
  let assert Ok(shared1) = xdh.compute_shared_secret(private, other_public)
  let assert Ok(shared2) = xdh.compute_shared_secret(other_private, public)
  assert shared1 == shared2
}

pub fn import_x448_spki_pub_pem_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/x448_pkcs8.pem")
  let assert Ok(#(private, _)) = xdh.from_pem(priv_pem)
  let assert Ok(pub_pem) = simplifile.read("test/fixtures/x448_spki_pub.pem")
  let assert Ok(public) = xdh.public_key_from_pem(pub_pem)
  let #(other_private, _) = xdh.generate_key_pair(X448)
  let assert Ok(shared1) = xdh.compute_shared_secret(private, public)
  let assert Ok(shared2) = xdh.compute_shared_secret(other_private, public)
  assert shared1 != shared2
}

pub fn import_x448_spki_pub_der_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/x448_pkcs8.pem")
  let assert Ok(#(private, _)) = xdh.from_pem(priv_pem)
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/x448_spki_pub.der")
  let assert Ok(public) = xdh.public_key_from_der(pub_der)
  let #(other_private, _) = xdh.generate_key_pair(X448)
  let assert Ok(shared1) = xdh.compute_shared_secret(private, public)
  let assert Ok(shared2) = xdh.compute_shared_secret(other_private, public)
  assert shared1 != shared2
}

pub fn private_key_curve_x25519_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/x25519_pkcs8.pem")
  let assert Ok(#(private, _)) = xdh.from_pem(pem)
  assert xdh.curve(private) == xdh.X25519
}

pub fn public_key_curve_x25519_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/x25519_spki_pub.pem")
  let assert Ok(public) = xdh.public_key_from_pem(pem)
  assert xdh.public_key_curve(public) == xdh.X25519
}

pub fn private_key_curve_x448_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/x448_pkcs8.pem")
  let assert Ok(#(private, _)) = xdh.from_pem(pem)
  assert xdh.curve(private) == xdh.X448
}

pub fn public_key_curve_x448_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/x448_spki_pub.pem")
  let assert Ok(public) = xdh.public_key_from_pem(pem)
  assert xdh.public_key_curve(public) == xdh.X448
}
