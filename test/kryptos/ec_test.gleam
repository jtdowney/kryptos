import birdie
import gleam/bit_array
import kryptos/ec
import kryptos/ecdh
import kryptos/ecdsa
import kryptos/hash
import simplifile

fn load_test_key() -> String {
  let assert Ok(pem) = simplifile.read("test/fixtures/p256_pkcs8.pem")
  pem
}

pub fn export_private_key_pem_test() {
  let assert Ok(#(private_key, _public_key)) = ec.from_pem(load_test_key())
  let assert Ok(pem) = ec.to_pem(private_key)

  birdie.snap(pem, title: "ec p256 private key pem")
}

pub fn export_private_key_der_test() {
  let assert Ok(#(private_key, _public_key)) = ec.from_pem(load_test_key())
  let assert Ok(der) = ec.to_der(private_key)

  birdie.snap(bit_array.base16_encode(der), title: "ec p256 private key der")
}

pub fn export_public_key_pem_test() {
  let assert Ok(#(_private_key, public_key)) = ec.from_pem(load_test_key())
  let assert Ok(pem) = ec.public_key_to_pem(public_key)

  birdie.snap(pem, title: "ec p256 public key pem")
}

pub fn export_public_key_der_test() {
  let assert Ok(#(_private_key, public_key)) = ec.from_pem(load_test_key())
  let assert Ok(der) = ec.public_key_to_der(public_key)

  birdie.snap(bit_array.base16_encode(der), title: "ec p256 public key der")
}

pub fn import_private_key_pem_roundtrip_test() {
  let assert Ok(#(private_key, original_public)) = ec.from_pem(load_test_key())
  let assert Ok(pem) = ec.to_pem(private_key)
  let assert Ok(#(imported_private, _imported_public)) = ec.from_pem(pem)

  let message = <<"ec roundtrip test":utf8>>
  let signature = ecdsa.sign(imported_private, message, hash.Sha256)
  let valid = ecdsa.verify(original_public, message, signature, hash.Sha256)
  assert valid
}

pub fn import_public_key_pem_roundtrip_test() {
  let assert Ok(#(_private_key, public_key)) = ec.from_pem(load_test_key())
  let assert Ok(pem) = ec.public_key_to_pem(public_key)
  let assert Ok(_imported_public) = ec.public_key_from_pem(pem)
}

pub fn import_private_key_der_roundtrip_test() {
  let assert Ok(#(private_key, original_public)) = ec.from_pem(load_test_key())
  let assert Ok(der) = ec.to_der(private_key)
  let assert Ok(#(imported_private, _imported_public)) = ec.from_der(der)

  let message = <<"ec der roundtrip test":utf8>>
  let signature = ecdsa.sign(imported_private, message, hash.Sha256)
  let valid = ecdsa.verify(original_public, message, signature, hash.Sha256)
  assert valid
}

pub fn import_public_key_der_roundtrip_test() {
  let assert Ok(#(_private_key, public_key)) = ec.from_pem(load_test_key())
  let assert Ok(der) = ec.public_key_to_der(public_key)
  let assert Ok(_imported_public) = ec.public_key_from_der(der)
}

pub fn public_key_from_private_key_test() {
  let assert Ok(#(private_key, public_key)) = ec.from_pem(load_test_key())
  let derived_public = ec.public_key_from_private_key(private_key)

  let message = <<"derived public key test":utf8>>
  let signature = ecdsa.sign(private_key, message, hash.Sha256)
  let valid1 = ecdsa.verify(public_key, message, signature, hash.Sha256)
  let valid2 = ecdsa.verify(derived_public, message, signature, hash.Sha256)
  assert valid1
  assert valid2
}

pub fn import_p256_pkcs8_der_test() {
  let assert Ok(der) = simplifile.read_bits("test/fixtures/p256_pkcs8.der")
  let assert Ok(#(private, public)) = ec.from_der(der)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
  )
}

pub fn import_p256_spki_pub_pem_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/p256_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(priv_pem)
  let assert Ok(pub_pem) = simplifile.read("test/fixtures/p256_spki_pub.pem")
  let assert Ok(public) = ec.public_key_from_pem(pub_pem)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
  )
}

pub fn import_p256_spki_pub_der_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/p256_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(priv_pem)
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/p256_spki_pub.der")
  let assert Ok(public) = ec.public_key_from_der(pub_der)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
  )
}

pub fn import_p384_pkcs8_pem_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p384_pkcs8.pem")
  let assert Ok(#(private, public)) = ec.from_pem(pem)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha384)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha384,
  )
}

pub fn import_p384_pkcs8_der_test() {
  let assert Ok(der) = simplifile.read_bits("test/fixtures/p384_pkcs8.der")
  let assert Ok(#(private, public)) = ec.from_der(der)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha384)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha384,
  )
}

pub fn import_p384_spki_pub_pem_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/p384_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(priv_pem)
  let assert Ok(pub_pem) = simplifile.read("test/fixtures/p384_spki_pub.pem")
  let assert Ok(public) = ec.public_key_from_pem(pub_pem)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha384)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha384,
  )
}

pub fn import_p384_spki_pub_der_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/p384_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(priv_pem)
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/p384_spki_pub.der")
  let assert Ok(public) = ec.public_key_from_der(pub_der)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha384)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha384,
  )
}

pub fn import_p521_pkcs8_pem_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p521_pkcs8.pem")
  let assert Ok(#(private, public)) = ec.from_pem(pem)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha512)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha512,
  )
}

pub fn import_p521_pkcs8_der_test() {
  let assert Ok(der) = simplifile.read_bits("test/fixtures/p521_pkcs8.der")
  let assert Ok(#(private, public)) = ec.from_der(der)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha512)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha512,
  )
}

pub fn import_p521_spki_pub_pem_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/p521_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(priv_pem)
  let assert Ok(pub_pem) = simplifile.read("test/fixtures/p521_spki_pub.pem")
  let assert Ok(public) = ec.public_key_from_pem(pub_pem)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha512)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha512,
  )
}

pub fn import_p521_spki_pub_der_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/p521_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(priv_pem)
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/p521_spki_pub.der")
  let assert Ok(public) = ec.public_key_from_der(pub_der)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha512)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha512,
  )
}

pub fn import_secp256k1_pkcs8_pem_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/secp256k1_pkcs8.pem")
  let assert Ok(#(private, public)) = ec.from_pem(pem)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
  )
}

pub fn import_secp256k1_pkcs8_der_test() {
  let assert Ok(der) = simplifile.read_bits("test/fixtures/secp256k1_pkcs8.der")
  let assert Ok(#(private, public)) = ec.from_der(der)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
  )
}

pub fn import_secp256k1_spki_pub_pem_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/secp256k1_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(priv_pem)
  let assert Ok(pub_pem) =
    simplifile.read("test/fixtures/secp256k1_spki_pub.pem")
  let assert Ok(public) = ec.public_key_from_pem(pub_pem)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
  )
}

pub fn import_secp256k1_spki_pub_der_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/secp256k1_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(priv_pem)
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/secp256k1_spki_pub.der")
  let assert Ok(public) = ec.public_key_from_der(pub_der)
  let signature = ecdsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256)
  assert ecdsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
  )
}

pub fn import_p256_ecdh_roundtrip_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p256_pkcs8.pem")
  let assert Ok(#(private, public)) = ec.from_pem(pem)
  let #(other_private, other_public) = ec.generate_key_pair(ec.P256)
  let assert Ok(shared1) = ecdh.compute_shared_secret(private, other_public)
  let assert Ok(shared2) = ecdh.compute_shared_secret(other_private, public)
  assert shared1 == shared2
}

pub fn public_key_to_raw_point_p256_test() {
  let #(_private, public_key) = ec.generate_key_pair(ec.P256)
  let raw_point = ec.public_key_to_raw_point(public_key)

  assert bit_array.byte_size(raw_point) == 65
  let assert <<first_byte:8, _rest:bits>> = raw_point
  assert first_byte == 0x04

  let assert Ok(reimported) = ec.public_key_from_raw_point(ec.P256, raw_point)
  let assert Ok(original_der) = ec.public_key_to_der(public_key)
  let assert Ok(reimported_der) = ec.public_key_to_der(reimported)
  assert original_der == reimported_der
}

pub fn public_key_to_raw_point_p384_test() {
  let #(_private, public_key) = ec.generate_key_pair(ec.P384)
  let raw_point = ec.public_key_to_raw_point(public_key)

  assert bit_array.byte_size(raw_point) == 97
  let assert <<first_byte:8, _rest:bits>> = raw_point
  assert first_byte == 0x04

  let assert Ok(reimported) = ec.public_key_from_raw_point(ec.P384, raw_point)
  let assert Ok(original_der) = ec.public_key_to_der(public_key)
  let assert Ok(reimported_der) = ec.public_key_to_der(reimported)
  assert original_der == reimported_der
}

pub fn public_key_to_raw_point_p521_test() {
  let #(_private, public_key) = ec.generate_key_pair(ec.P521)
  let raw_point = ec.public_key_to_raw_point(public_key)

  assert bit_array.byte_size(raw_point) == 133
  let assert <<first_byte:8, _rest:bits>> = raw_point
  assert first_byte == 0x04

  let assert Ok(reimported) = ec.public_key_from_raw_point(ec.P521, raw_point)
  let assert Ok(original_der) = ec.public_key_to_der(public_key)
  let assert Ok(reimported_der) = ec.public_key_to_der(reimported)
  assert original_der == reimported_der
}

pub fn public_key_to_raw_point_secp256k1_test() {
  let #(_private, public_key) = ec.generate_key_pair(ec.Secp256k1)
  let raw_point = ec.public_key_to_raw_point(public_key)

  assert bit_array.byte_size(raw_point) == 65
  let assert <<first_byte:8, _rest:bits>> = raw_point
  assert first_byte == 0x04

  let assert Ok(reimported) =
    ec.public_key_from_raw_point(ec.Secp256k1, raw_point)
  let assert Ok(original_der) = ec.public_key_to_der(public_key)
  let assert Ok(reimported_der) = ec.public_key_to_der(reimported)
  assert original_der == reimported_der
}

pub fn public_key_to_raw_point_decompresses_p256_test() {
  let assert Ok(pem) =
    simplifile.read("test/fixtures/p256_compressed_pkcs8.pem")
  let assert Ok(#(private_key, public_key)) = ec.from_pem(pem)
  let raw_point = ec.public_key_to_raw_point(public_key)

  assert bit_array.byte_size(raw_point) == 65
  let assert <<first_byte:8, _rest:bits>> = raw_point
  assert first_byte == 0x04

  let assert Ok(reimported) = ec.public_key_from_raw_point(ec.P256, raw_point)
  let message = <<"test message":utf8>>
  let signature = ecdsa.sign(private_key, message, hash.Sha256)
  assert ecdsa.verify(public_key, message, signature, hash.Sha256)
  assert ecdsa.verify(reimported, message, signature, hash.Sha256)
}

pub fn public_key_to_raw_point_decompresses_p384_test() {
  let assert Ok(pem) =
    simplifile.read("test/fixtures/p384_compressed_pkcs8.pem")
  let assert Ok(#(private_key, public_key)) = ec.from_pem(pem)
  let raw_point = ec.public_key_to_raw_point(public_key)

  assert bit_array.byte_size(raw_point) == 97
  let assert <<first_byte:8, _rest:bits>> = raw_point
  assert first_byte == 0x04

  let assert Ok(reimported) = ec.public_key_from_raw_point(ec.P384, raw_point)
  let message = <<"test message":utf8>>
  let signature = ecdsa.sign(private_key, message, hash.Sha384)
  assert ecdsa.verify(public_key, message, signature, hash.Sha384)
  assert ecdsa.verify(reimported, message, signature, hash.Sha384)
}

pub fn public_key_to_raw_point_decompresses_p521_test() {
  let assert Ok(pem) =
    simplifile.read("test/fixtures/p521_compressed_pkcs8.pem")
  let assert Ok(#(private_key, public_key)) = ec.from_pem(pem)
  let raw_point = ec.public_key_to_raw_point(public_key)

  assert bit_array.byte_size(raw_point) == 133
  let assert <<first_byte:8, _rest:bits>> = raw_point
  assert first_byte == 0x04

  let assert Ok(reimported) = ec.public_key_from_raw_point(ec.P521, raw_point)
  let message = <<"test message":utf8>>
  let signature = ecdsa.sign(private_key, message, hash.Sha512)
  assert ecdsa.verify(public_key, message, signature, hash.Sha512)
  assert ecdsa.verify(reimported, message, signature, hash.Sha512)
}

pub fn public_key_to_raw_point_decompresses_secp256k1_test() {
  let assert Ok(pem) =
    simplifile.read("test/fixtures/secp256k1_compressed_pkcs8.pem")
  let assert Ok(#(private_key, public_key)) = ec.from_pem(pem)
  let raw_point = ec.public_key_to_raw_point(public_key)

  assert bit_array.byte_size(raw_point) == 65
  let assert <<first_byte:8, _rest:bits>> = raw_point
  assert first_byte == 0x04

  let assert Ok(reimported) =
    ec.public_key_from_raw_point(ec.Secp256k1, raw_point)
  let message = <<"test message":utf8>>
  let signature = ecdsa.sign(private_key, message, hash.Sha256)
  assert ecdsa.verify(public_key, message, signature, hash.Sha256)
  assert ecdsa.verify(reimported, message, signature, hash.Sha256)
}

pub fn private_key_curve_p256_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p256_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(pem)
  assert ec.curve(private) == ec.P256
}

pub fn public_key_curve_p256_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p256_spki_pub.pem")
  let assert Ok(public) = ec.public_key_from_pem(pem)
  assert ec.public_key_curve(public) == ec.P256
}

pub fn private_key_curve_p384_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p384_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(pem)
  assert ec.curve(private) == ec.P384
}

pub fn public_key_curve_p384_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p384_spki_pub.pem")
  let assert Ok(public) = ec.public_key_from_pem(pem)
  assert ec.public_key_curve(public) == ec.P384
}

pub fn private_key_curve_p521_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p521_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(pem)
  assert ec.curve(private) == ec.P521
}

pub fn public_key_curve_p521_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p521_spki_pub.pem")
  let assert Ok(public) = ec.public_key_from_pem(pem)
  assert ec.public_key_curve(public) == ec.P521
}

pub fn private_key_curve_secp256k1_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/secp256k1_pkcs8.pem")
  let assert Ok(#(private, _)) = ec.from_pem(pem)
  assert ec.curve(private) == ec.Secp256k1
}

pub fn public_key_curve_secp256k1_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/secp256k1_spki_pub.pem")
  let assert Ok(public) = ec.public_key_from_pem(pem)
  assert ec.public_key_curve(public) == ec.Secp256k1
}
