import birdie
import gleam/bit_array
import kryptos/ec
import kryptos/ecdh
import kryptos/ecdsa
import kryptos/hash
import qcheck
import simplifile

fn load_test_key() -> String {
  let assert Ok(pem) = simplifile.read("test/fixtures/p256_pkcs8.pem")
  pem
}

fn compress_raw_point(point: BitArray, coordinate_size: Int) -> BitArray {
  let assert <<
    0x04,
    x:bytes-size(coordinate_size),
    y:bytes-size(coordinate_size),
  >> = point
  let assert Ok(<<final_y:8>>) = bit_array.slice(y, coordinate_size - 1, 1)
  let prefix = case final_y % 2 {
    0 -> 0x02
    _ -> 0x03
  }
  <<prefix, x:bits>>
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

pub fn public_key_from_der_rejects_explicit_curve_parameters_test() {
  let assert Ok(der) =
    simplifile.read_bits("test/fixtures/p256_explicit_params_spki_pub.der")
  assert ec.public_key_from_der(der) == Error(Nil)
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

pub fn public_key_from_compressed_raw_point_roundtrip_property_test() {
  let gen =
    qcheck.from_generators(qcheck.return(#(ec.P256, hash.Sha256)), [
      qcheck.return(#(ec.P384, hash.Sha384)),
      qcheck.return(#(ec.P521, hash.Sha512)),
      qcheck.return(#(ec.Secp256k1, hash.Sha256)),
    ])

  use #(curve, hash_algorithm) <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(20),
    gen,
  )
  let #(private_key, public_key) = ec.generate_key_pair(curve)
  let expected_point = ec.public_key_to_raw_point(public_key)
  let compressed = compress_raw_point(expected_point, ec.coordinate_size(curve))

  let assert Ok(imported) = ec.public_key_from_raw_point(curve, compressed)
  assert ec.public_key_to_raw_point(imported) == expected_point

  let message = <<"compressed SEC1 point":utf8>>
  let signature = ecdsa.sign(private_key, message, hash_algorithm)
  assert ecdsa.verify(imported, message, signature, hash_algorithm)
}

pub fn public_key_from_raw_point_accepts_both_compressed_prefixes_test() {
  let assert Ok(p256_compressed) =
    bit_array.base16_decode(
      "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    )
  let assert Ok(p256_uncompressed) =
    bit_array.base16_decode(
      "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    )
  let assert Ok(p256_key) =
    ec.public_key_from_raw_point(ec.P256, p256_compressed)
  assert ec.public_key_to_raw_point(p256_key) == p256_uncompressed

  let assert Ok(k256_compressed) =
    bit_array.base16_decode(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
  let assert Ok(k256_uncompressed) =
    bit_array.base16_decode(
      "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    )
  let assert Ok(k256_key) =
    ec.public_key_from_raw_point(ec.Secp256k1, k256_compressed)
  assert ec.public_key_to_raw_point(k256_key) == k256_uncompressed
}

pub fn public_key_from_raw_point_rejects_malformed_compressed_points_test() {
  let assert Error(Nil) =
    ec.public_key_from_raw_point(ec.P256, <<0x02, 0:size(31)-unit(8)>>)
  let assert Error(Nil) =
    ec.public_key_from_raw_point(ec.P256, <<0x02, 0:size(33)-unit(8)>>)
  let assert Error(Nil) = ec.public_key_from_raw_point(ec.P256, <<0x00>>)
  let assert Error(Nil) =
    ec.public_key_from_raw_point(ec.P256, <<0x06, 0:size(64)-unit(8)>>)
}

pub fn public_key_from_raw_point_rejects_invalid_compressed_points_test() {
  let assert Ok(invalid_p256) =
    bit_array.base16_decode(
      "02fd4bf61763b46581fd9174d623516cf3c81edd40e29ffa2777fb6cb0ae3ce535",
    )
  let assert Error(Nil) = ec.public_key_from_raw_point(ec.P256, invalid_p256)

  let invalid_k256 = <<0x02, 0:size(32)-unit(8)>>
  let assert Error(Nil) =
    ec.public_key_from_raw_point(ec.Secp256k1, invalid_k256)
}

pub fn public_key_from_raw_point_rejects_compressed_point_on_wrong_curve_test() {
  let assert Ok(k256_generator) =
    bit_array.base16_decode(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
  let assert Error(Nil) = ec.public_key_from_raw_point(ec.P256, k256_generator)
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

pub fn to_bytes_from_bytes_roundtrip_property_test() {
  let gen =
    qcheck.from_generators(qcheck.return(#(ec.P256, hash.Sha256, 32)), [
      qcheck.return(#(ec.P384, hash.Sha384, 48)),
      qcheck.return(#(ec.P521, hash.Sha512, 66)),
      qcheck.return(#(ec.Secp256k1, hash.Sha256, 32)),
    ])

  use input <- qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(20),
    gen,
  )
  let #(curve, hash_alg, expected_size) = input
  let #(private, public) = ec.generate_key_pair(curve)
  let bytes = ec.to_bytes(private)

  assert bit_array.byte_size(bytes) == expected_size

  let assert Ok(#(reimported_private, reimported_public)) =
    ec.from_bytes(curve, bytes)

  let message = <<"roundtrip test":utf8>>
  let signature = ecdsa.sign(reimported_private, message, hash_alg)
  assert ecdsa.verify(public, message, signature, hash_alg)
  assert ecdsa.verify(reimported_public, message, signature, hash_alg)
}

pub fn from_bytes_rejects_way_too_long_scalar_test() {
  // P256 expects 32 bytes, provide 34 (more than coordSize + 1)
  let long_scalar = <<0:size(34)-unit(8)>>
  assert ec.from_bytes(ec.P256, long_scalar) == Error(Nil)

  // P384 expects 48 bytes, provide 50
  let long_scalar_384 = <<0:size(50)-unit(8)>>
  assert ec.from_bytes(ec.P384, long_scalar_384) == Error(Nil)

  // P521 expects 66 bytes, provide 68
  let long_scalar_521 = <<0:size(68)-unit(8)>>
  assert ec.from_bytes(ec.P521, long_scalar_521) == Error(Nil)

  // Secp256k1 expects 32 bytes, provide 34
  let long_scalar_k1 = <<0:size(34)-unit(8)>>
  assert ec.from_bytes(ec.Secp256k1, long_scalar_k1) == Error(Nil)
}

pub fn from_bytes_rejects_invalid_der_sign_byte_test() {
  // P256 expects 32 bytes, provide 33 with non-zero leading byte
  // (33 bytes is only valid if first byte is 0x00 for DER sign)
  let invalid_der = <<1:8, 0:size(32)-unit(8)>>
  assert ec.from_bytes(ec.P256, invalid_der) == Error(Nil)

  // P384: 49 bytes with non-zero leading byte
  let invalid_der_384 = <<1:8, 0:size(48)-unit(8)>>
  assert ec.from_bytes(ec.P384, invalid_der_384) == Error(Nil)
}

pub fn from_bytes_rejects_empty_scalar_test() {
  assert ec.from_bytes(ec.P256, <<>>) == Error(Nil)
  assert ec.from_bytes(ec.P384, <<>>) == Error(Nil)
  assert ec.from_bytes(ec.P521, <<>>) == Error(Nil)
  assert ec.from_bytes(ec.Secp256k1, <<>>) == Error(Nil)
}

pub fn from_bytes_strips_der_sign_byte_test() {
  let scalar = <<1:size(32)-unit(8)>>
  let assert Ok(#(private_key, _)) = ec.from_bytes(ec.P256, <<0, scalar:bits>>)
  assert ec.to_bytes(private_key) == scalar
}

pub fn from_bytes_left_pads_short_scalar_test() {
  let assert Ok(#(private_key, _)) = ec.from_bytes(ec.P256, <<1>>)
  assert ec.to_bytes(private_key) == <<1:size(32)-unit(8)>>
}
