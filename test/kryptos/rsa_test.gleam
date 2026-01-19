import birdie
import gleam/bit_array
import gleam/int
import kryptos/crypto
import kryptos/hash
import kryptos/rsa
import qcheck
import simplifile

fn load_test_key() -> String {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa2048_pkcs8.pem")
  pem
}

fn load_test_key_pair() -> #(rsa.PrivateKey, rsa.PublicKey) {
  let assert Ok(#(private, public)) = rsa.from_pem(load_test_key(), rsa.Pkcs8)
  #(private, public)
}

// Property: sign then verify returns true for all padding/hash combinations
pub fn rsa_sign_verify_roundtrip_property_test() {
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(#(hash.Sha256, rsa.Pkcs1v15)), [
        qcheck.return(#(hash.Sha384, rsa.Pkcs1v15)),
        qcheck.return(#(hash.Sha512, rsa.Pkcs1v15)),
        qcheck.return(#(hash.Sha256, rsa.Pss(rsa.SaltLengthHashLen))),
        qcheck.return(#(hash.Sha256, rsa.Pss(rsa.SaltLengthMax))),
        qcheck.return(#(hash.Sha256, rsa.Pss(rsa.SaltLengthExplicit(20)))),
      ]),
      qcheck.byte_aligned_bit_array(),
    )

  let #(private_key, public_key) = load_test_key_pair()

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(#(hash_alg, padding), message) = input
    let signature = rsa.sign(private_key, message, hash_alg, padding)
    assert rsa.verify(public_key, message, signature, hash_alg, padding)
  })
}

// Property: wrong public key fails verification
pub fn rsa_wrong_public_key_fails_property_test() {
  let gen = qcheck.byte_aligned_bit_array()

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(3),
    gen,
    fn(message) {
      let assert Ok(#(private_key, _)) = rsa.generate_key_pair(2048)
      let assert Ok(#(_, other_public_key)) = rsa.generate_key_pair(2048)
      let signature = rsa.sign(private_key, message, hash.Sha256, rsa.Pkcs1v15)
      assert !rsa.verify(
        other_public_key,
        message,
        signature,
        hash.Sha256,
        rsa.Pkcs1v15,
      )
    },
  )
}

// Property: tampered message fails verification
pub fn rsa_tampered_message_fails_property_test() {
  let gen = qcheck.non_empty_byte_aligned_bit_array()
  let #(private_key, public_key) = load_test_key_pair()

  qcheck.run(qcheck.default_config(), gen, fn(message) {
    let signature = rsa.sign(private_key, message, hash.Sha256, rsa.Pkcs1v15)

    // Flip first bit
    let assert <<first_byte:8, rest:bits>> = message
    let tampered = <<{ int.bitwise_exclusive_or(first_byte, 1) }:8, rest:bits>>

    assert !rsa.verify(
      public_key,
      tampered,
      signature,
      hash.Sha256,
      rsa.Pkcs1v15,
    )
  })
}

// Property: encrypt then decrypt returns original plaintext
// Note: RSA plaintext size is limited by key size and padding
// For 2048-bit key with OAEP-SHA256: max ~190 bytes
pub fn rsa_encrypt_decrypt_roundtrip_property_test() {
  let #(private_key, public_key) = load_test_key_pair()
  let gen =
    qcheck.tuple2(
      qcheck.from_generators(qcheck.return(rsa.EncryptPkcs1v15), [
        qcheck.return(rsa.Oaep(hash: hash.Sha256, label: <<>>)),
        qcheck.return(rsa.Oaep(hash: hash.Sha384, label: <<>>)),
      ]),
      // Limit plaintext to 100 bytes to stay within all padding schemes
      qcheck.bounded_int(0, 100),
    )

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    gen,
    fn(input) {
      let #(padding, plaintext_size) = input
      let plaintext = crypto.random_bytes(plaintext_size)

      let assert Ok(ciphertext) = rsa.encrypt(public_key, plaintext, padding)
      let assert Ok(decrypted) = rsa.decrypt(private_key, ciphertext, padding)
      assert decrypted == plaintext
    },
  )
}

pub fn generate_key_pair_too_small_test() {
  let assert Error(Nil) = rsa.generate_key_pair(512)
}

pub fn generate_key_pair_minimum_test() {
  let assert Ok(#(_private_key, _public_key)) = rsa.generate_key_pair(1024)
}

pub fn verify_tampered_signature_test() {
  let #(private_key, public_key) = load_test_key_pair()
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha256, rsa.Pkcs1v15)
  let tampered = <<0, signature:bits>>
  let valid =
    rsa.verify(public_key, message, tampered, hash.Sha256, rsa.Pkcs1v15)
  assert !valid
}

pub fn encrypt_decrypt_oaep_sha512_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let plaintext = <<"secret message":utf8>>
  let padding = rsa.Oaep(hash: hash.Sha512, label: <<>>)
  let assert Ok(ciphertext) = rsa.encrypt(public_key, plaintext, padding)
  let assert Ok(decrypted) = rsa.decrypt(private_key, ciphertext, padding)
  assert decrypted == plaintext
}

pub fn encrypt_decrypt_oaep_with_label_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let plaintext = <<"secret message":utf8>>
  let label = <<"my label":utf8>>
  let padding = rsa.Oaep(hash: hash.Sha256, label: label)
  let assert Ok(ciphertext) = rsa.encrypt(public_key, plaintext, padding)
  let assert Ok(decrypted) = rsa.decrypt(private_key, ciphertext, padding)
  assert decrypted == plaintext
}

pub fn decrypt_wrong_key_test() {
  let assert Ok(#(_private_key, public_key)) = rsa.generate_key_pair(2048)
  let assert Ok(#(other_private, _other_public)) = rsa.generate_key_pair(2048)
  let plaintext = <<"secret message":utf8>>
  let assert Ok(ciphertext) =
    rsa.encrypt(public_key, plaintext, rsa.EncryptPkcs1v15)
  let result = rsa.decrypt(other_private, ciphertext, rsa.EncryptPkcs1v15)
  // PKCS#1 v1.5 may sometimes "succeed" with garbage data if padding happens to be valid
  // The important thing is the decrypted data is not equal to the original
  let is_different = case result {
    Error(Nil) -> True
    Ok(decrypted) -> decrypted != plaintext
  }
  assert is_different
}

pub fn decrypt_wrong_label_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let plaintext = <<"secret message":utf8>>
  let padding = rsa.Oaep(hash: hash.Sha256, label: <<"label1":utf8>>)
  let assert Ok(ciphertext) = rsa.encrypt(public_key, plaintext, padding)
  let wrong_padding = rsa.Oaep(hash: hash.Sha256, label: <<"label2":utf8>>)
  let result = rsa.decrypt(private_key, ciphertext, wrong_padding)
  assert result == Error(Nil)
}

pub fn export_private_pkcs8_pem_test() {
  let assert Ok(#(private_key, _public_key)) =
    rsa.from_pem(load_test_key(), rsa.Pkcs8)
  let assert Ok(pem) = rsa.to_pem(private_key, rsa.Pkcs8)

  birdie.snap(pem, title: "rsa private key pkcs8 pem")
}

pub fn export_private_pkcs1_pem_test() {
  let assert Ok(#(private_key, _public_key)) =
    rsa.from_pem(load_test_key(), rsa.Pkcs8)
  let assert Ok(pem) = rsa.to_pem(private_key, rsa.Pkcs1)

  birdie.snap(pem, title: "rsa private key pkcs1 pem")
}

pub fn export_public_spki_pem_test() {
  let assert Ok(#(_private_key, public_key)) =
    rsa.from_pem(load_test_key(), rsa.Pkcs8)
  let assert Ok(pem) = rsa.public_key_to_pem(public_key, rsa.Spki)

  birdie.snap(pem, title: "rsa public key spki pem")
}

pub fn export_public_pkcs1_pem_test() {
  let assert Ok(#(_private_key, public_key)) =
    rsa.from_pem(load_test_key(), rsa.Pkcs8)
  let assert Ok(pem) = rsa.public_key_to_pem(public_key, rsa.RsaPublicKey)

  birdie.snap(pem, title: "rsa public key pkcs1 pem")
}

pub fn export_private_pkcs8_der_test() {
  let assert Ok(#(private_key, _public_key)) =
    rsa.from_pem(load_test_key(), rsa.Pkcs8)
  let assert Ok(der) = rsa.to_der(private_key, rsa.Pkcs8)

  birdie.snap(bit_array.base16_encode(der), title: "rsa private key pkcs8 der")
}

pub fn export_private_pkcs1_der_test() {
  let assert Ok(#(private_key, _public_key)) =
    rsa.from_pem(load_test_key(), rsa.Pkcs8)
  let assert Ok(der) = rsa.to_der(private_key, rsa.Pkcs1)

  birdie.snap(bit_array.base16_encode(der), title: "rsa private key pkcs1 der")
}

pub fn export_public_spki_der_test() {
  let assert Ok(#(_private_key, public_key)) =
    rsa.from_pem(load_test_key(), rsa.Pkcs8)
  let assert Ok(der) = rsa.public_key_to_der(public_key, rsa.Spki)

  birdie.snap(bit_array.base16_encode(der), title: "rsa public key spki der")
}

pub fn export_public_pkcs1_der_test() {
  let assert Ok(#(_private_key, public_key)) =
    rsa.from_pem(load_test_key(), rsa.Pkcs8)
  let assert Ok(der) = rsa.public_key_to_der(public_key, rsa.RsaPublicKey)

  birdie.snap(bit_array.base16_encode(der), title: "rsa public key pkcs1 der")
}

pub fn roundtrip_pkcs8_pem_test() {
  let assert Ok(#(private_key, original_public)) = rsa.generate_key_pair(2048)
  let assert Ok(pem) = rsa.to_pem(private_key, rsa.Pkcs8)
  let assert Ok(#(imported_private, _imported_public)) =
    rsa.from_pem(pem, rsa.Pkcs8)

  let message = <<"roundtrip test":utf8>>
  let signature = rsa.sign(imported_private, message, hash.Sha256, rsa.Pkcs1v15)
  let valid =
    rsa.verify(original_public, message, signature, hash.Sha256, rsa.Pkcs1v15)
  assert valid
}

pub fn roundtrip_pkcs1_pem_test() {
  let assert Ok(#(private_key, original_public)) = rsa.generate_key_pair(2048)
  let assert Ok(pem) = rsa.to_pem(private_key, rsa.Pkcs1)
  let assert Ok(#(imported_private, _imported_public)) =
    rsa.from_pem(pem, rsa.Pkcs1)

  let message = <<"roundtrip pkcs1 test":utf8>>
  let signature = rsa.sign(imported_private, message, hash.Sha256, rsa.Pkcs1v15)
  let valid =
    rsa.verify(original_public, message, signature, hash.Sha256, rsa.Pkcs1v15)
  assert valid
}

pub fn roundtrip_pkcs8_der_test() {
  let assert Ok(#(private_key, original_public)) = rsa.generate_key_pair(2048)
  let assert Ok(der) = rsa.to_der(private_key, rsa.Pkcs8)
  let assert Ok(#(imported_private, _imported_public)) =
    rsa.from_der(der, rsa.Pkcs8)

  let message = <<"roundtrip der test":utf8>>
  let signature = rsa.sign(imported_private, message, hash.Sha256, rsa.Pkcs1v15)
  let valid =
    rsa.verify(original_public, message, signature, hash.Sha256, rsa.Pkcs1v15)
  assert valid
}

pub fn import_public_key_pem_test() {
  let assert Ok(#(_private_key, original_public)) = rsa.generate_key_pair(2048)
  let assert Ok(pem) = rsa.public_key_to_pem(original_public, rsa.Spki)
  let assert Ok(_imported_public) = rsa.public_key_from_pem(pem, rsa.Spki)
}

pub fn import_public_key_der_test() {
  let assert Ok(#(_private_key, original_public)) = rsa.generate_key_pair(2048)
  let assert Ok(der) = rsa.public_key_to_der(original_public, rsa.Spki)
  let assert Ok(_imported_public) = rsa.public_key_from_der(der, rsa.Spki)
}

pub fn public_key_from_private_key_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let derived_public = rsa.public_key_from_private_key(private_key)

  // Verify the derived public key works the same as the original
  let message = <<"derived public key test":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha256, rsa.Pkcs1v15)
  let valid1 =
    rsa.verify(public_key, message, signature, hash.Sha256, rsa.Pkcs1v15)
  let valid2 =
    rsa.verify(derived_public, message, signature, hash.Sha256, rsa.Pkcs1v15)
  assert valid1
  assert valid2
}

pub fn import_rsa2048_pkcs8_pem_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa2048_pkcs8.pem")
  let assert Ok(#(private, public)) = rsa.from_pem(pem, rsa.Pkcs8)
  let signature =
    rsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256, rsa.Pkcs1v15)
  assert rsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
    rsa.Pkcs1v15,
  )
}

pub fn import_rsa2048_pkcs8_der_test() {
  let assert Ok(der) = simplifile.read_bits("test/fixtures/rsa2048_pkcs8.der")
  let assert Ok(#(private, public)) = rsa.from_der(der, rsa.Pkcs8)
  let signature =
    rsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256, rsa.Pkcs1v15)
  assert rsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
    rsa.Pkcs1v15,
  )
}

pub fn import_rsa2048_pkcs1_pem_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa2048_pkcs1.pem")
  let assert Ok(#(private, public)) = rsa.from_pem(pem, rsa.Pkcs1)
  let signature =
    rsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256, rsa.Pkcs1v15)
  assert rsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
    rsa.Pkcs1v15,
  )
}

pub fn import_rsa2048_pkcs1_der_test() {
  let assert Ok(der) = simplifile.read_bits("test/fixtures/rsa2048_pkcs1.der")
  let assert Ok(#(private, public)) = rsa.from_der(der, rsa.Pkcs1)
  let signature =
    rsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256, rsa.Pkcs1v15)
  assert rsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
    rsa.Pkcs1v15,
  )
}

pub fn import_rsa2048_spki_pub_pem_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/rsa2048_pkcs8.pem")
  let assert Ok(#(private, _)) = rsa.from_pem(priv_pem, rsa.Pkcs8)
  let assert Ok(pub_pem) = simplifile.read("test/fixtures/rsa2048_spki_pub.pem")
  let assert Ok(public) = rsa.public_key_from_pem(pub_pem, rsa.Spki)
  let signature =
    rsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256, rsa.Pkcs1v15)
  assert rsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
    rsa.Pkcs1v15,
  )
}

pub fn import_rsa2048_spki_pub_der_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/rsa2048_pkcs8.pem")
  let assert Ok(#(private, _)) = rsa.from_pem(priv_pem, rsa.Pkcs8)
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/rsa2048_spki_pub.der")
  let assert Ok(public) = rsa.public_key_from_der(pub_der, rsa.Spki)
  let signature =
    rsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256, rsa.Pkcs1v15)
  assert rsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
    rsa.Pkcs1v15,
  )
}

pub fn import_rsa2048_pkcs1_pub_pem_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/rsa2048_pkcs8.pem")
  let assert Ok(#(private, _)) = rsa.from_pem(priv_pem, rsa.Pkcs8)
  let assert Ok(pub_pem) =
    simplifile.read("test/fixtures/rsa2048_pkcs1_pub.pem")
  let assert Ok(public) = rsa.public_key_from_pem(pub_pem, rsa.RsaPublicKey)
  let signature =
    rsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256, rsa.Pkcs1v15)
  assert rsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
    rsa.Pkcs1v15,
  )
}

pub fn import_rsa2048_pkcs1_pub_der_test() {
  let assert Ok(priv_pem) = simplifile.read("test/fixtures/rsa2048_pkcs8.pem")
  let assert Ok(#(private, _)) = rsa.from_pem(priv_pem, rsa.Pkcs8)
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/rsa2048_pkcs1_pub.der")
  let assert Ok(public) = rsa.public_key_from_der(pub_der, rsa.RsaPublicKey)
  let signature =
    rsa.sign(private, <<"too many secrets":utf8>>, hash.Sha256, rsa.Pkcs1v15)
  assert rsa.verify(
    public,
    <<"too many secrets":utf8>>,
    signature,
    hash.Sha256,
    rsa.Pkcs1v15,
  )
}

pub fn private_key_modulus_bits_2048_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa2048_pkcs8.pem")
  let assert Ok(#(private, _)) = rsa.from_pem(pem, rsa.Pkcs8)
  assert rsa.modulus_bits(private) == 2048
}

pub fn public_key_modulus_bits_2048_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa2048_spki_pub.pem")
  let assert Ok(public) = rsa.public_key_from_pem(pem, rsa.Spki)
  assert rsa.public_key_modulus_bits(public) == 2048
}

pub fn private_key_exponent_65537_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa2048_pkcs8.pem")
  let assert Ok(#(private, _)) = rsa.from_pem(pem, rsa.Pkcs8)
  assert rsa.public_exponent(private) == 65_537
}

pub fn public_key_exponent_65537_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa2048_spki_pub.pem")
  let assert Ok(public) = rsa.public_key_from_pem(pem, rsa.Spki)
  assert rsa.public_key_exponent(public) == 65_537
}

pub fn private_key_modulus_bits_1024_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa1024_e3_pkcs8.pem")
  let assert Ok(#(private, _)) = rsa.from_pem(pem, rsa.Pkcs8)
  assert rsa.modulus_bits(private) == 1024
}

pub fn public_key_modulus_bits_1024_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa1024_e3_spki_pub.pem")
  let assert Ok(public) = rsa.public_key_from_pem(pem, rsa.Spki)
  assert rsa.public_key_modulus_bits(public) == 1024
}

pub fn private_key_exponent_3_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa1024_e3_pkcs8.pem")
  let assert Ok(#(private, _)) = rsa.from_pem(pem, rsa.Pkcs8)
  assert rsa.public_exponent(private) == 3
}

pub fn public_key_exponent_3_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa1024_e3_spki_pub.pem")
  let assert Ok(public) = rsa.public_key_from_pem(pem, rsa.Spki)
  assert rsa.public_key_exponent(public) == 3
}

pub fn modulus_bytes_consistency_property_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(5),
    qcheck.return(Nil),
    fn(_) {
      let assert Ok(#(private, public)) = rsa.generate_key_pair(2048)
      let priv_modulus = rsa.modulus(private)
      let pub_modulus = rsa.public_key_modulus(public)
      assert priv_modulus == pub_modulus
    },
  )
}

pub fn exponent_bytes_consistency_property_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(5),
    qcheck.return(Nil),
    fn(_) {
      let assert Ok(#(private, public)) = rsa.generate_key_pair(2048)
      let priv_exp = rsa.public_exponent_bytes(private)
      let pub_exp = rsa.public_key_exponent_bytes(public)
      assert priv_exp == pub_exp
    },
  )
}

pub fn from_components_roundtrip_sign_verify_property_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(5),
    qcheck.byte_aligned_bit_array(),
    fn(message) {
      let assert Ok(#(original_private, original_public)) =
        rsa.generate_key_pair(2048)

      let n = rsa.modulus(original_private)
      let e = rsa.public_exponent_bytes(original_private)
      let d = rsa.private_exponent_bytes(original_private)

      let assert Ok(#(reconstructed_private, reconstructed_public)) =
        rsa.from_components(n, e, d)

      let signature =
        rsa.sign(reconstructed_private, message, hash.Sha256, rsa.Pkcs1v15)
      assert rsa.verify(
        original_public,
        message,
        signature,
        hash.Sha256,
        rsa.Pkcs1v15,
      )
      assert rsa.verify(
        reconstructed_public,
        message,
        signature,
        hash.Sha256,
        rsa.Pkcs1v15,
      )
    },
  )
}

pub fn from_full_components_roundtrip_sign_verify_property_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(5),
    qcheck.byte_aligned_bit_array(),
    fn(message) {
      let assert Ok(#(original_private, original_public)) =
        rsa.generate_key_pair(2048)

      let n = rsa.modulus(original_private)
      let e = rsa.public_exponent_bytes(original_private)
      let d = rsa.private_exponent_bytes(original_private)
      let p = rsa.prime1(original_private)
      let q = rsa.prime2(original_private)
      let dp = rsa.exponent1(original_private)
      let dq = rsa.exponent2(original_private)
      let qi = rsa.coefficient(original_private)

      let assert Ok(#(reconstructed_private, reconstructed_public)) =
        rsa.from_full_components(n, e, d, p, q, dp, dq, qi)

      let signature =
        rsa.sign(reconstructed_private, message, hash.Sha256, rsa.Pkcs1v15)
      assert rsa.verify(
        original_public,
        message,
        signature,
        hash.Sha256,
        rsa.Pkcs1v15,
      )
      assert rsa.verify(
        reconstructed_public,
        message,
        signature,
        hash.Sha256,
        rsa.Pkcs1v15,
      )
    },
  )
}

pub fn from_components_crt_accessors_work_test() {
  // Verify CRT accessors work on keys created via from_components
  let assert Ok(#(original_private, _)) = rsa.generate_key_pair(2048)

  let n = rsa.modulus(original_private)
  let e = rsa.public_exponent_bytes(original_private)
  let d = rsa.private_exponent_bytes(original_private)

  let assert Ok(#(reconstructed_private, _)) = rsa.from_components(n, e, d)

  // These should not crash - CRT params should be computed
  let p = rsa.prime1(reconstructed_private)
  let q = rsa.prime2(reconstructed_private)
  let dp = rsa.exponent1(reconstructed_private)
  let dq = rsa.exponent2(reconstructed_private)
  let qi = rsa.coefficient(reconstructed_private)

  // Verify the CRT params are non-empty
  assert bit_array.byte_size(p) > 0
  assert bit_array.byte_size(q) > 0
  assert bit_array.byte_size(dp) > 0
  assert bit_array.byte_size(dq) > 0
  assert bit_array.byte_size(qi) > 0

  // Verify modulus = p * q (basic sanity check)
  // We just verify that the key works for signing
  let message = <<"CRT test":utf8>>
  let signature =
    rsa.sign(reconstructed_private, message, hash.Sha256, rsa.Pkcs1v15)
  let reconstructed_public =
    rsa.public_key_from_private_key(reconstructed_private)
  assert rsa.verify(
    reconstructed_public,
    message,
    signature,
    hash.Sha256,
    rsa.Pkcs1v15,
  )
}

pub fn public_key_from_components_roundtrip_property_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(5),
    qcheck.byte_aligned_bit_array(),
    fn(message) {
      let assert Ok(#(private, _)) = rsa.generate_key_pair(2048)

      let n = rsa.modulus(private)
      let e = rsa.public_exponent_bytes(private)

      let assert Ok(reconstructed_public) = rsa.public_key_from_components(n, e)

      let signature = rsa.sign(private, message, hash.Sha256, rsa.Pkcs1v15)
      assert rsa.verify(
        reconstructed_public,
        message,
        signature,
        hash.Sha256,
        rsa.Pkcs1v15,
      )
    },
  )
}
