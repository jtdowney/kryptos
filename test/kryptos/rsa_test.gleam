import birdie
import gleam/bit_array
import kryptos/hash
import kryptos/rsa
import simplifile

fn load_test_key() -> String {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa2048_pkcs8.pem")
  pem
}

pub fn generate_key_pair_too_small_test() {
  let assert Error(Nil) = rsa.generate_key_pair(512)
}

pub fn generate_key_pair_minimum_test() {
  let assert Ok(#(_private_key, _public_key)) = rsa.generate_key_pair(1024)
}

pub fn sign_verify_pkcs1v15_sha256_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha256, rsa.Pkcs1v15)
  let valid =
    rsa.verify(public_key, message, signature, hash.Sha256, rsa.Pkcs1v15)
  assert valid
}

pub fn sign_verify_pkcs1v15_sha384_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha384, rsa.Pkcs1v15)
  let valid =
    rsa.verify(public_key, message, signature, hash.Sha384, rsa.Pkcs1v15)
  assert valid
}

pub fn sign_verify_pkcs1v15_sha512_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha512, rsa.Pkcs1v15)
  let valid =
    rsa.verify(public_key, message, signature, hash.Sha512, rsa.Pkcs1v15)
  assert valid
}

pub fn sign_verify_pss_hash_len_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let padding = rsa.Pss(rsa.SaltLengthHashLen)
  let signature = rsa.sign(private_key, message, hash.Sha256, padding)
  let valid = rsa.verify(public_key, message, signature, hash.Sha256, padding)
  assert valid
}

pub fn sign_verify_pss_max_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let padding = rsa.Pss(rsa.SaltLengthMax)
  let signature = rsa.sign(private_key, message, hash.Sha256, padding)
  let valid = rsa.verify(public_key, message, signature, hash.Sha256, padding)
  assert valid
}

pub fn sign_verify_pss_explicit_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let padding = rsa.Pss(rsa.SaltLengthExplicit(20))
  let signature = rsa.sign(private_key, message, hash.Sha256, padding)
  let valid = rsa.verify(public_key, message, signature, hash.Sha256, padding)
  assert valid
}

pub fn verify_wrong_key_test() {
  let assert Ok(#(private_key, _public_key)) = rsa.generate_key_pair(2048)
  let assert Ok(#(_other_private, other_public)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha256, rsa.Pkcs1v15)
  let valid =
    rsa.verify(other_public, message, signature, hash.Sha256, rsa.Pkcs1v15)
  assert !valid
}

pub fn verify_tampered_message_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha256, rsa.Pkcs1v15)
  let tampered = <<"goodbye world":utf8>>
  let valid =
    rsa.verify(public_key, tampered, signature, hash.Sha256, rsa.Pkcs1v15)
  assert !valid
}

pub fn verify_tampered_signature_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha256, rsa.Pkcs1v15)
  let tampered = <<0, signature:bits>>
  let valid =
    rsa.verify(public_key, message, tampered, hash.Sha256, rsa.Pkcs1v15)
  assert !valid
}

pub fn encrypt_decrypt_pkcs1v15_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let plaintext = <<"secret message":utf8>>
  let assert Ok(ciphertext) =
    rsa.encrypt(public_key, plaintext, rsa.EncryptPkcs1v15)
  let assert Ok(decrypted) =
    rsa.decrypt(private_key, ciphertext, rsa.EncryptPkcs1v15)
  assert decrypted == plaintext
}

pub fn encrypt_decrypt_oaep_sha256_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let plaintext = <<"secret message":utf8>>
  let padding = rsa.Oaep(hash: hash.Sha256, label: <<>>)
  let assert Ok(ciphertext) = rsa.encrypt(public_key, plaintext, padding)
  let assert Ok(decrypted) = rsa.decrypt(private_key, ciphertext, padding)
  assert decrypted == plaintext
}

pub fn encrypt_decrypt_oaep_sha384_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let plaintext = <<"secret message":utf8>>
  let padding = rsa.Oaep(hash: hash.Sha384, label: <<>>)
  let assert Ok(ciphertext) = rsa.encrypt(public_key, plaintext, padding)
  let assert Ok(decrypted) = rsa.decrypt(private_key, ciphertext, padding)
  assert decrypted == plaintext
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
