import kryptos/hash
import kryptos/rsa

pub fn generate_key_pair_2048_test() {
  let assert Ok(#(_private_key, _public_key)) = rsa.generate_key_pair(2048)
}

pub fn generate_key_pair_3072_test() {
  let assert Ok(#(_private_key, _public_key)) = rsa.generate_key_pair(3072)
}

pub fn generate_key_pair_4096_test() {
  let assert Ok(#(_private_key, _public_key)) = rsa.generate_key_pair(4096)
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
  assert valid == True
}

pub fn sign_verify_pkcs1v15_sha384_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha384, rsa.Pkcs1v15)
  let valid =
    rsa.verify(public_key, message, signature, hash.Sha384, rsa.Pkcs1v15)
  assert valid == True
}

pub fn sign_verify_pkcs1v15_sha512_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha512, rsa.Pkcs1v15)
  let valid =
    rsa.verify(public_key, message, signature, hash.Sha512, rsa.Pkcs1v15)
  assert valid == True
}

pub fn sign_verify_pss_hash_len_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let padding = rsa.Pss(rsa.SaltLengthHashLen)
  let signature = rsa.sign(private_key, message, hash.Sha256, padding)
  let valid = rsa.verify(public_key, message, signature, hash.Sha256, padding)
  assert valid == True
}

pub fn sign_verify_pss_max_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let padding = rsa.Pss(rsa.SaltLengthMax)
  let signature = rsa.sign(private_key, message, hash.Sha256, padding)
  let valid = rsa.verify(public_key, message, signature, hash.Sha256, padding)
  assert valid == True
}

pub fn sign_verify_pss_explicit_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let padding = rsa.Pss(rsa.SaltLengthExplicit(20))
  let signature = rsa.sign(private_key, message, hash.Sha256, padding)
  let valid = rsa.verify(public_key, message, signature, hash.Sha256, padding)
  assert valid == True
}

pub fn verify_wrong_key_test() {
  let assert Ok(#(private_key, _public_key)) = rsa.generate_key_pair(2048)
  let assert Ok(#(_other_private, other_public)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha256, rsa.Pkcs1v15)
  let valid =
    rsa.verify(other_public, message, signature, hash.Sha256, rsa.Pkcs1v15)
  assert valid == False
}

pub fn verify_tampered_message_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha256, rsa.Pkcs1v15)
  let tampered = <<"goodbye world":utf8>>
  let valid =
    rsa.verify(public_key, tampered, signature, hash.Sha256, rsa.Pkcs1v15)
  assert valid == False
}

pub fn verify_tampered_signature_test() {
  let assert Ok(#(private_key, public_key)) = rsa.generate_key_pair(2048)
  let message = <<"hello world":utf8>>
  let signature = rsa.sign(private_key, message, hash.Sha256, rsa.Pkcs1v15)
  let tampered = <<0, signature:bits>>
  let valid =
    rsa.verify(public_key, message, tampered, hash.Sha256, rsa.Pkcs1v15)
  assert valid == False
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
  assert is_different == True
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
