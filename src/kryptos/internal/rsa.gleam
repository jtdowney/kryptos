import gleam/result
import kryptos/rsa

/// Import an RSA private key from PKCS#8 DER-encoded bytes.
/// Internal use only for testing.
pub fn private_key_from_pkcs8(
  der_bytes: BitArray,
) -> Result(#(rsa.PrivateKey, rsa.PublicKey), Nil) {
  rsa.from_der(der_bytes, rsa.Pkcs8)
  |> result.map_error(fn(_) { Nil })
}

/// Import an RSA public key from X509/SPKI DER-encoded bytes.
/// Internal use only for testing.
pub fn public_key_from_x509(der_bytes: BitArray) -> Result(rsa.PublicKey, Nil) {
  rsa.public_key_from_der(der_bytes, rsa.Spki)
  |> result.map_error(fn(_) { Nil })
}
