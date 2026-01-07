import kryptos/public_key.{type PrivateKey, type PublicKey, type RSA}

/// Import an RSA private key from PKCS#8 DER-encoded bytes.
/// Internal use only for testing.
@external(erlang, "kryptos_ffi", "rsa_private_key_from_pkcs8")
@external(javascript, "../../kryptos_ffi.mjs", "rsaPrivateKeyFromPkcs8")
pub fn private_key_from_pkcs8(
  der_bytes: BitArray,
) -> Result(#(PrivateKey(RSA, RSA, Nil), PublicKey(RSA, RSA, Nil)), Nil)

/// Import an RSA public key from X509/SPKI DER-encoded bytes.
/// Internal use only for testing.
@external(erlang, "kryptos_ffi", "rsa_public_key_from_x509")
@external(javascript, "../../kryptos_ffi.mjs", "rsaPublicKeyFromX509")
pub fn public_key_from_x509(
  der_bytes: BitArray,
) -> Result(PublicKey(RSA, RSA, Nil), Nil)
