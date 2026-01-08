import kryptos/ec.{type Curve, type PrivateKey, type PublicKey}

/// Import a private key from raw scalar bytes. Internal use only for testing.
@external(erlang, "kryptos_ffi", "ec_private_key_from_bytes")
@external(javascript, "../../kryptos_ffi.mjs", "ecPrivateKeyFromBytes")
pub fn private_key_from_bytes(
  curve: Curve,
  private_scalar: BitArray,
) -> Result(#(PrivateKey, PublicKey), Nil)
