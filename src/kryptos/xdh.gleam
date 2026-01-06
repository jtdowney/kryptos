//// X25519 and X448 (XDH) key agreement.
////
//// XDH provides Diffie-Hellman key agreement using Montgomery curves X25519
//// and X448. These curves are designed specifically for key agreement and
//// offer excellent performance with strong security properties.
////
//// ## Example
////
//// ```gleam
//// import kryptos/xdh
////
//// // Alice generates a key pair
//// let #(alice_private, alice_public) = xdh.generate_key_pair(xdh.X25519)
////
//// // Bob generates a key pair
//// let #(bob_private, bob_public) = xdh.generate_key_pair(xdh.X25519)
////
//// // Both compute the same shared secret
//// let assert Ok(alice_shared) = xdh.compute_shared_secret(alice_private, bob_public)
//// let assert Ok(bob_shared) = xdh.compute_shared_secret(bob_private, alice_public)
//// // alice_shared == bob_shared
//// ```

import gleam/result
import kryptos/public_key.{type PrivateKey, type PublicKey, type XDH}

/// Supported curves for XDH key agreement.
pub type Curve {
  /// X25519 curve (Curve25519). 32-byte keys and shared secret.
  X25519
  /// X448 curve (Curve448). 56-byte keys and shared secret.
  X448
}

/// Returns the key size in bytes for the given curve.
///
/// - X25519: 32 bytes
/// - X448: 56 bytes
pub fn key_size(curve: Curve) -> Int {
  case curve {
    X25519 -> 32
    X448 -> 56
  }
}

/// Generates a new XDH key pair.
///
/// ## Parameters
/// - `curve`: The curve to use for key generation (X25519 or X448)
///
/// ## Returns
/// A tuple of `#(private_key, public_key)`.
@external(erlang, "kryptos_ffi", "xdh_generate_key_pair")
@external(javascript, "../kryptos_ffi.mjs", "xdhGenerateKeyPair")
pub fn generate_key_pair(
  curve: Curve,
) -> #(PrivateKey(Nil, Nil, XDH), PublicKey(Nil, Nil, XDH))

/// Computes a shared secret using XDH key agreement.
///
/// Both parties compute the same shared secret by combining their private key
/// with the other party's public key.
///
/// Returns `Error(Nil)` if the keys use different curves, the result is an
/// all-zero shared secret (low-order point attack), or another error occurs.
///
/// The raw shared secret should be passed through a KDF (like HKDF) before
/// use as a symmetric key.
pub fn compute_shared_secret(
  private_key: PrivateKey(signing, encrypting, XDH),
  peer_public_key: PublicKey(signing, encrypting, XDH),
) -> Result(BitArray, Nil) {
  use shared <- result.try(do_compute_shared_secret(
    private_key,
    peer_public_key,
  ))
  case is_all_zeros(shared) {
    True -> Error(Nil)
    False -> Ok(shared)
  }
}

fn is_all_zeros(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<0, rest:bytes>> -> is_all_zeros(rest)
    _ -> False
  }
}

@external(erlang, "kryptos_ffi", "xdh_compute_shared_secret")
@external(javascript, "../kryptos_ffi.mjs", "xdhComputeSharedSecret")
fn do_compute_shared_secret(
  private_key: PrivateKey(signing, encrypting, XDH),
  peer_public_key: PublicKey(signing, encrypting, XDH),
) -> Result(BitArray, Nil)

/// Imports a private key from raw bytes.
///
/// The bytes should be the raw private key scalar:
/// - X25519: 32 bytes
/// - X448: 56 bytes
///
/// Returns the private key and its corresponding public key, or `Error(Nil)`
/// if the bytes are invalid.
@external(erlang, "kryptos_ffi", "xdh_private_key_from_bytes")
@external(javascript, "../kryptos_ffi.mjs", "xdhPrivateKeyFromBytes")
pub fn private_key_from_bytes(
  curve: Curve,
  private_bytes: BitArray,
) -> Result(#(PrivateKey(Nil, Nil, XDH), PublicKey(Nil, Nil, XDH)), Nil)

/// Imports a public key from raw bytes.
///
/// The bytes should be the raw public key point:
/// - X25519: 32 bytes
/// - X448: 56 bytes
///
/// Returns the public key or `Error(Nil)` if the bytes are invalid.
@external(erlang, "kryptos_ffi", "xdh_public_key_from_bytes")
@external(javascript, "../kryptos_ffi.mjs", "xdhPublicKeyFromBytes")
pub fn public_key_from_bytes(
  curve: Curve,
  public_bytes: BitArray,
) -> Result(PublicKey(Nil, Nil, XDH), Nil)
