//// Elliptic Curve Diffie-Hellman (ECDH) key agreement.
////
//// ECDH allows two parties to establish a shared secret over an insecure
//// channel using elliptic curve key pairs. The shared secret can then be
//// used with a key derivation function (KDF) to derive symmetric keys.
////
//// ## Example
////
//// ```gleam
//// import kryptos/ec
//// import kryptos/ecdh
////
//// // Alice generates a key pair
//// let #(alice_private, alice_public) = ec.generate_key_pair(ec.P256)
////
//// // Bob generates a key pair
//// let #(bob_private, bob_public) = ec.generate_key_pair(ec.P256)
////
//// // Both compute the same shared secret
//// let assert Ok(alice_shared) = ecdh.compute_shared_secret(alice_private, bob_public)
//// let assert Ok(bob_shared) = ecdh.compute_shared_secret(bob_private, alice_public)
//// // alice_shared == bob_shared
//// ```

import kryptos/ec.{type PrivateKey, type PublicKey}

/// Computes a shared secret using ECDH key agreement.
///
/// Both parties compute the same shared secret by combining their private key
/// with the other party's public key. The result is the x-coordinate of the
/// resulting elliptic curve point, returned as raw bytes.
///
/// The raw shared secret should be passed through a KDF (like HKDF) before
/// use as a symmetric key.
///
/// ## Parameters
/// - `private_key`: Your EC private key
/// - `peer_public_key`: The other party's public key
///
/// ## Returns
/// `Ok(BitArray)` containing the shared secret on success, `Error(Nil)`
/// if the keys use different curves or another error occurs.
@external(erlang, "kryptos_ffi", "ecdh_compute_shared_secret")
@external(javascript, "../kryptos_ffi.mjs", "ecdhComputeSharedSecret")
pub fn compute_shared_secret(
  private_key: PrivateKey,
  peer_public_key: PublicKey,
) -> Result(BitArray, Nil)
