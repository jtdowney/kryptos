import bigi
import gleam/bit_array
import gleam/order
import kryptos/rsa
import qcheck

pub fn compute_crt_params_invariants_property_test() {
  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(15),
    qcheck.from_generators(qcheck.return(1024), [
      qcheck.return(2048),
      qcheck.return(3072),
    ]),
    fn(bits) {
      let assert Ok(#(private, _)) = rsa.generate_key_pair(bits)

      let n = rsa.modulus(private)
      let e = rsa.public_exponent_bytes(private)
      let d = rsa.private_exponent_bytes(private)

      // Reconstruct via our CRT derivation
      let assert Ok(#(reconstructed, _)) = rsa.from_components(n, e, d)
      let n_bytes = rsa.modulus(reconstructed)
      let d_bytes = rsa.private_exponent_bytes(reconstructed)
      let p_bytes = rsa.prime1(reconstructed)
      let q_bytes = rsa.prime2(reconstructed)
      let dp_bytes = rsa.exponent1(reconstructed)
      let dq_bytes = rsa.exponent2(reconstructed)
      let qi_bytes = rsa.coefficient(reconstructed)

      let assert Ok(n_val) =
        bigi.from_bytes(n_bytes, bigi.BigEndian, bigi.Unsigned)
      let assert Ok(d_val) =
        bigi.from_bytes(d_bytes, bigi.BigEndian, bigi.Unsigned)
      let assert Ok(p) = bigi.from_bytes(p_bytes, bigi.BigEndian, bigi.Unsigned)
      let assert Ok(q) = bigi.from_bytes(q_bytes, bigi.BigEndian, bigi.Unsigned)
      let assert Ok(dp) =
        bigi.from_bytes(dp_bytes, bigi.BigEndian, bigi.Unsigned)
      let assert Ok(dq) =
        bigi.from_bytes(dq_bytes, bigi.BigEndian, bigi.Unsigned)
      let assert Ok(qi) =
        bigi.from_bytes(qi_bytes, bigi.BigEndian, bigi.Unsigned)

      let one = bigi.from_int(1)

      // Verify modulus size matches requested key size
      assert bit_array.byte_size(n_bytes) * 8 == bits

      // Invariant 1: p × q = n (factorization is correct)
      assert bigi.multiply(p, q) == n_val

      // Invariant 2: dp = d mod (p-1)
      assert dp == bigi.modulo(d_val, bigi.subtract(p, one))

      // Invariant 3: dq = d mod (q-1)
      assert dq == bigi.modulo(d_val, bigi.subtract(q, one))

      // Invariant 4: qi × q ≡ 1 (mod p) (modular inverse is correct)
      assert bigi.modulo(bigi.multiply(qi, q), p) == one

      // Invariant 5: p < q (ordering convention from rsa_crt.gleam:177-179)
      assert bigi.compare(p, q) == order.Lt
    },
  )
}
