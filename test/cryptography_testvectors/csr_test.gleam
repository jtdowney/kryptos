/// Tests for CSR parsing using test vectors from pyca/cryptography.
/// https://github.com/pyca/cryptography/tree/main/vectors/cryptography_vectors/x509/requests
import filepath
import gleam/bit_array
import gleam/list
import kryptos/x509.{
  DnsName, EcPublicKey, EcdsaSha256, Oid, RsaPublicKey, RsaSha1, RsaSha256,
}
import kryptos/x509/csr
import kryptos/x509/test_helpers.{count_oid, has_attr_oid, has_oid}
import simplifile

const vectors_dir = "test/cryptography_testvectors/vectors/x509/requests"

fn vector_path(filename: String) -> String {
  filepath.join(vectors_dir, filename)
}

pub fn parse_rsa_sha256_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("rsa_sha256.pem"))
  let assert Ok(parsed) = csr.from_pem(pem)

  assert csr.version(parsed) == 0
  assert csr.signature_algorithm(parsed) == RsaSha256
  let assert RsaPublicKey(_) = csr.public_key(parsed)

  let subject_str = csr.subject(parsed) |> x509.name_to_string
  assert subject_str == "C=US, ST=Texas, L=Austin, O=PyCA, CN=cryptography.io"
}

pub fn parse_rsa_sha256_der_test() {
  let assert Ok(der) = simplifile.read_bits(vector_path("rsa_sha256.der"))
  let assert Ok(parsed) = csr.from_der(der)

  assert csr.version(parsed) == 0
  assert csr.signature_algorithm(parsed) == RsaSha256
  let assert RsaPublicKey(_) = csr.public_key(parsed)
}

pub fn parse_rsa_sha1_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("rsa_sha1.pem"))
  let assert Ok(parsed) = csr.from_pem(pem)

  assert csr.version(parsed) == 0
  assert csr.signature_algorithm(parsed) == RsaSha1
  let assert RsaPublicKey(_) = csr.public_key(parsed)

  let subject_str = csr.subject(parsed) |> x509.name_to_string
  assert subject_str == "C=US, ST=Texas, L=Austin, O=PyCA, CN=cryptography.io"
}

pub fn parse_rsa_sha1_der_test() {
  let assert Ok(der) = simplifile.read_bits(vector_path("rsa_sha1.der"))
  let assert Ok(parsed) = csr.from_der(der)

  assert csr.version(parsed) == 0
  assert csr.signature_algorithm(parsed) == RsaSha1
}

pub fn parse_ec_sha256_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("ec_sha256.pem"))
  let assert Ok(parsed) = csr.from_pem(pem)

  assert csr.version(parsed) == 0
  assert csr.signature_algorithm(parsed) == EcdsaSha256
  let assert EcPublicKey(_) = csr.public_key(parsed)

  let subject_str = csr.subject(parsed) |> x509.name_to_string
  assert subject_str == "CN=cryptography.io, O=PyCA, C=US, ST=Texas, L=Austin"
}

pub fn parse_ec_sha256_der_test() {
  let assert Ok(der) = simplifile.read_bits(vector_path("ec_sha256.der"))
  let assert Ok(parsed) = csr.from_der(der)

  assert csr.version(parsed) == 0
  assert csr.signature_algorithm(parsed) == EcdsaSha256
  let assert EcPublicKey(_) = csr.public_key(parsed)
}

/// Test PEM with "BEGIN NEW CERTIFICATE REQUEST" header (legacy format)
pub fn parse_ec_sha256_old_header_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("ec_sha256_old_header.pem"))
  let assert Ok(parsed) = csr.from_pem(pem)

  assert csr.version(parsed) == 0
  assert csr.signature_algorithm(parsed) == EcdsaSha256
  let assert EcPublicKey(_) = csr.public_key(parsed)
}

pub fn parse_san_rsa_sha1_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("san_rsa_sha1.pem"))
  let assert Ok(parsed) = csr.from_pem(pem)

  assert csr.version(parsed) == 0
  assert csr.signature_algorithm(parsed) == RsaSha1
  let assert RsaPublicKey(_) = csr.public_key(parsed)

  let sans = csr.subject_alt_names(parsed)
  assert list.length(sans) == 2
  assert list.contains(sans, DnsName("cryptography.io"))
  assert list.contains(sans, DnsName("sub.cryptography.io"))
}

pub fn parse_san_rsa_sha1_der_test() {
  let assert Ok(der) = simplifile.read_bits(vector_path("san_rsa_sha1.der"))
  let assert Ok(parsed) = csr.from_der(der)

  let sans = csr.subject_alt_names(parsed)
  assert list.length(sans) == 2
  assert list.contains(sans, DnsName("cryptography.io"))
  assert list.contains(sans, DnsName("sub.cryptography.io"))
}

pub fn parse_challenge_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("challenge.pem"))
  let assert Ok(parsed) = csr.from_pem(pem)

  assert csr.version(parsed) == 0
  let assert RsaPublicKey(_) = csr.public_key(parsed)
  assert has_attr_oid(csr.attributes(parsed), [1, 2, 840, 113_549, 1, 9, 7])
}

pub fn parse_challenge_unstructured_pem_test() {
  let assert Ok(pem) =
    simplifile.read(vector_path("challenge-unstructured.pem"))
  let assert Ok(parsed) = csr.from_pem(pem)

  assert csr.version(parsed) == 0
  let assert RsaPublicKey(_) = csr.public_key(parsed)

  let attrs = csr.attributes(parsed)
  assert has_attr_oid(attrs, [1, 2, 840, 113_549, 1, 9, 7])
  assert has_attr_oid(attrs, [1, 2, 840, 113_549, 1, 9, 2])
}

pub fn parse_basic_constraints_pem_unverified_test() {
  let assert Ok(pem) = simplifile.read(vector_path("basic_constraints.pem"))
  let assert Ok(parsed) = csr.from_pem_unverified(pem)

  assert csr.version(parsed) == 0
  assert has_oid(csr.extensions(parsed), [2, 5, 29, 19])
}

pub fn parse_unsupported_extension_pem_unverified_test() {
  let assert Ok(pem) = simplifile.read(vector_path("unsupported_extension.pem"))
  let assert Ok(parsed) = csr.from_pem_unverified(pem)

  assert csr.version(parsed) == 0

  let exts = csr.extensions(parsed)
  assert list.length(exts) >= 1
}

pub fn parse_unsupported_extension_critical_pem_unverified_test() {
  let assert Ok(pem) =
    simplifile.read(vector_path("unsupported_extension_critical.pem"))
  let assert Ok(parsed) = csr.from_pem_unverified(pem)

  assert csr.version(parsed) == 0
  let exts = csr.extensions(parsed)
  assert list.length(exts) >= 1
}

pub fn parse_two_basic_constraints_pem_unverified_test() {
  let assert Ok(pem) = simplifile.read(vector_path("two_basic_constraints.pem"))
  let assert Ok(parsed) = csr.from_pem_unverified(pem)

  assert csr.version(parsed) == 0
  assert count_oid(csr.extensions(parsed), [2, 5, 29, 19]) == 2
}

pub fn parse_freeipa_bad_critical_pem_unverified_test() {
  let assert Ok(pem) = simplifile.read(vector_path("freeipa-bad-critical.pem"))
  let assert Ok(parsed) = csr.from_pem_unverified(pem)

  assert csr.version(parsed) == 0
}

pub fn parse_dsa_sha1_fails_with_unsupported_key_type_test() {
  let assert Ok(pem) = simplifile.read(vector_path("dsa_sha1.pem"))
  let result = csr.from_pem(pem)

  assert result == Error(csr.UnsupportedKeyType(Oid([1, 2, 840, 10_040, 4, 1])))
}

pub fn parse_dsa_sha1_der_fails_with_unsupported_key_type_test() {
  let assert Ok(der) = simplifile.read_bits(vector_path("dsa_sha1.der"))
  let result = csr.from_der(der)

  assert result == Error(csr.UnsupportedKeyType(Oid([1, 2, 840, 10_040, 4, 1])))
}

pub fn parse_rsa_md4_fails_with_unsupported_signature_algorithm_test() {
  let assert Ok(pem) = simplifile.read(vector_path("rsa_md4.pem"))
  let result = csr.from_pem(pem)

  assert result
    == Error(
      csr.UnsupportedSignatureAlgorithm(Oid([1, 2, 840, 113_549, 1, 1, 3])),
    )
}

pub fn parse_rsa_md4_der_fails_with_unsupported_signature_algorithm_test() {
  let assert Ok(der) = simplifile.read_bits(vector_path("rsa_md4.der"))
  let result = csr.from_der(der)

  assert result
    == Error(
      csr.UnsupportedSignatureAlgorithm(Oid([1, 2, 840, 113_549, 1, 1, 3])),
    )
}

pub fn parse_invalid_signature_fails_verification_test() {
  let assert Ok(pem) = simplifile.read(vector_path("invalid_signature.pem"))
  let result = csr.from_pem(pem)

  assert result == Error(csr.SignatureVerificationFailed)
}

pub fn parse_invalid_signature_succeeds_unverified_test() {
  let assert Ok(pem) = simplifile.read(vector_path("invalid_signature.pem"))
  let assert Ok(parsed) = csr.from_pem_unverified(pem)

  assert csr.version(parsed) == 0
  let assert RsaPublicKey(_) = csr.public_key(parsed)
}

pub fn parse_basic_constraints_fails_verification_test() {
  let assert Ok(pem) = simplifile.read(vector_path("basic_constraints.pem"))
  let result = csr.from_pem(pem)

  assert result == Error(csr.SignatureVerificationFailed)
}

pub fn parse_unsupported_extension_fails_verification_test() {
  let assert Ok(pem) = simplifile.read(vector_path("unsupported_extension.pem"))
  let result = csr.from_pem(pem)

  assert result == Error(csr.SignatureVerificationFailed)
}

pub fn parse_two_basic_constraints_fails_verification_test() {
  let assert Ok(pem) = simplifile.read(vector_path("two_basic_constraints.pem"))
  let result = csr.from_pem(pem)

  assert result == Error(csr.SignatureVerificationFailed)
}

pub fn parse_bad_version_fails_test() {
  let assert Ok(pem) = simplifile.read(vector_path("bad-version.pem"))
  let result = csr.from_pem(pem)

  assert result == Error(csr.UnsupportedVersion(1))
}

pub fn parse_challenge_invalid_der_unverified_test() {
  let assert Ok(der) =
    simplifile.read_bits(vector_path("challenge-invalid.der"))
  let assert Ok(parsed) = csr.from_der_unverified(der)

  assert csr.version(parsed) == 0
}

pub fn parse_challenge_multi_valued_der_unverified_test() {
  let assert Ok(der) =
    simplifile.read_bits(vector_path("challenge-multi-valued.der"))
  let assert Ok(parsed) = csr.from_der_unverified(der)

  assert csr.version(parsed) == 0
}

pub fn parse_long_form_attribute_pem_unverified_test() {
  let assert Ok(pem) = simplifile.read(vector_path("long-form-attribute.pem"))
  let assert Ok(parsed) = csr.from_pem_unverified(pem)

  assert csr.version(parsed) == 0
}

pub fn parse_zero_element_attribute_pem_unverified_test() {
  let assert Ok(pem) =
    simplifile.read(vector_path("zero-element-attribute.pem"))
  let assert Ok(parsed) = csr.from_pem_unverified(pem)

  assert csr.version(parsed) == 0
}

fn assert_pem_der_consistency(basename: String) {
  let assert Ok(pem) = simplifile.read(vector_path(basename <> ".pem"))
  let assert Ok(der) = simplifile.read_bits(vector_path(basename <> ".der"))

  let assert Ok(parsed_pem) = csr.from_pem(pem)
  let assert Ok(parsed_der) = csr.from_der(der)

  assert csr.to_der(parsed_pem) == csr.to_der(parsed_der)
}

pub fn rsa_sha256_pem_der_consistency_test() {
  assert_pem_der_consistency("rsa_sha256")
}

pub fn ec_sha256_pem_der_consistency_test() {
  assert_pem_der_consistency("ec_sha256")
}

pub fn san_rsa_sha1_pem_der_consistency_test() {
  assert_pem_der_consistency("san_rsa_sha1")
}

fn assert_der_roundtrip(basename: String) {
  let assert Ok(der) = simplifile.read_bits(vector_path(basename <> ".der"))
  let assert Ok(parsed) = csr.from_der(der)
  assert csr.to_der(parsed) == der
}

pub fn rsa_sha256_roundtrip_test() {
  assert_der_roundtrip("rsa_sha256")
}

pub fn ec_sha256_roundtrip_test() {
  assert_der_roundtrip("ec_sha256")
}

pub fn san_rsa_sha1_roundtrip_test() {
  assert_der_roundtrip("san_rsa_sha1")
}

pub fn challenge_roundtrip_test() {
  let assert Ok(pem) = simplifile.read(vector_path("challenge.pem"))
  let assert Ok(parsed) = csr.from_pem(pem)

  let repem = csr.to_pem(parsed)
  let assert Ok(reparsed) = csr.from_pem(repem)

  assert csr.version(reparsed) == csr.version(parsed)
  assert csr.signature_algorithm(reparsed) == csr.signature_algorithm(parsed)
  assert bit_array.byte_size(csr.to_der(reparsed))
    == bit_array.byte_size(csr.to_der(parsed))
}
