/// Tests for certificate parsing using test vectors from pyca/cryptography.
/// https://github.com/pyca/cryptography/tree/main/vectors/cryptography_vectors/x509
import filepath
import gleam/list
import gleam/option.{Some}
import gleam/string
import kryptos/x509.{
  CrlSign, DigitalSignature, DnsName, EcPublicKey, EdPublicKey, Email, IpAddress,
  KeyCertSign, Oid, RsaPublicKey, ServerAuth, XdhPublicKey,
}
import kryptos/x509/certificate
import kryptos/x509/test_helpers.{has_oid}
import simplifile

const vectors_dir = "test/cryptography_testvectors/vectors/x509/certificates"

fn vector_path(filename: String) -> String {
  filepath.join(vectors_dir, filename)
}

fn custom_path(filename: String) -> String {
  vectors_dir |> filepath.join("custom") |> filepath.join(filename)
}

fn ed25519_path(filename: String) -> String {
  vectors_dir |> filepath.join("ed25519") |> filepath.join(filename)
}

fn ed448_path(filename: String) -> String {
  vectors_dir |> filepath.join("ed448") |> filepath.join(filename)
}

pub fn parse_cryptography_io_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("cryptography.io.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert certificate.signature_algorithm(parsed) == x509.RsaSha256
  let assert RsaPublicKey(_) = certificate.public_key(parsed)

  let subject_str = certificate.subject(parsed) |> x509.name_to_string
  assert string.contains(subject_str, "CN=www.cryptography.io")
  assert string.contains(subject_str, "OU=GT48742965")
}

pub fn parse_ecdsa_root_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("ecdsa_root.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert certificate.signature_algorithm(parsed) == x509.EcdsaSha384
  let assert EcPublicKey(_) = certificate.public_key(parsed)

  let subject_str = certificate.subject(parsed) |> x509.name_to_string
  assert string.contains(subject_str, "CN=DigiCert Global Root G3")
  assert string.contains(subject_str, "O=DigiCert Inc")
  assert string.contains(subject_str, "C=US")

  let assert Ok(bc) = certificate.basic_constraints(parsed)
  assert bc.ca

  let ku = certificate.key_usage(parsed)
  assert list.contains(ku, DigitalSignature)
  assert list.contains(ku, KeyCertSign)
  assert list.contains(ku, CrlSign)
}

/// v1_cert.pem uses MD5 signature which is not supported
pub fn parse_v1_cert_pem_fails_unsupported_signature_test() {
  let assert Ok(pem) = simplifile.read(vector_path("v1_cert.pem"))
  let result = certificate.from_pem(pem)

  assert result
    == Error(
      certificate.UnsupportedAlgorithm(Oid([1, 2, 840, 113_549, 1, 1, 4])),
    )
}

pub fn parse_letsencrypt_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("letsencryptx3.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert certificate.signature_algorithm(parsed) == x509.RsaSha256
  let assert RsaPublicKey(_) = certificate.public_key(parsed)

  let assert Ok(bc) = certificate.basic_constraints(parsed)
  assert bc.ca
  assert bc.path_len_constraint == Some(0)
}

pub fn parse_wildcard_san_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("wildcard_san.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let assert RsaPublicKey(_) = certificate.public_key(parsed)

  let sans = certificate.subject_alt_names(parsed)
  assert list.contains(sans, DnsName("*.langui.sh"))
  assert list.contains(sans, DnsName("langui.sh"))
}

pub fn parse_chain_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("cryptography.io.chain.pem"))
  let assert Ok([parsed, ..]) = certificate.from_pem(pem)

  // Verify we got the leaf certificate (first in chain)
  assert certificate.version(parsed) == 2
  let assert RsaPublicKey(_) = certificate.public_key(parsed)
}

/// "BEGIN X509 CERTIFICATE" header is not supported (only "BEGIN CERTIFICATE")
/// Returns empty list since no matching certificate blocks found
pub fn parse_old_header_pem_returns_empty_list_test() {
  let assert Ok(pem) =
    simplifile.read(vector_path("cryptography.io.old_header.pem"))
  let result = certificate.from_pem(pem)

  assert result == Ok([])
}

/// e-trust.ru.der uses GOST signature algorithm which is not supported
pub fn parse_e_trust_der_fails_unsupported_signature_test() {
  let assert Ok(der) = simplifile.read_bits(vector_path("e-trust.ru.der"))
  let result = certificate.from_der(der)

  assert result
    == Error(certificate.UnsupportedAlgorithm(Oid([1, 2, 643, 2, 2, 3])))
}

/// ed25519-rfc8410.pem is signed with Ed25519 but contains an X25519 public key
/// (for key agreement per RFC 8410). The certificate is valid.
pub fn parse_ed25519_rfc8410_pem_test() {
  let assert Ok(pem) = simplifile.read(ed25519_path("ed25519-rfc8410.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert certificate.signature_algorithm(parsed) == x509.Ed25519
  let assert XdhPublicKey(_) = certificate.public_key(parsed)

  let subject_str = certificate.subject(parsed) |> x509.name_to_string
  assert string.contains(subject_str, "CN=IETF Test Demo")
}

pub fn parse_ed25519_root_pem_test() {
  let assert Ok(pem) = simplifile.read(ed25519_path("root-ed25519.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert certificate.signature_algorithm(parsed) == x509.Ed25519
  let assert EdPublicKey(_) = certificate.public_key(parsed)

  let assert Ok(bc) = certificate.basic_constraints(parsed)
  assert bc.ca
}

pub fn parse_ed25519_server_cert_pem_test() {
  let assert Ok(pem) = simplifile.read(ed25519_path("server-ed25519-cert.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let assert EdPublicKey(_) = certificate.public_key(parsed)

  let sans = certificate.subject_alt_names(parsed)
  assert list.contains(sans, DnsName("Ed25519"))

  let eku = certificate.extended_key_usage(parsed)
  assert list.contains(eku, ServerAuth)
}

pub fn parse_ed448_root_pem_test() {
  let assert Ok(pem) = simplifile.read(ed448_path("root-ed448.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert certificate.signature_algorithm(parsed) == x509.Ed448
  let assert EdPublicKey(_) = certificate.public_key(parsed)

  let assert Ok(bc) = certificate.basic_constraints(parsed)
  assert bc.ca
}

pub fn parse_ed448_server_cert_pem_test() {
  let assert Ok(pem) = simplifile.read(ed448_path("server-ed448-cert.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let assert EdPublicKey(_) = certificate.public_key(parsed)

  let sans = certificate.subject_alt_names(parsed)
  assert list.contains(sans, DnsName("Ed448"))
}

pub fn parse_san_email_dns_ip_dirname_uri_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("san_email_dns_ip_dirname_uri.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let assert RsaPublicKey(_) = certificate.public_key(parsed)

  let sans = certificate.subject_alt_names(parsed)
  assert list.contains(sans, Email("user@cryptography.io"))
  assert list.contains(sans, DnsName("cryptography.io"))
  assert list.contains(sans, IpAddress(<<127, 0, 0, 1>>))
}

pub fn parse_san_ipaddr_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("san_ipaddr.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let sans = certificate.subject_alt_names(parsed)
  assert list.contains(sans, IpAddress(<<127, 0, 0, 1>>))
}

pub fn parse_san_rfc822_names_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("san_rfc822_names.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let sans = certificate.subject_alt_names(parsed)
  assert list.contains(sans, Email("email"))
  assert list.contains(sans, Email("email <email>"))
  assert list.contains(sans, Email("email <email@email>"))
  assert list.contains(sans, Email("email <email@xn--eml-vla4c.com>"))
  assert list.contains(sans, Email("myemail:"))
  assert list.length(sans) == 5
}

pub fn parse_all_key_usages_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("all_key_usages.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2

  let ku = certificate.key_usage(parsed)
  assert list.contains(ku, DigitalSignature)
  assert list.contains(ku, KeyCertSign)
  assert list.contains(ku, CrlSign)
}

pub fn parse_extended_key_usage_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("extended_key_usage.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2

  let eku = certificate.extended_key_usage(parsed)
  assert list.contains(eku, ServerAuth)
}

pub fn parse_basic_constraints_not_critical_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("basic_constraints_not_critical.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let assert Ok(bc) = certificate.basic_constraints(parsed)
  assert !bc.ca
}

pub fn parse_bc_path_length_zero_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("bc_path_length_zero.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let assert Ok(bc) = certificate.basic_constraints(parsed)
  assert bc.ca
  assert bc.path_len_constraint == Some(0)
}

pub fn parse_no_sans_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("no_sans.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert list.is_empty(certificate.subject_alt_names(parsed))
}

pub fn parse_utf8_common_name_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("utf8_common_name.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 0

  let subject_str = certificate.subject(parsed) |> x509.name_to_string
  assert string.contains(subject_str, "UTF8")
}

pub fn parse_authority_key_identifier_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("authority_key_identifier.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let assert Ok(_aki) = certificate.authority_key_identifier(parsed)
}

pub fn parse_unsupported_extension_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("unsupported_extension.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert list.length(certificate.extensions(parsed)) >= 1
}

/// Note: invalid_signature_cert.pem name refers to CRL signature testing,
/// the certificate itself has a valid self-signature
pub fn parse_invalid_signature_cert_parses_successfully_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("invalid_signature_cert.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 0
  let assert RsaPublicKey(_) = certificate.public_key(parsed)
}

pub fn parse_valid_signature_cert_passes_verification_test() {
  let assert Ok(pem) = simplifile.read(custom_path("valid_signature_cert.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  let assert Ok(_) = certificate.verify_self_signed(parsed)
}

/// DSA certificates fail because DSA signature algorithm is parsed first
pub fn parse_dsa_cert_fails_with_unsupported_signature_algorithm_test() {
  let assert Ok(pem) = simplifile.read(custom_path("dsa_selfsigned_ca.pem"))
  let result = certificate.from_pem(pem)

  assert result
    == Error(certificate.UnsupportedAlgorithm(Oid([1, 2, 840, 10_040, 4, 3])))
}

fn assert_pem_der_roundtrip(pem_path: String) {
  let assert Ok(pem) = simplifile.read(pem_path)
  let assert Ok([parsed]) = certificate.from_pem(pem)

  let der = certificate.to_der(parsed)
  let assert Ok(reparsed) = certificate.from_der(der)

  assert certificate.version(reparsed) == certificate.version(parsed)
  assert certificate.signature_algorithm(reparsed)
    == certificate.signature_algorithm(parsed)
}

pub fn cryptography_io_roundtrip_test() {
  assert_pem_der_roundtrip(vector_path("cryptography.io.pem"))
}

pub fn ecdsa_root_roundtrip_test() {
  assert_pem_der_roundtrip(vector_path("ecdsa_root.pem"))
}

pub fn letsencrypt_roundtrip_test() {
  assert_pem_der_roundtrip(vector_path("letsencryptx3.pem"))
}

pub fn ed25519_roundtrip_test() {
  assert_pem_der_roundtrip(ed25519_path("root-ed25519.pem"))
}

pub fn ed448_roundtrip_test() {
  assert_pem_der_roundtrip(ed448_path("root-ed448.pem"))
}

pub fn parse_accvraiz1_root_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("accvraiz1.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert certificate.signature_algorithm(parsed) == x509.RsaSha1
  let assert RsaPublicKey(_) = certificate.public_key(parsed)

  let subject_str = certificate.subject(parsed) |> x509.name_to_string
  assert string.contains(subject_str, "CN=ACCVRAIZ1")
  assert string.contains(subject_str, "C=ES")
}

/// Contains critical Name Constraints (2.5.29.30) - rejected per RFC 5280
pub fn parse_department_of_state_root_pem_rejects_critical_extension_test() {
  let assert Ok(pem) =
    simplifile.read(vector_path("department-of-state-root.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 30])))
}

pub fn parse_rapidssl_sha256_ca_g3_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("rapidssl_sha256_ca_g3.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert certificate.signature_algorithm(parsed) == x509.RsaSha256
  let assert RsaPublicKey(_) = certificate.public_key(parsed)

  let subject_str = certificate.subject(parsed) |> x509.name_to_string
  assert string.contains(subject_str, "RapidSSL")
}

/// verisign_md2_root.pem uses MD2 which is not supported
pub fn parse_verisign_md2_root_pem_fails_unsupported_signature_test() {
  let assert Ok(pem) = simplifile.read(vector_path("verisign_md2_root.pem"))
  let result = certificate.from_pem(pem)

  assert result
    == Error(
      certificate.UnsupportedAlgorithm(Oid([1, 2, 840, 113_549, 1, 1, 2])),
    )
}

pub fn parse_chain_with_garbage_pem_test() {
  let assert Ok(pem) =
    simplifile.read(vector_path("cryptography.io.chain_with_garbage.pem"))
  let assert Ok([parsed, ..]) = certificate.from_pem(pem)

  // Verify we got the leaf certificate (first in chain)
  assert certificate.version(parsed) == 2
  let assert RsaPublicKey(_) = certificate.public_key(parsed)
}

pub fn parse_with_garbage_pem_test() {
  let assert Ok(pem) =
    simplifile.read(vector_path("cryptography.io.with_garbage.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_with_headers_pem_test() {
  let assert Ok(pem) =
    simplifile.read(vector_path("cryptography.io.with_headers.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_badssl_sct_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("badssl-sct.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert certificate.signature_algorithm(parsed) == x509.RsaSha256
  let assert RsaPublicKey(_) = certificate.public_key(parsed)

  let subject_str = certificate.subject(parsed) |> x509.name_to_string
  assert string.contains(subject_str, "badssl.com")
}

pub fn parse_cryptography_scts_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("cryptography-scts.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let assert RsaPublicKey(_) = certificate.public_key(parsed)
}

/// Precerts contain CT Poison (1.3.6.1.4.1.11129.2.4.3) marked critical - rejected per RFC 5280
pub fn parse_cryptography_io_precert_pem_rejects_critical_extension_test() {
  let assert Ok(pem) =
    simplifile.read(vector_path("cryptography.io.precert.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(
      certificate.UnrecognizedCriticalExtension(
        Oid([1, 3, 6, 1, 4, 1, 11_129, 2, 4, 3]),
      ),
    )
}

pub fn parse_bigoid_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("bigoid.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

/// unique_identifier.pem contains x500UniqueIdentifier in DN which uses
/// an unsupported ASN.1 type (BIT STRING instead of string types)
pub fn parse_unique_identifier_pem_fails_structure_test() {
  let assert Ok(pem) = simplifile.read(vector_path("unique_identifier.pem"))
  let result = certificate.from_pem(pem)

  assert result == Error(certificate.ParseError)
}

pub fn parse_utf8_dnsname_pem_test() {
  let assert Ok(pem) = simplifile.read(vector_path("utf8-dnsname.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let sans = certificate.subject_alt_names(parsed)
  assert list.contains(sans, DnsName("partner.biztositas.hu"))
  assert list.contains(sans, DnsName("biztositas.hu"))
  assert list.contains(sans, DnsName("xn--biztosts-fza2j.hu"))
}

pub fn parse_tls_feature_ocsp_staple_pem_test() {
  let assert Ok(pem) =
    simplifile.read(vector_path("tls-feature-ocsp-staple.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let assert RsaPublicKey(_) = certificate.public_key(parsed)
}

pub fn parse_san_dirname_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("san_dirname.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let sans = certificate.subject_alt_names(parsed)
  assert list.length(sans) == 1
  let assert [x509.DirectoryName(_)] = sans
}

pub fn parse_san_empty_hostname_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("san_empty_hostname.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_san_idna_names_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("san_idna_names.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let sans = certificate.subject_alt_names(parsed)
  assert list.contains(sans, Email("email@xn--80ato2c.cryptography"))
  assert list.contains(sans, DnsName("xn--80ato2c.cryptography"))
  let has_uri =
    list.any(sans, fn(san) {
      case san {
        x509.Uri(_) -> True
        _ -> False
      }
    })
  assert has_uri
  assert list.length(sans) == 3
}

pub fn parse_san_idna2003_dnsname_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("san_idna2003_dnsname.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_san_other_name_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("san_other_name.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let sans = certificate.subject_alt_names(parsed)
  assert list.length(sans) == 1
  let assert [x509.OtherName(x509.Oid([1, 2, 3, 4]), _value)] = sans
}

pub fn parse_san_registered_id_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("san_registered_id.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let sans = certificate.subject_alt_names(parsed)
  assert list.length(sans) == 1
  let assert [x509.RegisteredId(x509.Oid([1, 2, 3, 4]))] = sans
}

pub fn parse_san_rfc822_idna_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("san_rfc822_idna.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_san_uri_with_port_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("san_uri_with_port.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_san_wildcard_idna_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("san_wildcard_idna.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

/// all_supported_names.pem has many DN attributes but no SANs
pub fn parse_all_supported_names_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("all_supported_names.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let assert RsaPublicKey(_) = certificate.public_key(parsed)

  assert list.is_empty(certificate.subject_alt_names(parsed))
}

pub fn parse_aia_ca_issuers_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("aia_ca_issuers.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [1, 3, 6, 1, 5, 5, 7, 1, 1])
}

pub fn parse_aia_ocsp_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("aia_ocsp.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [1, 3, 6, 1, 5, 5, 7, 1, 1])
}

pub fn parse_aia_ocsp_ca_issuers_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("aia_ocsp_ca_issuers.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [1, 3, 6, 1, 5, 5, 7, 1, 1])
}

pub fn parse_authority_key_identifier_no_keyid_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("authority_key_identifier_no_keyid.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let assert Ok(aki) = certificate.authority_key_identifier(parsed)
  // This cert has AKI without keyIdentifier (just issuer and serial)
  assert aki.key_identifier == option.None
}

pub fn parse_cdp_all_reasons_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("cdp_all_reasons.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [2, 5, 29, 31])
}

pub fn parse_cdp_crl_issuer_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("cdp_crl_issuer.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [2, 5, 29, 31])
}

pub fn parse_cdp_empty_hostname_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("cdp_empty_hostname.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_cdp_fullname_reasons_crl_issuer_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("cdp_fullname_reasons_crl_issuer.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [2, 5, 29, 31])
}

pub fn parse_cdp_reason_aa_compromise_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("cdp_reason_aa_compromise.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_cp_cps_uri_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("cp_cps_uri.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [2, 5, 29, 32])
}

pub fn parse_cp_user_notice_no_explicit_text_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("cp_user_notice_no_explicit_text.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_cp_user_notice_with_explicit_text_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("cp_user_notice_with_explicit_text.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_cp_user_notice_with_notice_reference_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("cp_user_notice_with_notice_reference.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

/// Name Constraints (2.5.29.30) is typically marked critical - rejected per RFC 5280
pub fn parse_nc_permitted_pem_rejects_critical_extension_test() {
  let assert Ok(pem) = simplifile.read(custom_path("nc_permitted.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 30])))
}

/// Name Constraints (2.5.29.30) is typically marked critical - rejected per RFC 5280
pub fn parse_nc_permitted_2_pem_rejects_critical_extension_test() {
  let assert Ok(pem) = simplifile.read(custom_path("nc_permitted_2.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 30])))
}

/// Name Constraints (2.5.29.30) is typically marked critical - rejected per RFC 5280
pub fn parse_nc_excluded_pem_rejects_critical_extension_test() {
  let assert Ok(pem) = simplifile.read(custom_path("nc_excluded.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 30])))
}

/// Name Constraints (2.5.29.30) is typically marked critical - rejected per RFC 5280
pub fn parse_nc_permitted_excluded_pem_rejects_critical_extension_test() {
  let assert Ok(pem) = simplifile.read(custom_path("nc_permitted_excluded.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 30])))
}

/// Name Constraints (2.5.29.30) is typically marked critical - rejected per RFC 5280
pub fn parse_nc_permitted_excluded_2_pem_rejects_critical_extension_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("nc_permitted_excluded_2.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 30])))
}

/// Name Constraints (2.5.29.30) is typically marked critical - rejected per RFC 5280
pub fn parse_nc_single_ip_netmask_pem_rejects_critical_extension_test() {
  let assert Ok(pem) = simplifile.read(custom_path("nc_single_ip_netmask.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 30])))
}

/// Policy Constraints (2.5.29.36) is marked critical - rejected per RFC 5280
pub fn parse_pc_inhibit_require_pem_rejects_critical_extension_test() {
  let assert Ok(pem) = simplifile.read(custom_path("pc_inhibit_require.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 36])))
}

/// Policy Constraints (2.5.29.36) is marked critical - rejected per RFC 5280
pub fn parse_pc_inhibit_pem_rejects_critical_extension_test() {
  let assert Ok(pem) = simplifile.read(custom_path("pc_inhibit.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 36])))
}

/// Policy Constraints (2.5.29.36) is marked critical - rejected per RFC 5280
pub fn parse_pc_require_pem_rejects_critical_extension_test() {
  let assert Ok(pem) = simplifile.read(custom_path("pc_require.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 36])))
}

/// Policy Constraints (2.5.29.36) is marked critical - rejected per RFC 5280
pub fn parse_policy_constraints_explicit_pem_rejects_critical_extension_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("policy_constraints_explicit.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 36])))
}

/// Inhibit Any Policy (2.5.29.54) is marked critical - rejected per RFC 5280
pub fn parse_inhibit_any_policy_5_pem_rejects_critical_extension_test() {
  let assert Ok(pem) = simplifile.read(custom_path("inhibit_any_policy_5.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 54])))
}

pub fn parse_sia_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("sia.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [1, 3, 6, 1, 5, 5, 7, 1, 11])
}

pub fn parse_ian_uri_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("ian_uri.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [2, 5, 29, 18])
}

pub fn parse_ocsp_nocheck_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("ocsp_nocheck.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [1, 3, 6, 1, 5, 5, 7, 48, 1, 5])
}

pub fn parse_freshestcrl_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("freshestcrl.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [2, 5, 29, 46])
}

pub fn parse_private_key_usage_period_both_dates_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("private_key_usage_period_both_dates.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  assert has_oid(certificate.extensions(parsed), [2, 5, 29, 16])
}

pub fn parse_private_key_usage_period_only_not_after_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("private_key_usage_period_only_not_after.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_private_key_usage_period_only_not_before_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("private_key_usage_period_only_not_before.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_rsa_pss_pem_fails_unsupported_signature_test() {
  let assert Ok(pem) = simplifile.read(custom_path("rsa_pss.pem"))
  let result = certificate.from_pem(pem)

  assert result
    == Error(
      certificate.UnsupportedAlgorithm(Oid([1, 2, 840, 113_549, 1, 1, 10])),
    )
}

pub fn parse_rsa_pss_cert_pem_fails_unsupported_signature_test() {
  let assert Ok(pem) = simplifile.read(custom_path("rsa_pss_cert.pem"))
  let result = certificate.from_pem(pem)

  assert result
    == Error(
      certificate.UnsupportedAlgorithm(Oid([1, 2, 840, 113_549, 1, 1, 10])),
    )
}

pub fn parse_rsa_pss_sha256_no_null_pem_fails_unsupported_signature_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("rsa_pss_sha256_no_null.pem"))
  let result = certificate.from_pem(pem)

  assert result
    == Error(
      certificate.UnsupportedAlgorithm(Oid([1, 2, 840, 113_549, 1, 1, 10])),
    )
}

/// Contains critical CRL Distribution Points (2.5.29.31) - rejected per RFC 5280
pub fn parse_negative_serial_pem_rejects_critical_extension_test() {
  let assert Ok(pem) = simplifile.read(custom_path("negative_serial.pem"))
  let result = certificate.from_pem(pem)
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([2, 5, 29, 31])))
}

pub fn parse_post2000utctime_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("post2000utctime.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_empty_eku_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("empty-eku.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
  let eku = certificate.extended_key_usage(parsed)
  assert list.is_empty(eku)
}

pub fn parse_ekucrit_testuser_cert_pem_test() {
  let assert Ok(pem) = simplifile.read(custom_path("ekucrit-testuser-cert.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_ms_certificate_template_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("ms-certificate-template.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_two_basic_constraints_pem_rejects_duplicate_extension_test() {
  let assert Ok(pem) = simplifile.read(custom_path("two_basic_constraints.pem"))
  assert certificate.from_pem(pem) == Error(certificate.ParseError)
}

pub fn parse_unsupported_extension_2_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("unsupported_extension_2.pem"))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

/// RFC 5280 §4.2: MUST reject certificates with unrecognized critical extensions
pub fn parse_unsupported_extension_critical_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path("unsupported_extension_critical.pem"))
  let result = certificate.from_pem(pem)
  // OID 1.2.3.4 is unknown and marked critical - must be rejected per RFC 5280
  assert result
    == Error(certificate.UnrecognizedCriticalExtension(Oid([1, 2, 3, 4])))
}

pub fn parse_admissions_extension_authority_not_provided_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path(
      "admissions_extension_authority_not_provided.pem",
    ))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn parse_admissions_extension_optional_data_not_provided_pem_test() {
  let assert Ok(pem) =
    simplifile.read(custom_path(
      "admissions_extension_optional_data_not_provided.pem",
    ))
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2
}

pub fn accvraiz1_roundtrip_test() {
  assert_pem_der_roundtrip(vector_path("accvraiz1.pem"))
}

pub fn rapidssl_roundtrip_test() {
  assert_pem_der_roundtrip(vector_path("rapidssl_sha256_ca_g3.pem"))
}

pub fn badssl_sct_roundtrip_test() {
  assert_pem_der_roundtrip(vector_path("badssl-sct.pem"))
}
