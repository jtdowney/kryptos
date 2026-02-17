//// X.509 Certificate generation and parsing.
////
//// This module provides a builder for creating X.509 certificates.
//// Certificates can be self-signed. CA-signing is not currently supported.
////
//// ## Example
////
//// ```gleam
//// import gleam/option.{None}
//// import gleam/time/duration
//// import gleam/time/timestamp
//// import kryptos/ec
//// import kryptos/hash
//// import kryptos/x509
//// import kryptos/x509/certificate
////
//// let #(private_key, _) = ec.generate_key_pair(ec.P256)
////
//// let subject =
////   x509.name([
////     x509.cn("example.com"),
////     x509.organization("Acme Inc"),
////   ])
////
//// let now = timestamp.system_time()
//// // 86,400 seconds per day per CA/Browser Forum definition
//// let one_year_later = timestamp.add(now, duration.seconds(86_400 * 365))
//// let validity = x509.Validity(not_before: now, not_after: one_year_later)
////
//// let assert Ok(builder) =
////   certificate.new()
////   |> certificate.with_subject(subject)
////   |> certificate.with_validity(validity)
////   |> certificate.with_basic_constraints(ca: False, path_len_constraint: None)
////   |> certificate.with_key_usage(x509.DigitalSignature)
////   |> certificate.with_extended_key_usage(x509.ServerAuth)
////   |> certificate.with_dns_name("example.com")
////
//// let assert Ok(cert) =
////   certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)
//// ```
////
//// ## Parsing Certificates
////
//// ```gleam
//// import kryptos/x509/certificate
////
//// let pem = "-----BEGIN CERTIFICATE-----
//// MIIBkTCB+wIJAK...
//// -----END CERTIFICATE-----"
////
//// let assert Ok([cert]) = certificate.from_pem(pem)
////
//// // Access certificate fields
//// let subject = certificate.subject(cert)
//// let validity = certificate.validity(cert)
//// let public_key = certificate.public_key(cert)
////
//// // Verify a self-signed certificate
//// let assert Ok(Nil) = certificate.verify_self_signed(cert)
//// ```

import bitty as p
import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set.{type Set}
import kryptos/crypto
import kryptos/ec
import kryptos/ecdsa
import kryptos/eddsa
import kryptos/hash.{type HashAlgorithm}
import kryptos/internal/der
import kryptos/internal/utils.{parse_ip}
import kryptos/internal/x509.{type SigAlgInfo} as x509_internal
import kryptos/rsa
import kryptos/x509
import kryptos/xdh

const oid_authority_key_identifier = x509.Oid([2, 5, 29, 35])

const oid_basic_constraints = x509.Oid([2, 5, 29, 19])

const oid_client_auth = x509.Oid([1, 3, 6, 1, 5, 5, 7, 3, 2])

const oid_code_signing = x509.Oid([1, 3, 6, 1, 5, 5, 7, 3, 3])

const oid_email_protection = x509.Oid([1, 3, 6, 1, 5, 5, 7, 3, 4])

const oid_extended_key_usage = x509.Oid([2, 5, 29, 37])

const oid_key_usage = x509.Oid([2, 5, 29, 15])

const oid_ocsp_signing = x509.Oid([1, 3, 6, 1, 5, 5, 7, 3, 9])

const oid_server_auth = x509.Oid([1, 3, 6, 1, 5, 5, 7, 3, 1])

const oid_subject_key_identifier = x509.Oid([2, 5, 29, 14])

const pem_begin = "-----BEGIN CERTIFICATE-----"

const pem_end = "-----END CERTIFICATE-----"

/// Phantom type marker for certificates created via the builder.
pub type Built

/// Phantom type marker for certificates parsed from PEM/DER.
pub type Parsed

/// Error type for certificate parsing failures.
pub type CertificateError {
  /// Failed to parse the certificate data.
  ParseError

  /// The certificate uses an algorithm or key type that is not supported.
  UnsupportedAlgorithm(x509.Oid)

  /// Cryptographic signature verification failed.
  SignatureVerificationFailed

  /// The certificate contains an unrecognized extension marked as critical.
  ///
  /// Per RFC 5280 §4.2, certificates with unknown critical extensions must
  /// be rejected. Non-critical unknown extensions are allowed.
  UnrecognizedCriticalExtension(x509.Oid)
}

type ExtensionsAcc {
  ExtensionsAcc(
    basic_constraints: Option(x509.BasicConstraints),
    key_usage: List(x509.KeyUsage),
    extended_key_usage: List(x509.ExtendedKeyUsage),
    subject_alt_names: List(x509.SubjectAltName),
    subject_key_identifier: Option(BitArray),
    authority_key_identifier: Option(x509.AuthorityKeyIdentifier),
    raw: List(#(x509.Oid, Bool, BitArray)),
    seen_oids: Set(List(Int)),
  )
}

fn empty_extensions_acc() -> ExtensionsAcc {
  ExtensionsAcc(
    basic_constraints: None,
    key_usage: [],
    extended_key_usage: [],
    subject_alt_names: [],
    subject_key_identifier: None,
    authority_key_identifier: None,
    raw: [],
    seen_oids: set.new(),
  )
}

type RawTbs {
  RawTbs(
    version: Int,
    serial_number: BitArray,
    sig_alg_oid: List(Int),
    issuer: x509.Name,
    validity: x509.Validity,
    subject: x509.Name,
    spki_alg_oid: List(Int),
    spki_bytes: BitArray,
    has_unique_ids: Bool,
    extensions: Option(List(#(x509.Oid, Bool, BitArray))),
  )
}

type RawCertificate {
  RawCertificate(
    tbs_bytes: BitArray,
    tbs: RawTbs,
    outer_sig_alg_oid: List(Int),
    signature: BitArray,
  )
}

/// Configuration for the Subject Key Identifier extension.
pub type SubjectKeyIdentifierConfig {
  /// Automatically compute SKI as SHA-1 hash of the public key (RFC 5280 method 1).
  SkiAuto
  /// Use a custom SKI value.
  SkiExplicit(BitArray)
}

/// Configuration for the Authority Key Identifier extension.
pub type AuthorityKeyIdentifierConfig {
  /// Automatically compute AKI as SHA-1 hash of the signing key (default).
  AkiAuto
  /// Use a custom AKI keyIdentifier value.
  AkiExplicit(BitArray)
  /// Exclude the AKI extension entirely.
  AkiExclude
}

/// An X.509 Certificate.
///
/// The phantom type parameter tracks how the certificate was created:
/// - `Certificate(Built)` - created via `self_signed_with_ecdsa` etc.
/// - `Certificate(Parsed)` - created via `from_pem` or `from_der`
///
/// Export functions (`to_pem`, `to_der`) work on any `Certificate(a)`.
/// Accessor functions (`version`, `subject`, etc.) require `Certificate(Parsed)`.
pub opaque type Certificate(status) {
  BuiltCertificate(der: BitArray)
  ParsedCertificate(
    der: BitArray,
    tbs_bytes: BitArray,
    signature: BitArray,
    version: Int,
    serial_number: BitArray,
    signature_algorithm: x509.SignatureAlgorithm,
    issuer: x509.Name,
    validity: x509.Validity,
    subject: x509.Name,
    public_key: x509.PublicKey,
    basic_constraints: Option(x509.BasicConstraints),
    key_usage: List(x509.KeyUsage),
    extended_key_usage: List(x509.ExtendedKeyUsage),
    subject_alt_names: List(x509.SubjectAltName),
    subject_key_identifier: Option(BitArray),
    authority_key_identifier: Option(x509.AuthorityKeyIdentifier),
    extensions: List(#(x509.Oid, Bool, BitArray)),
  )
}

/// A builder for constructing X.509 certificates.
///
/// Create a builder with `new()`, configure it with `with_*` functions, then
/// sign with one of the signing functions:
///
/// - `self_signed_with_ecdsa()` for ECDSA keys
/// - `self_signed_with_rsa()` for RSA keys
/// - `self_signed_with_eddsa()` for Ed25519/Ed448 keys
pub opaque type Builder {
  Builder(
    subject: x509.Name,
    validity: Option(x509.Validity),
    basic_constraints: Option(#(Bool, Option(Int))),
    key_usage: List(x509.KeyUsage),
    extended_key_usage: List(x509.ExtendedKeyUsage),
    subject_alt_names: List(x509.SubjectAltName),
    serial_number: Option(BitArray),
    subject_key_identifier: Option(SubjectKeyIdentifierConfig),
    authority_key_identifier: AuthorityKeyIdentifierConfig,
  )
}

/// Creates a new certificate builder with default values.
///
/// Use the `with_*` functions to configure the builder, then call
/// a signing function to generate the certificate.
///
/// ## Returns
/// A new Builder ready for configuration.
pub fn new() -> Builder {
  Builder(
    subject: x509.name([]),
    validity: None,
    basic_constraints: None,
    key_usage: [],
    extended_key_usage: [],
    subject_alt_names: [],
    serial_number: None,
    subject_key_identifier: None,
    authority_key_identifier: AkiAuto,
  )
}

/// Sets the distinguished name subject for the certificate.
///
/// The subject identifies who the certificate is issued to.
///
/// ## Parameters
/// - `builder`: The certificate builder
/// - `subject`: A distinguished name created with `x509.name`
///
/// ## Returns
/// The updated builder.
pub fn with_subject(builder: Builder, subject: x509.Name) -> Builder {
  Builder(..builder, subject:)
}

/// Sets the validity period for the certificate.
///
/// ## Parameters
/// - `builder`: The certificate builder
/// - `validity`: The validity period with not_before and not_after timestamps
///
/// ## Returns
/// The updated builder.
pub fn with_validity(builder: Builder, validity: x509.Validity) -> Builder {
  Builder(..builder, validity: Some(validity))
}

/// Sets the Basic Constraints extension.
///
/// This extension indicates whether the certificate is a CA certificate
/// and optionally limits the path length of the certification chain.
///
/// ## Parameters
/// - `builder`: The certificate builder
/// - `ca`: True if this is a CA certificate
/// - `path_len_constraint`: Maximum path length (only valid for CA certs)
///
/// ## Returns
/// The updated builder.
///
/// ## Notes
/// Per RFC 5280, path_len_constraint is only meaningful when ca is True.
/// If ca is False and path_len_constraint is present, the constraint is ignored.
pub fn with_basic_constraints(
  builder: Builder,
  ca ca: Bool,
  path_len_constraint path_len_constraint: Option(Int),
) -> Builder {
  let effective_path_len = case ca {
    True -> path_len_constraint
    False -> None
  }
  Builder(..builder, basic_constraints: Some(#(ca, effective_path_len)))
}

/// Adds a Key Usage flag to the certificate.
///
/// Key Usage defines the cryptographic operations the key may be used for.
/// Multiple usages can be added by chaining calls.
///
/// ## Parameters
/// - `builder`: The certificate builder
/// - `usage`: The key usage flag to add
///
/// ## Returns
/// The updated builder.
pub fn with_key_usage(builder: Builder, usage: x509.KeyUsage) -> Builder {
  Builder(..builder, key_usage: [usage, ..builder.key_usage])
}

/// Adds an Extended Key Usage purpose to the certificate.
///
/// Extended Key Usage provides more specific purposes than Key Usage,
/// such as server authentication or code signing.
///
/// ## Parameters
/// - `builder`: The certificate builder
/// - `usage`: The extended key usage purpose to add
///
/// ## Returns
/// The updated builder.
pub fn with_extended_key_usage(
  builder: Builder,
  usage: x509.ExtendedKeyUsage,
) -> Builder {
  Builder(..builder, extended_key_usage: [usage, ..builder.extended_key_usage])
}

/// Adds a DNS name to the Subject Alternative Names extension.
///
/// SANs allow a certificate to be valid for multiple hostnames.
///
/// ## Parameters
/// - `builder`: The certificate builder
/// - `name`: A DNS hostname (e.g., "example.com" or "*.example.com")
///
/// ## Returns
/// - `Ok(Builder)` with the updated builder
/// - `Error(Nil)` if the DNS name contains non-ASCII characters
pub fn with_dns_name(builder: Builder, name: String) -> Result(Builder, Nil) {
  case utils.is_ascii(name) {
    True ->
      Builder(..builder, subject_alt_names: [
        x509.DnsName(name),
        ..builder.subject_alt_names
      ])
      |> Ok
    False -> Error(Nil)
  }
}

/// Adds an email address to the Subject Alternative Names extension.
///
/// ## Parameters
/// - `builder`: The certificate builder
/// - `email`: An email address (e.g., "user@example.com")
///
/// ## Returns
/// - `Ok(Builder)` with the updated builder
/// - `Error(Nil)` if the email contains non-ASCII characters
pub fn with_email(builder: Builder, email: String) -> Result(Builder, Nil) {
  case utils.is_ascii(email) {
    True ->
      Builder(..builder, subject_alt_names: [
        x509.Email(email),
        ..builder.subject_alt_names
      ])
      |> Ok
    False -> Error(Nil)
  }
}

/// Adds an IP address to the Subject Alternative Names extension.
///
/// ## Parameters
/// - `builder`: The certificate builder
/// - `ip`: An IPv4 address (e.g., "192.168.1.1") or IPv6 address
///   (e.g., "2001:db8::1", "::1")
///
/// ## Returns
/// - `Ok(Builder)` with the updated builder
/// - `Error(Nil)` if the IP address cannot be parsed
pub fn with_ip(builder: Builder, ip: String) -> Result(Builder, Nil) {
  parse_ip(ip)
  |> result.map(fn(parsed) {
    Builder(..builder, subject_alt_names: [
      x509.IpAddress(parsed),
      ..builder.subject_alt_names
    ])
  })
}

/// Sets the serial number for the certificate.
///
/// If not set, a random serial number will be generated during signing.
///
/// ## Parameters
/// - `builder`: The certificate builder
/// - `serial`: The serial number as raw bytes
///
/// ## Returns
/// The updated builder.
pub fn with_serial_number(builder: Builder, serial: BitArray) -> Builder {
  Builder(..builder, serial_number: Some(serial))
}

/// Enables the Subject Key Identifier extension in the certificate.
///
/// If not called, the SKI extension will not be included in the certificate.
///
/// ## Parameters
/// - `builder`: The certificate builder
/// - `ski`: The SKI configuration - use `SkiAuto` to compute from the public key
///   (SHA-1 hash per RFC 5280 method 1) or `SkiExplicit(bytes)` for a custom value
///
/// ## Returns
/// The updated builder.
pub fn with_subject_key_identifier(
  builder: Builder,
  ski: SubjectKeyIdentifierConfig,
) -> Builder {
  Builder(..builder, subject_key_identifier: Some(ski))
}

/// Configures the Authority Key Identifier extension for the certificate.
///
/// By default, self-signed certificates include an AKI with keyIdentifier
/// computed as the SHA-1 hash of the signing public key.
///
/// ## Parameters
/// - `builder`: The certificate builder
/// - `aki`: The AKI configuration:
///   - `AkiAuto` - compute from the public key (default)
///   - `AkiExplicit(bytes)` - use provided keyIdentifier bytes
///   - `AkiExclude` - omit the AKI extension
///
/// ## Returns
/// The updated builder.
pub fn with_authority_key_identifier(
  builder: Builder,
  aki: AuthorityKeyIdentifierConfig,
) -> Builder {
  Builder(..builder, authority_key_identifier: aki)
}

/// Generates a cryptographically random serial number that is RFC 5280 compliant.
@internal
pub fn generate_serial_number() -> BitArray {
  let bytes = crypto.random_bytes(20)
  let assert <<first:8, rest:bits>> = bytes
  <<int.bitwise_and(first, 0x7f):8, rest:bits>>
}

/// Signs a self-signed certificate with an ECDSA private key.
///
/// The public key is derived from the private key and used as both
/// the issuer and subject public key.
///
/// ## Parameters
/// - `builder`: The configured certificate builder
/// - `key`: An EC private key from `ec.generate_key_pair`
/// - `hash`: The hash algorithm for signing.
///
/// ## Returns
/// - `Ok(Certificate(Built))` containing the signed certificate
/// - `Error(Nil)` if the hash algorithm is not supported, validity is missing,
///   or the public key cannot be encoded
pub fn self_signed_with_ecdsa(
  builder: Builder,
  key: ec.PrivateKey,
  hash: HashAlgorithm,
) -> Result(Certificate(Built), Nil) {
  use validity <- result.try(option.to_result(builder.validity, Nil))
  use sig_alg <- result.try(x509_internal.ecdsa_sig_alg_info(hash))
  let public_key = ec.public_key_from_private_key(key)
  use spki <- result.try(ec.public_key_to_der(public_key))

  let serial = case builder.serial_number {
    Some(s) -> s
    None -> generate_serial_number()
  }

  use tbs <- result.try(encode_tbs_certificate(
    builder,
    serial,
    sig_alg,
    spki,
    validity,
  ))
  let signature = ecdsa.sign(key, tbs, hash)

  use cert_der <- result.try(encode_certificate(tbs, sig_alg, signature))
  Ok(BuiltCertificate(cert_der))
}

/// Signs a self-signed certificate with an RSA private key using PKCS#1 v1.5 padding.
///
/// The public key is derived from the private key and used as both
/// the issuer and subject public key.
///
/// ## Parameters
/// - `builder`: The configured certificate builder
/// - `key`: An RSA private key from `rsa.generate_key_pair`
/// - `hash`: The hash algorithm for signing.
///
/// ## Returns
/// - `Ok(Certificate(Built))` containing the signed certificate
/// - `Error(Nil)` if the hash algorithm is not supported, validity is missing,
///   or the public key cannot be encoded
pub fn self_signed_with_rsa(
  builder: Builder,
  key: rsa.PrivateKey,
  hash: HashAlgorithm,
) -> Result(Certificate(Built), Nil) {
  use validity <- result.try(option.to_result(builder.validity, Nil))
  use sig_alg <- result.try(x509_internal.rsa_sig_alg_info(hash))
  let public_key = rsa.public_key_from_private_key(key)
  use spki <- result.try(rsa.public_key_to_der(public_key, rsa.Spki))

  let serial = case builder.serial_number {
    Some(s) -> s
    None -> generate_serial_number()
  }

  use tbs <- result.try(encode_tbs_certificate(
    builder,
    serial,
    sig_alg,
    spki,
    validity,
  ))
  let signature = rsa.sign(key, tbs, hash, rsa.Pkcs1v15)
  use cert_der <- result.try(encode_certificate(tbs, sig_alg, signature))
  Ok(BuiltCertificate(cert_der))
}

/// Signs a self-signed certificate with an EdDSA private key.
///
/// The public key is derived from the private key and used as both
/// the issuer and subject public key. EdDSA has built-in hashing, so no
/// hash algorithm parameter is needed.
///
/// ## Parameters
/// - `builder`: The configured certificate builder
/// - `key`: An EdDSA private key from `eddsa.generate_key_pair`
///
/// ## Returns
/// - `Ok(Certificate(Built))` containing the signed certificate
/// - `Error(Nil)` if validity is missing or the public key cannot be encoded
pub fn self_signed_with_eddsa(
  builder: Builder,
  key: eddsa.PrivateKey,
) -> Result(Certificate(Built), Nil) {
  use validity <- result.try(option.to_result(builder.validity, Nil))
  let sig_alg = x509_internal.eddsa_sig_alg_info(eddsa.curve(key))
  let public_key = eddsa.public_key_from_private_key(key)
  use spki <- result.try(eddsa.public_key_to_der(public_key))

  let serial = case builder.serial_number {
    Some(s) -> s
    None -> generate_serial_number()
  }

  use tbs <- result.try(encode_tbs_certificate(
    builder,
    serial,
    sig_alg,
    spki,
    validity,
  ))
  let signature = eddsa.sign(key, tbs)
  use cert_der <- result.try(encode_certificate(tbs, sig_alg, signature))
  Ok(BuiltCertificate(cert_der))
}

/// Exports the certificate as DER-encoded bytes.
///
/// DER (Distinguished Encoding Rules) is a binary format commonly used
/// for programmatic certificate handling.
///
/// ## Parameters
/// - `cert`: The signed certificate
///
/// ## Returns
/// The raw DER-encoded certificate bytes.
pub fn to_der(cert: Certificate(a)) -> BitArray {
  case cert {
    BuiltCertificate(der) -> der
    ParsedCertificate(der, ..) -> der
  }
}

/// Exports the certificate as a PEM-encoded string.
///
/// PEM (Privacy-Enhanced Mail) is a Base64-encoded format with header and
/// footer lines.
///
/// ## Parameters
/// - `cert`: The signed certificate
///
/// ## Returns
/// A PEM-encoded string with `-----BEGIN CERTIFICATE-----` headers.
pub fn to_pem(cert: Certificate(a)) -> String {
  x509_internal.encode_pem(to_der(cert), pem_begin, pem_end)
}

/// Parse all PEM-encoded certificates from a string.
///
/// Extracts and parses all `-----BEGIN CERTIFICATE-----` blocks from the input.
/// Certificates are returned in the order they appear.
///
/// **Note:** This function does NOT verify the certificates' cryptographic
/// signatures. To verify a certificate was signed by an issuer, use `verify()`.
/// For self-signed certificates, use `verify_self_signed()`.
///
/// ## Parameters
/// - `pem`: A string containing one or more PEM-encoded certificates
///
/// ## Returns
/// - `Ok(List(Certificate(Parsed)))` with parsed certificates (empty list if no certificates found)
/// - `Error(ParseError)` if base64 decoding fails or certificate structure is invalid
/// - `Error(UnsupportedAlgorithm(oid))` if any certificate uses an unsupported algorithm
/// - `Error(UnrecognizedCriticalExtension(oid))` if any certificate has unknown critical extensions
pub fn from_pem(
  pem: String,
) -> Result(List(Certificate(Parsed)), CertificateError) {
  x509_internal.decode_pem_all(pem, pem_begin, pem_end)
  |> result.replace_error(ParseError)
  |> result.try(list.try_map(_, from_der))
}

fn certificate_version() -> p.Parser(Int) {
  use opt <- p.then(p.optional(der.context_tag(0, der.integer())))
  case opt {
    None -> p.success(0)
    Some(<<0>>) -> p.success(0)
    Some(<<1>>) -> p.success(1)
    Some(<<2>>) -> p.success(2)
    Some(_) -> p.fail("invalid certificate version")
  }
}

fn validity_parser() -> p.Parser(x509.Validity) {
  use not_before <- p.then(x509_internal.time())
  use not_after <- p.then(x509_internal.time())
  p.success(x509.Validity(not_before:, not_after:))
}

fn skip_unique_ids() -> p.Parser(Bool) {
  p.many(
    p.attempt({
      use #(tag, _) <- p.then(der.tlv())
      case tag {
        0x81 | 0x82 -> p.success(Nil)
        _ -> p.fail("not a unique id tag")
      }
    }),
  )
  |> p.map(fn(items) { !list.is_empty(items) })
}

fn optional_extensions() -> p.Parser(Option(List(#(x509.Oid, Bool, BitArray)))) {
  p.optional(der.context_tag(
    3,
    der.sequence(p.many(der.sequence(x509_internal.single_extension()))),
  ))
}

fn tbs_parser() -> p.Parser(RawTbs) {
  use version <- p.then(certificate_version())
  use serial_number <- p.then(der.integer())
  use sig_alg_oid <- p.then(
    der.sequence(x509_internal.signature_algorithm_oid()),
  )
  use issuer <- p.then(der.sequence(x509_internal.name()))
  use validity <- p.then(der.sequence(validity_parser()))
  use subject <- p.then(der.sequence(x509_internal.name()))
  use #(spki_alg_oid, spki_bytes) <- p.then(x509_internal.public_key_info())
  use has_unique_ids <- p.then(skip_unique_ids())
  use extensions <- p.then(optional_extensions())
  p.success(RawTbs(
    version:,
    serial_number:,
    sig_alg_oid:,
    issuer:,
    validity:,
    subject:,
    spki_alg_oid:,
    spki_bytes:,
    has_unique_ids:,
    extensions:,
  ))
}

fn certificate_parser() -> p.Parser(RawCertificate) {
  der.sequence({
    use #(tbs_bytes, tbs) <- p.then(der.sequence_with_raw(tbs_parser()))
    use outer_sig_alg_oid <- p.then(
      der.sequence(x509_internal.signature_algorithm_oid()),
    )
    use signature <- p.then(der.bit_string())
    p.success(RawCertificate(tbs_bytes:, tbs:, outer_sig_alg_oid:, signature:))
  })
}

/// Parse a DER-encoded X.509 certificate.
///
/// Validates the ASN.1 structure and extracts all standard fields and
/// extensions. Unknown non-critical extensions are preserved but not parsed.
///
/// **Note:** This function does NOT verify the certificate's cryptographic
/// signature. To verify a certificate was signed by an issuer, use `verify()`.
/// For self-signed certificates, use `verify_self_signed()`.
///
/// ## Parameters
/// - `der`: Raw DER-encoded certificate bytes
///
/// ## Returns
/// - `Ok(Certificate(Parsed))` if parsing succeeds
/// - `Error(ParseError)` if the ASN.1 structure is malformed
/// - `Error(UnsupportedAlgorithm(oid))` if the signature algorithm or key type is not supported
/// - `Error(UnrecognizedCriticalExtension(oid))` if an unknown extension is marked critical (per RFC 5280)
pub fn from_der(der: BitArray) -> Result(Certificate(Parsed), CertificateError) {
  use raw <- result.try(
    p.run(certificate_parser(), on: der)
    |> result.replace_error(ParseError),
  )

  use signature_algorithm <- result.try(
    x509_internal.lookup_signature_algorithm(raw.tbs.sig_alg_oid)
    |> result.map_error(UnsupportedAlgorithm),
  )

  // Signature algorithm OIDs must match (RFC 5280 §4.1.1.2)
  use <- bool.guard(
    when: raw.tbs.sig_alg_oid != raw.outer_sig_alg_oid,
    return: Error(ParseError),
  )

  use public_key <- result.try(
    x509_internal.dispatch_public_key_parse(
      raw.tbs.spki_alg_oid,
      raw.tbs.spki_bytes,
    )
    |> result.map_error(fn(oid) {
      case oid {
        x509.Oid([]) -> ParseError
        _ -> UnsupportedAlgorithm(oid)
      }
    }),
  )

  // RFC 5280 version validation
  use <- bool.guard(
    when: raw.tbs.has_unique_ids && raw.tbs.version < 1,
    return: Error(ParseError),
  )
  use <- bool.guard(
    when: option.is_some(raw.tbs.extensions) && raw.tbs.version < 2,
    return: Error(ParseError),
  )

  use exts <- result.try(process_all_extensions(raw.tbs.extensions))

  Ok(ParsedCertificate(
    der:,
    tbs_bytes: raw.tbs_bytes,
    signature: raw.signature,
    version: raw.tbs.version,
    serial_number: raw.tbs.serial_number,
    signature_algorithm:,
    issuer: raw.tbs.issuer,
    validity: raw.tbs.validity,
    subject: raw.tbs.subject,
    public_key:,
    basic_constraints: exts.basic_constraints,
    key_usage: exts.key_usage,
    extended_key_usage: exts.extended_key_usage,
    subject_alt_names: exts.subject_alt_names,
    subject_key_identifier: exts.subject_key_identifier,
    authority_key_identifier: exts.authority_key_identifier,
    extensions: exts.raw,
  ))
}

/// Returns the version of a parsed certificate.
///
/// X.509 certificates use:
/// - Version 1 = value 0
/// - Version 2 = value 1
/// - Version 3 = value 2 (most common, supports extensions)
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// The version number (0, 1, or 2).
pub fn version(cert: Certificate(Parsed)) -> Int {
  let assert ParsedCertificate(version:, ..) = cert
  version
}

/// Returns the serial number of a parsed certificate.
///
/// Serial numbers are unique within a CA and encoded as unsigned integers.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// The serial number as raw bytes.
pub fn serial_number(cert: Certificate(Parsed)) -> BitArray {
  let assert ParsedCertificate(serial_number:, ..) = cert
  serial_number
}

/// Returns the signature algorithm used to sign the certificate.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// The signature algorithm identifier.
pub fn signature_algorithm(cert: Certificate(Parsed)) -> x509.SignatureAlgorithm {
  let assert ParsedCertificate(signature_algorithm:, ..) = cert
  signature_algorithm
}

/// Returns the issuer distinguished name.
///
/// The issuer identifies the CA that signed this certificate.
/// For self-signed certificates, issuer equals subject.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// The issuer as a distinguished name.
pub fn issuer(cert: Certificate(Parsed)) -> x509.Name {
  let assert ParsedCertificate(issuer:, ..) = cert
  issuer
}

/// Returns the validity period of the certificate.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// The validity period with `not_before` and `not_after` timestamps.
pub fn validity(cert: Certificate(Parsed)) -> x509.Validity {
  let assert ParsedCertificate(validity:, ..) = cert
  validity
}

/// Returns the subject distinguished name.
///
/// The subject identifies the entity the certificate was issued to.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// The subject as a distinguished name.
pub fn subject(cert: Certificate(Parsed)) -> x509.Name {
  let assert ParsedCertificate(subject:, ..) = cert
  subject
}

/// Returns the public key embedded in the certificate.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// The subject's public key (RSA, EC, Ed, or XDH).
pub fn public_key(cert: Certificate(Parsed)) -> x509.PublicKey {
  let assert ParsedCertificate(public_key:, ..) = cert
  public_key
}

/// Returns the Basic Constraints extension from a parsed certificate.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// - `Ok(BasicConstraints)` if the extension is present
/// - `Error(Nil)` if the extension is not present
pub fn basic_constraints(
  cert: Certificate(Parsed),
) -> Result(x509.BasicConstraints, Nil) {
  let assert ParsedCertificate(basic_constraints:, ..) = cert
  option.to_result(basic_constraints, Nil)
}

/// Returns the Key Usage flags from a parsed certificate.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// List of key usage flags, or empty list if extension not present.
pub fn key_usage(cert: Certificate(Parsed)) -> List(x509.KeyUsage) {
  let assert ParsedCertificate(key_usage:, ..) = cert
  key_usage
}

/// Returns the Extended Key Usage purposes from a parsed certificate.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// List of extended key usage purposes, or empty list if extension not present.
pub fn extended_key_usage(
  cert: Certificate(Parsed),
) -> List(x509.ExtendedKeyUsage) {
  let assert ParsedCertificate(extended_key_usage:, ..) = cert
  extended_key_usage
}

/// Returns the Subject Alternative Names (SA) from a parsed certificate.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// List of SANs (DNS names, emails, IPs), or empty list if extension not present.
pub fn subject_alt_names(cert: Certificate(Parsed)) -> List(x509.SubjectAltName) {
  let assert ParsedCertificate(subject_alt_names:, ..) = cert
  subject_alt_names
}

/// Returns the Subject Key Identifier (SKI) from a parsed certificate.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// - `Ok(BitArray)` with the SKI bytes if extension is present
/// - `Error(Nil)` if extension is not present
pub fn subject_key_identifier(
  cert: Certificate(Parsed),
) -> Result(BitArray, Nil) {
  let assert ParsedCertificate(subject_key_identifier:, ..) = cert
  option.to_result(subject_key_identifier, Nil)
}

/// Returns the Authority Key Identifier (AKI) from a parsed certificate.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// - `Ok(AuthorityKeyIdentifier)` if extension is present
/// - `Error(Nil)` if extension is not present
pub fn authority_key_identifier(
  cert: Certificate(Parsed),
) -> Result(x509.AuthorityKeyIdentifier, Nil) {
  let assert ParsedCertificate(authority_key_identifier:, ..) = cert
  option.to_result(authority_key_identifier, Nil)
}

/// Returns all extensions as raw (OID, critical, value) tuples.
///
/// This returns every extension present in the certificate, including those
/// that kryptos also parses into typed representations (Basic Constraints,
/// Key Usage, Extended Key Usage, Subject Alt Names, etc).
///
/// This is useful for inspecting extension criticality or accessing the raw
/// DER-encoded value of any extension.
///
/// The Bool indicates whether the extension was marked as critical per RFC 5280.
///
/// ## Parameters
/// - `cert`: A parsed certificate
///
/// ## Returns
/// List of all extension tuples `#(Oid, Bool, BitArray)`.
pub fn extensions(
  cert: Certificate(Parsed),
) -> List(#(x509.Oid, Bool, BitArray)) {
  let assert ParsedCertificate(extensions:, ..) = cert
  extensions
}

/// Verify a certificate's signature against an issuer's public key.
///
/// This verifies that the certificate was signed by the private key
/// corresponding to the provided public key.
///
/// ## Parameters
/// - `cert`: The parsed certificate to verify
/// - `issuer_public_key`: The public key to verify against (must be RSA, ECDSA, or EdDSA)
///
/// ## Returns
/// - `Ok(Nil)` if the signature is valid
/// - `Error(SignatureVerificationFailed)` if the signature is invalid
/// - `Error(UnsupportedAlgorithm)` if the key cannot be used for verification
pub fn verify(
  cert: Certificate(Parsed),
  issuer_public_key: x509.PublicKey,
) -> Result(Nil, CertificateError) {
  let assert ParsedCertificate(tbs_bytes:, signature:, signature_algorithm:, ..) =
    cert

  use <- bool.lazy_guard(when: is_xdh_key(issuer_public_key), return: fn() {
    let oid =
      xdh_key_oid(issuer_public_key)
      |> result.unwrap(x509.Oid([]))
    Error(UnsupportedAlgorithm(oid))
  })

  let verified =
    x509_internal.verify_signature(
      issuer_public_key,
      tbs_bytes,
      signature,
      signature_algorithm,
    )

  case verified {
    True -> Ok(Nil)
    False -> Error(SignatureVerificationFailed)
  }
}

/// Verify a self-signed certificate against its own public key.
///
/// This is a convenience function that extracts the public key from the
/// certificate and verifies the signature against it.
///
/// ## Parameters
/// - `cert`: The parsed self-signed certificate to verify
///
/// ## Returns
/// - `Ok(Nil)` if the signature is valid
/// - `Error(SignatureVerificationFailed)` if the signature is invalid
/// - `Error(UnsupportedAlgorithm)` if the certificate contains a key that cannot sign (e.g., XDH)
pub fn verify_self_signed(
  cert: Certificate(Parsed),
) -> Result(Nil, CertificateError) {
  public_key(cert)
  |> verify(cert, _)
}

fn process_all_extensions(
  raw_exts: Option(List(#(x509.Oid, Bool, BitArray))),
) -> Result(ExtensionsAcc, CertificateError) {
  case raw_exts {
    None -> Ok(empty_extensions_acc())
    Some(raw) -> {
      list.try_fold(raw, empty_extensions_acc(), fn(acc, ext) {
        let #(x509.Oid(components), _, _) = ext
        case set.contains(acc.seen_oids, components) {
          True -> Error(ParseError)
          False -> {
            ExtensionsAcc(
              ..acc,
              seen_oids: set.insert(acc.seen_oids, components),
            )
            |> process_extension(ext)
          }
        }
      })
      |> result.map(fn(acc) { ExtensionsAcc(..acc, raw:) })
    }
  }
}

fn process_extension(
  acc: ExtensionsAcc,
  ext: #(x509.Oid, Bool, BitArray),
) -> Result(ExtensionsAcc, CertificateError) {
  let #(oid, is_critical, value) = ext
  case oid {
    x509.Oid([2, 5, 29, 19]) -> {
      parse_basic_constraints_ext(value)
      |> result.replace_error(ParseError)
      |> result.map(fn(bc) { ExtensionsAcc(..acc, basic_constraints: Some(bc)) })
    }
    x509.Oid([2, 5, 29, 15]) -> {
      parse_key_usage_ext(value)
      |> result.replace_error(ParseError)
      |> result.map(fn(key_usage) { ExtensionsAcc(..acc, key_usage:) })
    }
    x509.Oid([2, 5, 29, 37]) -> {
      parse_extended_key_usage_ext(value, is_critical)
      |> result.map(fn(extended_key_usage) {
        ExtensionsAcc(..acc, extended_key_usage:)
      })
    }
    x509.Oid([2, 5, 29, 17]) -> {
      p.run(x509_internal.san_extension(is_critical), on: value)
      |> result.replace_error(ParseError)
      |> result.map(fn(subject_alt_names) {
        ExtensionsAcc(..acc, subject_alt_names:)
      })
    }
    x509.Oid([2, 5, 29, 14]) -> {
      parse_subject_key_identifier_ext(value)
      |> result.replace_error(ParseError)
      |> result.map(fn(ski) {
        ExtensionsAcc(..acc, subject_key_identifier: Some(ski))
      })
    }
    x509.Oid([2, 5, 29, 35]) -> {
      parse_authority_key_identifier_ext(value)
      |> result.replace_error(ParseError)
      |> result.map(fn(aki) {
        ExtensionsAcc(..acc, authority_key_identifier: Some(aki))
      })
    }
    _ -> {
      case is_critical {
        True -> Error(UnrecognizedCriticalExtension(oid))
        False -> Ok(acc)
      }
    }
  }
}

fn parse_basic_constraints_ext(
  bytes: BitArray,
) -> Result(x509.BasicConstraints, Nil) {
  use #(ca, path_len_bytes) <- result.try(
    p.run(
      der.sequence(p.pair(
        p.optional(der.boolean()) |> p.map(option.unwrap(_, False)),
        p.optional(der.integer()),
      )),
      on: bytes,
    )
    |> result.replace_error(Nil),
  )
  case ca, path_len_bytes {
    True, Some(plb) -> {
      use path_len <- result.try(bytes_to_int(plb))
      Ok(x509.BasicConstraints(ca: True, path_len_constraint: Some(path_len)))
    }
    _, _ -> Ok(x509.BasicConstraints(ca:, path_len_constraint: None))
  }
}

fn bytes_to_int(bytes: BitArray) -> Result(Int, Nil) {
  case bytes {
    <<n:8>> -> Ok(n)
    <<n:16>> -> Ok(n)
    <<n:24>> -> Ok(n)
    <<n:32>> -> Ok(n)
    _ -> Error(Nil)
  }
}

fn parse_key_usage_ext(bytes: BitArray) -> Result(List(x509.KeyUsage), Nil) {
  case bytes {
    <<0x03, len:8, unused_bits:8, rest:bits>> if unused_bits <= 7 && len >= 2 -> {
      bit_array.slice(rest, 0, len - 1)
      |> result.map(decode_key_usage_bits)
    }
    _ -> Error(Nil)
  }
}

fn decode_key_usage_bits(bytes: BitArray) -> List(x509.KeyUsage) {
  case bytes {
    <<
      digital_signature:1,
      non_repudiation:1,
      key_encipherment:1,
      data_encipherment:1,
      key_agreement:1,
      key_cert_sign:1,
      crl_sign:1,
      encipher_only:1,
      rest:bits,
    >> -> {
      let usages =
        [
          #(digital_signature, x509.DigitalSignature),
          #(non_repudiation, x509.NonRepudiation),
          #(key_encipherment, x509.KeyEncipherment),
          #(data_encipherment, x509.DataEncipherment),
          #(key_agreement, x509.KeyAgreement),
          #(key_cert_sign, x509.KeyCertSign),
          #(crl_sign, x509.CrlSign),
          #(encipher_only, x509.EncipherOnly),
        ]
        |> list.filter_map(fn(pair) {
          case pair {
            #(1, usage) -> Ok(usage)
            _ -> Error(Nil)
          }
        })

      case rest {
        <<1:1, _:bits>> -> [x509.DecipherOnly, ..usages]
        _ -> usages
      }
    }
    _ -> []
  }
}

fn parse_subject_key_identifier_ext(bytes: BitArray) -> Result(BitArray, Nil) {
  p.run(der.octet_string(), on: bytes)
  |> result.replace_error(Nil)
}

fn parse_authority_key_identifier_ext(
  bytes: BitArray,
) -> Result(x509.AuthorityKeyIdentifier, Nil) {
  use fields <- result.try(
    p.run(der.sequence(p.many(der.tlv())), on: bytes)
    |> result.replace_error(Nil),
  )
  list.try_fold(fields, #(None, None, None), fn(acc, field) {
    let #(key_id, issuer_names, serial) = acc
    let #(tag, value) = field
    case tag {
      0x80 -> Ok(#(Some(value), issuer_names, serial))
      0xa1 -> {
        p.run(x509_internal.general_names(False), on: value)
        |> result.replace_error(Nil)
        |> result.map(fn(names) { #(key_id, Some(names), serial) })
      }
      0x82 -> Ok(#(key_id, issuer_names, Some(value)))
      _ -> Error(Nil)
    }
  })
  |> result.map(fn(acc) {
    let #(key_id, issuer_names, serial) = acc
    x509.AuthorityKeyIdentifier(
      key_identifier: key_id,
      authority_cert_issuer: issuer_names,
      authority_cert_serial_number: serial,
    )
  })
}

fn parse_extended_key_usage_ext(
  bytes: BitArray,
  is_critical: Bool,
) -> Result(List(x509.ExtendedKeyUsage), CertificateError) {
  use oids <- result.try(
    p.run(der.sequence(p.many(der.oid())), on: bytes)
    |> result.replace_error(ParseError),
  )
  list.try_fold(oids, [], fn(acc, oid_components) {
    case oid_to_eku(oid_components) {
      Ok(eku) -> Ok([eku, ..acc])
      Error(_) ->
        case is_critical {
          False -> Ok(acc)
          True -> Error(UnrecognizedCriticalExtension(x509.Oid(oid_components)))
        }
    }
  })
  |> result.map(list.reverse)
}

fn oid_to_eku(oid: List(Int)) -> Result(x509.ExtendedKeyUsage, Nil) {
  case oid {
    [1, 3, 6, 1, 5, 5, 7, 3, 1] -> Ok(x509.ServerAuth)
    [1, 3, 6, 1, 5, 5, 7, 3, 2] -> Ok(x509.ClientAuth)
    [1, 3, 6, 1, 5, 5, 7, 3, 3] -> Ok(x509.CodeSigning)
    [1, 3, 6, 1, 5, 5, 7, 3, 4] -> Ok(x509.EmailProtection)
    [1, 3, 6, 1, 5, 5, 7, 3, 9] -> Ok(x509.OcspSigning)
    _ -> Error(Nil)
  }
}

fn encode_tbs_certificate(
  builder: Builder,
  serial: BitArray,
  sig_alg: SigAlgInfo,
  spki: BitArray,
  validity: x509.Validity,
) -> Result(BitArray, Nil) {
  use version <- result.try(encode_version())
  use serial_int <- result.try(der.encode_integer(serial))
  use sig_alg_der <- result.try(x509_internal.encode_algorithm_identifier(
    sig_alg,
  ))
  use issuer <- result.try(x509_internal.encode_name(builder.subject))
  use validity_der <- result.try(encode_validity(validity))
  use subject <- result.try(x509_internal.encode_name(builder.subject))
  use extensions <- result.try(encode_extensions(builder, spki))

  der.encode_sequence(
    bit_array.concat([
      version,
      serial_int,
      sig_alg_der,
      issuer,
      validity_der,
      subject,
      spki,
      extensions,
    ]),
  )
}

fn encode_version() -> Result(BitArray, Nil) {
  der.encode_integer(<<2>>)
  |> result.try(der.encode_context_tag(0, _))
}

fn encode_validity(validity: x509.Validity) -> Result(BitArray, Nil) {
  let x509.Validity(not_before, not_after) = validity
  use not_before_der <- result.try(der.encode_timestamp(not_before))
  use not_after_der <- result.try(der.encode_timestamp(not_after))
  der.encode_sequence(bit_array.concat([not_before_der, not_after_der]))
}

fn encode_extensions(builder: Builder, spki: BitArray) -> Result(BitArray, Nil) {
  let x509.Name(rdns) = builder.subject
  let subject_is_empty = list.is_empty(rdns)
  let sans_is_empty = list.is_empty(builder.subject_alt_names)
  use <- bool.guard(when: subject_is_empty && sans_is_empty, return: Error(Nil))

  let extension_results = [
    encode_basic_constraints_opt(builder.basic_constraints),
    encode_key_usage_opt(builder.key_usage),
    encode_extended_key_usage_opt(builder.extended_key_usage),
    encode_san_opt(builder.subject_alt_names, subject_is_empty),
    encode_ski_opt(builder.subject_key_identifier, spki),
    encode_aki_opt(builder.authority_key_identifier, spki),
  ]

  use results <- result.try(result.all(extension_results))
  let encoded = result.values(results)

  case encoded {
    [] -> Ok(<<>>)
    _ -> {
      encoded
      |> bit_array.concat
      |> der.encode_sequence
      |> result.try(der.encode_context_tag(3, _))
    }
  }
}

fn encode_basic_constraints_opt(
  config: Option(#(Bool, Option(Int))),
) -> Result(Result(BitArray, Nil), Nil) {
  case config {
    None -> Ok(Error(Nil))
    Some(#(ca, path_len)) ->
      result.map(encode_basic_constraints_extension(ca, path_len), Ok)
  }
}

fn encode_key_usage_opt(
  usages: List(x509.KeyUsage),
) -> Result(Result(BitArray, Nil), Nil) {
  use <- bool.guard(when: list.is_empty(usages), return: Ok(Error(Nil)))
  result.map(encode_key_usage_extension(usages), Ok)
}

fn encode_extended_key_usage_opt(
  usages: List(x509.ExtendedKeyUsage),
) -> Result(Result(BitArray, Nil), Nil) {
  use <- bool.guard(when: list.is_empty(usages), return: Ok(Error(Nil)))
  result.map(encode_extended_key_usage_extension(usages), Ok)
}

fn encode_san_opt(
  sans: List(x509.SubjectAltName),
  critical: Bool,
) -> Result(Result(BitArray, Nil), Nil) {
  use <- bool.guard(when: list.is_empty(sans), return: Ok(Error(Nil)))
  result.map(x509_internal.encode_san_extension(sans, critical), Ok)
}

fn encode_ski_opt(
  config: Option(SubjectKeyIdentifierConfig),
  spki: BitArray,
) -> Result(Result(BitArray, Nil), Nil) {
  case config {
    None -> Ok(Error(Nil))
    Some(SkiAuto) ->
      compute_ski(spki)
      |> result.try(encode_subject_key_identifier_extension)
      |> result.map(Ok)
    Some(SkiExplicit(ski)) ->
      encode_subject_key_identifier_extension(ski)
      |> result.map(Ok)
  }
}

fn encode_aki_opt(
  config: AuthorityKeyIdentifierConfig,
  spki: BitArray,
) -> Result(Result(BitArray, Nil), Nil) {
  case config {
    AkiExclude -> Ok(Error(Nil))
    AkiAuto ->
      compute_ski(spki)
      |> result.try(encode_authority_key_identifier_extension)
      |> result.map(Ok)
    AkiExplicit(key_id) ->
      encode_authority_key_identifier_extension(key_id)
      |> result.map(Ok)
  }
}

fn encode_basic_constraints_extension(
  ca: Bool,
  path_len: Option(Int),
) -> Result(BitArray, Nil) {
  let x509.Oid(oid_components) = oid_basic_constraints
  use oid_encoded <- result.try(der.encode_oid(oid_components))

  let ca_bool = case ca {
    True -> der.encode_bool(True)
    False -> <<>>
  }

  case path_len {
    Some(n) -> der.encode_small_int(n)
    None -> Ok(<<>>)
  }
  |> result.map(fn(path_len_int) { bit_array.concat([ca_bool, path_len_int]) })
  |> result.try(der.encode_sequence)
  |> result.try(der.encode_octet_string)
  |> result.map(fn(value_octet) {
    bit_array.concat([oid_encoded, der.encode_bool(True), value_octet])
  })
  |> result.try(der.encode_sequence)
}

const key_usages = [
  x509.DigitalSignature,
  x509.NonRepudiation,
  x509.KeyEncipherment,
  x509.DataEncipherment,
  x509.KeyAgreement,
  x509.KeyCertSign,
  x509.CrlSign,
  x509.EncipherOnly,
  x509.DecipherOnly,
]

fn encode_key_usage_extension(
  usages: List(x509.KeyUsage),
) -> Result(BitArray, Nil) {
  let x509.Oid(oid_components) = oid_key_usage
  use oid_encoded <- result.try(der.encode_oid(oid_components))

  let last_set_index =
    list.index_fold(key_usages, 0, fn(last_index, usage, index) {
      case list.contains(usages, usage) {
        True -> index + 1
        False -> last_index
      }
    })

  let key_usage_bits =
    key_usages
    |> list.take(last_set_index)
    |> list.fold(<<>>, fn(acc, usage) {
      let bit = case list.contains(usages, usage) {
        True -> 1
        False -> 0
      }
      <<acc:bits, bit:1>>
    })

  key_usage_bits
  |> der.encode_bit_string
  |> result.try(der.encode_octet_string)
  |> result.map(fn(value_octet) {
    bit_array.concat([oid_encoded, der.encode_bool(True), value_octet])
  })
  |> result.try(der.encode_sequence)
}

fn encode_extended_key_usage_extension(
  usages: List(x509.ExtendedKeyUsage),
) -> Result(BitArray, Nil) {
  let x509.Oid(oid_components) = oid_extended_key_usage
  use oid_encoded <- result.try(der.encode_oid(oid_components))

  usages
  |> list.try_map(fn(usage) {
    let x509.Oid(components) = case usage {
      x509.ServerAuth -> oid_server_auth
      x509.ClientAuth -> oid_client_auth
      x509.CodeSigning -> oid_code_signing
      x509.EmailProtection -> oid_email_protection
      x509.OcspSigning -> oid_ocsp_signing
    }
    der.encode_oid(components)
  })
  |> result.map(bit_array.concat)
  |> result.try(der.encode_sequence)
  |> result.try(der.encode_octet_string)
  |> result.map(fn(value_octet) { bit_array.concat([oid_encoded, value_octet]) })
  |> result.try(der.encode_sequence)
}

fn compute_ski(spki: BitArray) -> Result(BitArray, Nil) {
  spki
  |> x509_internal.extract_spki_public_key_bytes
  |> result.try(crypto.hash(hash.Sha1, _))
}

fn encode_subject_key_identifier_extension(
  ski: BitArray,
) -> Result(BitArray, Nil) {
  let x509.Oid(oid_components) = oid_subject_key_identifier
  use oid_encoded <- result.try(der.encode_oid(oid_components))

  ski
  |> der.encode_octet_string
  |> result.try(der.encode_octet_string)
  |> result.map(fn(value_octet) { bit_array.concat([oid_encoded, value_octet]) })
  |> result.try(der.encode_sequence)
}

fn encode_authority_key_identifier_extension(
  key_identifier: BitArray,
) -> Result(BitArray, Nil) {
  let x509.Oid(oid_components) = oid_authority_key_identifier
  use oid_encoded <- result.try(der.encode_oid(oid_components))

  key_identifier
  |> der.encode_context_primitive_tag(0, _)
  |> result.try(der.encode_sequence)
  |> result.try(der.encode_octet_string)
  |> result.map(fn(value_octet) { bit_array.concat([oid_encoded, value_octet]) })
  |> result.try(der.encode_sequence)
}

fn encode_certificate(
  tbs: BitArray,
  sig_alg: SigAlgInfo,
  signature: BitArray,
) -> Result(BitArray, Nil) {
  use sig_alg_der <- result.try(x509_internal.encode_algorithm_identifier(
    sig_alg,
  ))
  use sig_bits <- result.try(der.encode_bit_string(signature))
  der.encode_sequence(bit_array.concat([tbs, sig_alg_der, sig_bits]))
}

fn is_xdh_key(key: x509.PublicKey) -> Bool {
  case key {
    x509.XdhPublicKey(_) -> True
    _ -> False
  }
}

fn xdh_key_oid(key: x509.PublicKey) -> Result(x509.Oid, Nil) {
  case key {
    x509.XdhPublicKey(xdh_key) ->
      case xdh.public_key_curve(xdh_key) {
        xdh.X25519 -> Ok(x509.Oid([1, 3, 101, 110]))
        xdh.X448 -> Ok(x509.Oid([1, 3, 101, 111]))
      }
    _ -> Error(Nil)
  }
}
