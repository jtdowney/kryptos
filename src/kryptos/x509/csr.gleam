//// X.509 Certificate Signing Request (CSR) generation.
////
//// This module provides a builder for creating PKCS#10 Certificate Signing
//// Requests. CSRs are used to request certificates from a Certificate Authority.
////
//// ## Example
////
//// ```gleam
//// import gleam/result
//// import kryptos/ec
//// import kryptos/hash
//// import kryptos/x509
//// import kryptos/x509/csr
////
//// let #(private_key, _) = ec.generate_key_pair(ec.P256)
////
//// let subject = x509.name([
////   x509.cn("example.com"),
////   x509.organization("Acme Inc"),
////   x509.country("US"),
//// ])
////
//// let assert Ok(builder) =
////   csr.new()
////   |> csr.with_subject(subject)
////   |> csr.with_dns_name("example.com")
////   |> result.try(csr.with_dns_name(_, "www.example.com"))
////
//// let assert Ok(my_csr) = csr.sign_with_ecdsa(builder, private_key, hash.Sha256)
////
//// let pem = csr.to_pem(my_csr)
//// ```

import bitty as p
import bitty/bytes as b
import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/option.{type Option}
import gleam/result
import kryptos/ec
import kryptos/ecdsa
import kryptos/eddsa
import kryptos/hash.{type HashAlgorithm}
import kryptos/internal/der
import kryptos/internal/utils.{parse_ip}
import kryptos/internal/x509.{type SigAlgInfo} as x509_internal
import kryptos/rsa
import kryptos/x509

const oid_extension_request = x509.Oid([1, 2, 840, 113_549, 1, 9, 14])

const pem_begin = "-----BEGIN CERTIFICATE REQUEST-----"

const pem_end = "-----END CERTIFICATE REQUEST-----"

const pem_new_begin = "-----BEGIN NEW CERTIFICATE REQUEST-----"

const pem_new_end = "-----END NEW CERTIFICATE REQUEST-----"

/// Phantom type marker for CSRs created via the builder.
pub type Built

/// Phantom type marker for CSRs parsed from PEM/DER.
pub type Parsed

/// A Certificate Signing Request.
///
/// The phantom type parameter tracks how the CSR was created:
/// - `Csr(Built)` - created via `sign_with_ecdsa` or `sign_with_rsa`
/// - `Csr(Parsed)` - created via `from_pem` or `from_der`
///
/// Export functions (`to_pem`, `to_der`) work on any `Csr(a)`.
/// Accessor functions (`subject`, `public_key`, etc.) require `Csr(Parsed)`.
pub opaque type Csr(status) {
  BuiltCsr(der: BitArray)
  ParsedCsr(
    der: BitArray,
    cert_req_info_bytes: BitArray,
    signature: BitArray,
    version: Int,
    subject: x509.Name,
    public_key: x509.PublicKey,
    signature_algorithm: x509.SignatureAlgorithm,
    subject_alt_names: List(x509.SubjectAltName),
    extensions: List(#(x509.Oid, Bool, BitArray)),
    attributes: List(#(x509.Oid, BitArray)),
  )
}

/// Error type for CSR parsing failures.
pub type CsrError {
  InvalidPem
  InvalidStructure
  UnsupportedSignatureAlgorithm(x509.Oid)
  UnsupportedKeyType(x509.Oid)
  SignatureVerificationFailed
  UnsupportedVersion(Int)
}

/// A builder for constructing CSRs.
pub opaque type Builder {
  Builder(subject: x509.Name, extensions: x509.Extensions)
}

/// Creates a new CSR builder with an empty subject and no extensions.
///
/// Use the `with_*` functions to configure the builder, then call
/// `sign_with_ecdsa` or `sign_with_rsa` to generate the signed CSR.
///
/// ## Returns
/// A new Builder ready for configuration.
pub fn new() -> Builder {
  Builder(
    subject: x509.name([]),
    extensions: x509.Extensions(subject_alt_names: []),
  )
}

/// Sets the distinguished name subject for the CSR.
///
/// The subject identifies who the certificate will be issued to.
///
/// ## Parameters
/// - `builder`: The CSR builder
/// - `subject`: A distinguished name created with `x509.name`
///
/// ## Returns
/// The updated builder.
pub fn with_subject(builder: Builder, subject: x509.Name) -> Builder {
  Builder(..builder, subject:)
}

/// Adds a DNS name to the Subject Alternative Names extension.
///
/// SANs allow a certificate to be valid for multiple hostnames. Modern
/// browsers require the domain to appear in the SAN extension, not just
/// the Common Name.
///
/// ## Parameters
/// - `builder`: The CSR builder
/// - `name`: A DNS hostname (e.g., "example.com" or "*.example.com")
///
/// ## Returns
/// - `Ok(Builder)` with the updated builder
/// - `Error(Nil)` if the DNS name contains non-ASCII characters
pub fn with_dns_name(builder: Builder, name: String) -> Result(Builder, Nil) {
  use <- bool.guard(when: !utils.is_ascii(name), return: Error(Nil))
  let x509.Extensions(sans) = builder.extensions
  Ok(
    Builder(
      ..builder,
      extensions: x509.Extensions(subject_alt_names: [
        x509.DnsName(name),
        ..sans
      ]),
    ),
  )
}

/// Adds an email address to the Subject Alternative Names extension.
///
/// Used for S/MIME certificates where the certificate should be valid
/// for a specific email address.
///
/// ## Parameters
/// - `builder`: The CSR builder
/// - `email`: An email address (e.g., "user@example.com")
///
/// ## Returns
/// - `Ok(Builder)` with the updated builder
/// - `Error(Nil)` if the email contains non-ASCII characters
pub fn with_email(builder: Builder, email: String) -> Result(Builder, Nil) {
  use <- bool.guard(when: !utils.is_ascii(email), return: Error(Nil))
  let x509.Extensions(sans) = builder.extensions
  Ok(
    Builder(
      ..builder,
      extensions: x509.Extensions(subject_alt_names: [x509.Email(email), ..sans]),
    ),
  )
}

/// Adds an IP address to the Subject Alternative Names extension.
///
/// Allows the certificate to be valid when accessed by IP address instead
/// of hostname.
///
/// ## Parameters
/// - `builder`: The CSR builder
/// - `ip`: An IPv4 address (e.g., "192.168.1.1") or IPv6 address
///   (e.g., "2001:db8::1", "::1")
///
/// ## Returns
/// - `Ok(Builder)` with the updated builder
/// - `Error(Nil)` if the IP address cannot be parsed
pub fn with_ip(builder: Builder, ip: String) -> Result(Builder, Nil) {
  use parsed <- result.try(parse_ip(ip))
  let x509.Extensions(sans) = builder.extensions
  Ok(
    Builder(
      ..builder,
      extensions: x509.Extensions(subject_alt_names: [
        x509.IpAddress(parsed),
        ..sans
      ]),
    ),
  )
}

/// Signs the CSR with an ECDSA private key.
///
/// The public key is derived from the private key and included in the CSR.
/// The resulting CSR can be submitted to a Certificate Authority.
///
/// ## Parameters
/// - `builder`: The configured CSR builder
/// - `key`: An EC private key from `ec.generate_key_pair`
/// - `hash`: The hash algorithm for signing. Recommended: `Sha256` for P-256,
///   `Sha384` for P-384, `Sha512` for P-521. Note: `Sha1` is supported for
///   legacy compatibility but is cryptographically weak and should be avoided.
///
/// ## Returns
/// - `Ok(Csr(Built))` containing the signed CSR
/// - `Error(Nil)` if the hash algorithm is not supported or the public key
///   cannot be encoded
pub fn sign_with_ecdsa(
  builder: Builder,
  key: ec.PrivateKey,
  hash: HashAlgorithm,
) -> Result(Csr(Built), Nil) {
  use sig_alg <- result.try(x509_internal.ecdsa_sig_alg_info(hash))
  let public_key = ec.public_key_from_private_key(key)
  use spki <- result.try(ec.public_key_to_der(public_key))
  use cert_request_info <- result.try(encode_certification_request_info(
    builder,
    spki,
  ))
  let signature = ecdsa.sign(key, cert_request_info, hash)
  use csr_der <- result.try(encode_csr(cert_request_info, sig_alg, signature))
  Ok(BuiltCsr(csr_der))
}

/// Signs the CSR with an RSA private key using PKCS#1 v1.5 padding.
///
/// The public key is derived from the private key and included in the CSR.
/// The resulting CSR can be submitted to a Certificate Authority.
///
/// ## Parameters
/// - `builder`: The configured CSR builder
/// - `key`: An RSA private key from `rsa.generate_key_pair`
/// - `hash`: The hash algorithm for signing. Recommended: `Sha256` for 2048-bit
///   keys, `Sha384` or `Sha512` for 3072-bit or larger keys. Note: `Sha1` is
///   supported for legacy compatibility but is cryptographically weak and
///   should be avoided.
///
/// ## Returns
/// - `Ok(Csr(Built))` containing the signed CSR
/// - `Error(Nil)` if the hash algorithm is not supported or the public key
///   cannot be encoded
pub fn sign_with_rsa(
  builder: Builder,
  key: rsa.PrivateKey,
  hash: HashAlgorithm,
) -> Result(Csr(Built), Nil) {
  use sig_alg <- result.try(x509_internal.rsa_sig_alg_info(hash))
  let public_key = rsa.public_key_from_private_key(key)
  use spki <- result.try(rsa.public_key_to_der(public_key, rsa.Spki))
  use cert_request_info <- result.try(encode_certification_request_info(
    builder,
    spki,
  ))
  let signature = rsa.sign(key, cert_request_info, hash, rsa.Pkcs1v15)
  use csr_der <- result.try(encode_csr(cert_request_info, sig_alg, signature))
  Ok(BuiltCsr(csr_der))
}

/// Signs the CSR with an EdDSA private key (Ed25519 or Ed448).
///
/// **Note**: Support for EdDSA is limited with browsers and certificate
/// authorities.
///
/// ## Parameters
/// - `builder`: The configured CSR builder
/// - `key`: An EdDSA private key from `eddsa.generate_key_pair`
///
/// ## Returns
/// - `Ok(Csr(Built))` containing the signed CSR
/// - `Error(Nil)` if the public key cannot be encoded
pub fn sign_with_eddsa(
  builder: Builder,
  key: eddsa.PrivateKey,
) -> Result(Csr(Built), Nil) {
  let sig_alg = x509_internal.eddsa_sig_alg_info(eddsa.curve(key))
  let public_key = eddsa.public_key_from_private_key(key)
  use spki <- result.try(eddsa.public_key_to_der(public_key))
  use cert_request_info <- result.try(encode_certification_request_info(
    builder,
    spki,
  ))
  let signature = eddsa.sign(key, cert_request_info)
  use csr_der <- result.try(encode_csr(cert_request_info, sig_alg, signature))
  Ok(BuiltCsr(csr_der))
}

/// Exports the CSR as DER-encoded bytes.
///
/// DER (Distinguished Encoding Rules) is a binary format commonly used
/// for programmatic certificate handling.
///
/// ## Parameters
/// - `csr`: The signed CSR (either built or parsed)
///
/// ## Returns
/// The raw DER-encoded CSR bytes.
pub fn to_der(csr: Csr(a)) -> BitArray {
  case csr {
    BuiltCsr(der) -> der
    ParsedCsr(der, ..) -> der
  }
}

/// Exports the CSR as a PEM-encoded string.
///
/// PEM (Privacy-Enhanced Mail) is a Base64-encoded format with header and
/// footer lines. This is the format typically required when submitting
/// a CSR to a Certificate Authority.
///
/// ## Parameters
/// - `csr`: The signed CSR (either built or parsed)
///
/// ## Returns
/// A PEM-encoded string with `-----BEGIN CERTIFICATE REQUEST-----` headers.
pub fn to_pem(csr: Csr(a)) -> String {
  x509_internal.encode_pem(to_der(csr), pem_begin, pem_end)
}

/// Parse a PEM-encoded CSR and verify its signature.
///
/// Returns an error if the PEM is invalid, the structure is malformed,
/// or the signature doesn't verify against the embedded public key.
pub fn from_pem(pem: String) -> Result(Csr(Parsed), CsrError) {
  use der <- result.try(decode_csr_pem(pem) |> result.replace_error(InvalidPem))
  from_der(der)
}

/// Parse a DER-encoded CSR and verify its signature.
pub fn from_der(der: BitArray) -> Result(Csr(Parsed), CsrError) {
  use parsed <- result.try(from_der_unverified(der))
  use _ <- result.try(verify_signature(parsed))
  Ok(parsed)
}

/// Parse a PEM-encoded CSR without verifying the signature.
///
/// Useful for debugging malformed or partially valid CSRs.
/// The parsed fields may not be trustworthy.
pub fn from_pem_unverified(pem: String) -> Result(Csr(Parsed), CsrError) {
  use der <- result.try(decode_csr_pem(pem) |> result.replace_error(InvalidPem))
  from_der_unverified(der)
}

/// Parse a DER-encoded CSR without verifying the signature.
///
/// Useful for debugging malformed or partially valid CSRs.
/// The parsed fields may not be trustworthy since the signature
/// was not verified.
pub fn from_der_unverified(der: BitArray) -> Result(Csr(Parsed), CsrError) {
  use raw <- result.try(
    p.run(csr_parser(), on: der)
    |> result.replace_error(InvalidStructure),
  )

  use version <- result.try(parse_version(raw.info.version))

  use public_key <- result.try(
    x509_internal.dispatch_public_key_parse(
      raw.info.spki_alg_oid,
      raw.info.spki_bytes,
    )
    |> result.map_error(fn(oid) {
      case oid {
        x509.Oid([]) -> InvalidStructure
        _ -> UnsupportedKeyType(oid)
      }
    }),
  )

  use signature_algorithm <- result.try(
    x509_internal.lookup_signature_algorithm(raw.sig_alg_oid)
    |> result.map_error(UnsupportedSignatureAlgorithm),
  )

  use #(subject_alt_names, extensions, attributes) <- result.try(
    process_attributes(raw.info.raw_attributes)
    |> result.replace_error(InvalidStructure),
  )

  Ok(ParsedCsr(
    der:,
    cert_req_info_bytes: raw.cert_req_info_bytes,
    signature: raw.signature,
    version:,
    subject: raw.info.subject,
    public_key:,
    signature_algorithm:,
    subject_alt_names:,
    extensions:,
    attributes:,
  ))
}

/// Returns the version of a parsed CSR.
///
/// PKCS#10 v1 CSRs always have version 0.
///
/// ## Parameters
/// - `csr`: A parsed CSR
///
/// ## Returns
/// The version number (always 0 for PKCS#10 v1).
pub fn version(csr: Csr(Parsed)) -> Int {
  let assert ParsedCsr(version:, ..) = csr
  version
}

/// Returns the subject (distinguished name) of a parsed CSR.
///
/// The subject identifies who the certificate is being requested for.
///
/// ## Parameters
/// - `csr`: A parsed CSR
///
/// ## Returns
/// The subject as a distinguished name.
pub fn subject(csr: Csr(Parsed)) -> x509.Name {
  let assert ParsedCsr(subject:, ..) = csr
  subject
}

/// Returns the public key embedded in a parsed CSR.
///
/// This is the key that the requester wants certified.
///
/// ## Parameters
/// - `csr`: A parsed CSR
///
/// ## Returns
/// The subject's public key (RSA, EC, or EdDSA).
pub fn public_key(csr: Csr(Parsed)) -> x509.PublicKey {
  let assert ParsedCsr(public_key:, ..) = csr
  public_key
}

/// Returns the signature algorithm used to sign the CSR.
///
/// ## Parameters
/// - `csr`: A parsed CSR
///
/// ## Returns
/// The signature algorithm identifier.
pub fn signature_algorithm(csr: Csr(Parsed)) -> x509.SignatureAlgorithm {
  let assert ParsedCsr(signature_algorithm:, ..) = csr
  signature_algorithm
}

/// Returns the Subject Alternative Names from the CSR.
///
/// ## Parameters
/// - `csr`: A parsed CSR
///
/// ## Returns
/// List of SANs (DNS names, emails, IPs), or empty list if no SAN extension
/// was requested.
pub fn subject_alt_names(csr: Csr(Parsed)) -> List(x509.SubjectAltName) {
  let assert ParsedCsr(subject_alt_names:, ..) = csr
  subject_alt_names
}

/// Returns any extensions beyond SANs as raw (OID, critical, value) tuples.
///
/// This allows access to extensions that kryptos doesn't have typed
/// representations for. The Bool indicates whether the extension was
/// marked as critical per RFC 5280.
pub fn extensions(csr: Csr(Parsed)) -> List(#(x509.Oid, Bool, BitArray)) {
  let assert ParsedCsr(extensions:, ..) = csr
  extensions
}

/// Returns any non-extension attributes as raw (OID, value) pairs.
///
/// Most CSRs only have the extensionRequest attribute, so this is
/// typically empty.
pub fn attributes(csr: Csr(Parsed)) -> List(#(x509.Oid, BitArray)) {
  let assert ParsedCsr(attributes:, ..) = csr
  attributes
}

fn decode_csr_pem(pem: String) -> Result(BitArray, Nil) {
  case x509_internal.decode_pem(pem, pem_begin, pem_end) {
    Ok(der) -> Ok(der)
    Error(_) -> x509_internal.decode_pem(pem, pem_new_begin, pem_new_end)
  }
}

fn parse_version(bytes: BitArray) -> Result(Int, CsrError) {
  case bytes {
    <<0>> -> Ok(0)
    <<v>> -> Error(UnsupportedVersion(v))
    _ -> Error(InvalidStructure)
  }
}

type RawCertReqInfo {
  RawCertReqInfo(
    version: BitArray,
    subject: x509.Name,
    spki_alg_oid: List(Int),
    spki_bytes: BitArray,
    raw_attributes: Option(List(#(List(Int), BitArray))),
  )
}

type RawCsr {
  RawCsr(
    cert_req_info_bytes: BitArray,
    info: RawCertReqInfo,
    sig_alg_oid: List(Int),
    signature: BitArray,
  )
}

fn single_attribute_parser() -> p.Parser(#(List(Int), BitArray)) {
  p.pair(der.oid(), der.set(b.rest()))
}

fn cert_req_info_parser() -> p.Parser(RawCertReqInfo) {
  use version <- p.then(der.integer())
  use subject <- p.then(der.sequence(x509_internal.name()))
  use #(spki_alg_oid, spki_bytes) <- p.then(x509_internal.public_key_info())
  use raw_attributes <- p.then(
    p.optional(der.context_tag(
      0,
      p.many(der.sequence(single_attribute_parser())),
    )),
  )
  p.success(RawCertReqInfo(
    version:,
    subject:,
    spki_alg_oid:,
    spki_bytes:,
    raw_attributes:,
  ))
}

fn csr_parser() -> p.Parser(RawCsr) {
  der.sequence({
    use #(cert_req_info_bytes, info) <- p.then(
      der.sequence_with_raw(cert_req_info_parser()),
    )
    use sig_alg_oid <- p.then(
      der.sequence(x509_internal.signature_algorithm_oid()),
    )
    use signature <- p.then(der.bit_string())
    p.success(RawCsr(cert_req_info_bytes:, info:, sig_alg_oid:, signature:))
  })
}

fn process_attributes(
  raw_attributes: Option(List(#(List(Int), BitArray))),
) -> Result(
  #(
    List(x509.SubjectAltName),
    List(#(x509.Oid, Bool, BitArray)),
    List(#(x509.Oid, BitArray)),
  ),
  Nil,
) {
  case raw_attributes {
    option.None -> Ok(#([], [], []))
    option.Some(attrs) -> process_attributes_loop(attrs, [], [], [])
  }
}

fn process_attributes_loop(
  attrs: List(#(List(Int), BitArray)),
  sans: List(x509.SubjectAltName),
  exts: List(#(x509.Oid, Bool, BitArray)),
  other: List(#(x509.Oid, BitArray)),
) -> Result(
  #(
    List(x509.SubjectAltName),
    List(#(x509.Oid, Bool, BitArray)),
    List(#(x509.Oid, BitArray)),
  ),
  Nil,
) {
  case attrs {
    [] -> Ok(#(sans, list.reverse(exts), list.reverse(other)))
    [#([1, 2, 840, 113_549, 1, 9, 14], value), ..rest] -> {
      use #(new_sans, new_exts) <- result.try(parse_extension_request(value))
      process_attributes_loop(
        rest,
        list.append(sans, new_sans),
        list.append(exts, new_exts),
        other,
      )
    }
    [#(oid, value), ..rest] ->
      process_attributes_loop(rest, sans, exts, [
        #(x509.Oid(oid), value),
        ..other
      ])
  }
}

fn parse_extension_request(
  bytes: BitArray,
) -> Result(
  #(List(x509.SubjectAltName), List(#(x509.Oid, Bool, BitArray))),
  Nil,
) {
  use <- bool.guard(
    when: bit_array.byte_size(bytes) == 0,
    return: Ok(#([], [])),
  )
  use #(exts_content, _) <- result.try(
    p.run_partial(der.sequence(b.rest()), on: bytes)
    |> result.replace_error(Nil),
  )
  parse_extensions(exts_content, [], [])
}

fn parse_extensions(
  bytes: BitArray,
  sans: List(x509.SubjectAltName),
  exts: List(#(x509.Oid, Bool, BitArray)),
) -> Result(
  #(List(x509.SubjectAltName), List(#(x509.Oid, Bool, BitArray))),
  Nil,
) {
  case bytes {
    <<>> -> Ok(#(sans, list.reverse(exts)))
    _ -> {
      use #(ext_bytes, rest) <- result.try(
        p.run_partial(der.sequence(b.rest()), on: bytes)
        |> result.replace_error(Nil),
      )
      use #(oid, is_critical, value) <- result.try(
        p.run(x509_internal.single_extension(), on: ext_bytes)
        |> result.replace_error(Nil),
      )
      case oid {
        x509.Oid([2, 5, 29, 17]) -> {
          use new_sans <- result.try(
            p.run(x509_internal.san_extension(False), on: value)
            |> result.replace_error(Nil),
          )
          parse_extensions(rest, list.append(sans, new_sans), exts)
        }
        _ -> parse_extensions(rest, sans, [#(oid, is_critical, value), ..exts])
      }
    }
  }
}

fn verify_signature(csr: Csr(Parsed)) -> Result(Nil, CsrError) {
  let assert ParsedCsr(
    cert_req_info_bytes:,
    signature:,
    public_key:,
    signature_algorithm:,
    ..,
  ) = csr

  let verified =
    x509_internal.verify_signature(
      public_key,
      cert_req_info_bytes,
      signature,
      signature_algorithm,
    )

  case verified {
    True -> Ok(Nil)
    False -> Error(SignatureVerificationFailed)
  }
}

fn encode_csr(
  cert_request_info: BitArray,
  sig_alg: SigAlgInfo,
  signature: BitArray,
) -> Result(BitArray, Nil) {
  use sig_alg_der <- result.try(x509_internal.encode_algorithm_identifier(
    sig_alg,
  ))
  use sig_bits <- result.try(der.encode_bit_string(signature))
  der.encode_sequence(
    bit_array.concat([cert_request_info, sig_alg_der, sig_bits]),
  )
}

fn encode_certification_request_info(
  builder: Builder,
  spki: BitArray,
) -> Result(BitArray, Nil) {
  use version <- result.try(der.encode_integer(<<0>>))
  use subject <- result.try(x509_internal.encode_name(builder.subject))
  use attributes <- result.try(encode_attributes(builder.extensions))
  der.encode_sequence(bit_array.concat([version, subject, spki, attributes]))
}

fn encode_attributes(extensions: x509.Extensions) -> Result(BitArray, Nil) {
  case list.is_empty(extensions.subject_alt_names) {
    True -> der.encode_context_tag(0, <<>>)
    False ->
      extensions
      |> encode_extension_request
      |> result.try(der.encode_context_tag(0, _))
  }
}

fn encode_extension_request(
  extensions: x509.Extensions,
) -> Result(BitArray, Nil) {
  let x509.Oid(ext_req_components) = oid_extension_request
  use oid_encoded <- result.try(der.encode_oid(ext_req_components))

  extensions
  |> encode_extensions
  |> result.try(der.encode_set)
  |> result.map(fn(set_encoded) { bit_array.concat([oid_encoded, set_encoded]) })
  |> result.try(der.encode_sequence)
}

fn encode_extensions(extensions: x509.Extensions) -> Result(BitArray, Nil) {
  let x509.Extensions(sans) = extensions

  x509_internal.encode_san_extension(sans, False)
  |> result.try(der.encode_sequence)
}
