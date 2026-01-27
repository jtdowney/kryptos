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

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import gleam/string_tree
import kryptos/ec
import kryptos/ecdsa
import kryptos/eddsa
import kryptos/hash.{type HashAlgorithm}
import kryptos/internal/der
import kryptos/internal/utils
import kryptos/rsa
import kryptos/x509.{
  type Extensions, type Name, type Oid, type PublicKey, type Rdn,
  type SignatureAlgorithm, type SubjectAltName, DnsName, EcPublicKey, EcdsaSha1,
  EcdsaSha256, EcdsaSha384, EcdsaSha512, Ed25519, Ed448, EdPublicKey, Email,
  Extensions, IpAddress, Name, Oid, Rdn, RsaPublicKey, RsaSha1, RsaSha256,
  RsaSha384, RsaSha512, Unknown,
}

const oid_extension_request = Oid([1, 2, 840, 113_549, 1, 9, 14])

const oid_subject_alt_name = Oid([2, 5, 29, 17])

const oid_rsa_with_sha1 = Oid([1, 2, 840, 113_549, 1, 1, 5])

const oid_rsa_with_sha256 = Oid([1, 2, 840, 113_549, 1, 1, 11])

const oid_rsa_with_sha384 = Oid([1, 2, 840, 113_549, 1, 1, 12])

const oid_rsa_with_sha512 = Oid([1, 2, 840, 113_549, 1, 1, 13])

const oid_ecdsa_with_sha1 = Oid([1, 2, 840, 10_045, 4, 1])

const oid_ecdsa_with_sha256 = Oid([1, 2, 840, 10_045, 4, 3, 2])

const oid_ecdsa_with_sha384 = Oid([1, 2, 840, 10_045, 4, 3, 3])

const oid_ecdsa_with_sha512 = Oid([1, 2, 840, 10_045, 4, 3, 4])

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
    version: Int,
    subject: Name,
    public_key: PublicKey,
    signature_algorithm: SignatureAlgorithm,
    subject_alt_names: List(SubjectAltName),
    extensions: List(#(Oid, BitArray)),
    attributes: List(#(Oid, BitArray)),
  )
}

/// Error type for CSR parsing failures.
pub type CsrError {
  InvalidPem
  InvalidStructure
  UnsupportedSignatureAlgorithm(Oid)
  UnsupportedKeyType(Oid)
  SignatureVerificationFailed
  UnsupportedVersion(Int)
}

/// A builder for constructing CSRs.
pub opaque type Builder {
  Builder(subject: Name, extensions: Extensions)
}

/// Creates a new CSR builder with an empty subject and no extensions.
///
/// Use the `with_*` functions to configure the builder, then call
/// `sign_with_ecdsa` or `sign_with_rsa` to generate the signed CSR.
///
/// ## Returns
/// A new Builder ready for configuration.
pub fn new() -> Builder {
  Builder(subject: x509.name([]), extensions: Extensions(subject_alt_names: []))
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
pub fn with_subject(builder: Builder, subject: Name) -> Builder {
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
  let Extensions(sans) = builder.extensions
  Ok(
    Builder(
      ..builder,
      extensions: Extensions(subject_alt_names: [DnsName(name), ..sans]),
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
  let Extensions(sans) = builder.extensions
  Ok(
    Builder(
      ..builder,
      extensions: Extensions(subject_alt_names: [Email(email), ..sans]),
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
  let Extensions(sans) = builder.extensions
  Ok(
    Builder(
      ..builder,
      extensions: Extensions(subject_alt_names: [IpAddress(parsed), ..sans]),
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
  use sig_alg <- result.try(ecdsa_sig_alg_info(hash))
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
  use sig_alg <- result.try(rsa_sig_alg_info(hash))
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
  let der = to_der(csr)
  let encoded = bit_array.base64_encode(der, True)
  let lines =
    utils.chunk_string(encoded, 64)
    |> list.map(fn(line) { line <> "\n" })

  string_tree.new()
  |> string_tree.append("-----BEGIN CERTIFICATE REQUEST-----\n")
  |> string_tree.append_tree(string_tree.from_strings(lines))
  |> string_tree.append("-----END CERTIFICATE REQUEST-----\n\n")
  |> string_tree.to_string
}

/// Parse a PEM-encoded CSR and verify its signature.
///
/// Returns an error if the PEM is invalid, the structure is malformed,
/// or the signature doesn't verify against the embedded public key.
pub fn from_pem(pem: String) -> Result(Csr(Parsed), CsrError) {
  use der <- result.try(decode_pem(pem))
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
  use der <- result.try(decode_pem(pem))
  from_der_unverified(der)
}

/// Parse a DER-encoded CSR without verifying the signature.
pub fn from_der_unverified(der: BitArray) -> Result(Csr(Parsed), CsrError) {
  use #(csr_content, _) <- result.try(
    der.parse_sequence(der) |> result.replace_error(InvalidStructure),
  )

  // Parse CertificationRequestInfo - we need to preserve the original bytes
  use #(cert_req_info_bytes, after_info) <- result.try(
    extract_sequence_with_header(csr_content)
    |> result.replace_error(InvalidStructure),
  )

  // Parse the inner content of CertificationRequestInfo
  use #(cert_req_info_content, _) <- result.try(
    der.parse_sequence(cert_req_info_bytes)
    |> result.replace_error(InvalidStructure),
  )

  // Parse version (INTEGER)
  use #(version_bytes, after_version) <- result.try(
    der.parse_integer(cert_req_info_content)
    |> result.replace_error(InvalidStructure),
  )
  use version <- result.try(parse_version(version_bytes))

  // Parse subject (Name)
  use #(subject_bytes, after_subject) <- result.try(
    der.parse_sequence(after_version) |> result.replace_error(InvalidStructure),
  )
  use subject <- result.try(parse_name(subject_bytes))

  // Parse SubjectPublicKeyInfo
  use #(spki_bytes, after_spki) <- result.try(
    extract_sequence_with_header(after_subject)
    |> result.replace_error(InvalidStructure),
  )
  use public_key <- result.try(parse_public_key(spki_bytes))

  // Parse attributes [0] (optional)
  use #(subject_alt_names, extensions, attributes) <- result.try(
    parse_attributes(after_spki) |> result.replace_error(InvalidStructure),
  )

  // Parse signature algorithm
  use #(sig_alg_bytes, after_sig_alg) <- result.try(
    der.parse_sequence(after_info) |> result.replace_error(InvalidStructure),
  )
  use signature_algorithm <- result.try(parse_signature_algorithm(sig_alg_bytes))

  // Parse signature (BIT STRING) - store for verification
  use #(_signature, _) <- result.try(
    der.parse_bit_string(after_sig_alg)
    |> result.replace_error(InvalidStructure),
  )

  Ok(ParsedCsr(
    der:,
    version:,
    subject:,
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
pub fn version(csr: Csr(Parsed)) -> Int {
  let assert ParsedCsr(version:, ..) = csr
  version
}

/// Returns the subject (distinguished name) of a parsed CSR.
pub fn subject(csr: Csr(Parsed)) -> Name {
  let assert ParsedCsr(subject:, ..) = csr
  subject
}

/// Returns the public key embedded in a parsed CSR.
pub fn public_key(csr: Csr(Parsed)) -> PublicKey {
  let assert ParsedCsr(public_key:, ..) = csr
  public_key
}

/// Returns the signature algorithm used to sign the CSR.
pub fn signature_algorithm(csr: Csr(Parsed)) -> SignatureAlgorithm {
  let assert ParsedCsr(signature_algorithm:, ..) = csr
  signature_algorithm
}

/// Returns the Subject Alternative Names from the CSR.
///
/// Returns an empty list if no SAN extension was requested.
pub fn subject_alt_names(csr: Csr(Parsed)) -> List(SubjectAltName) {
  let assert ParsedCsr(subject_alt_names:, ..) = csr
  subject_alt_names
}

/// Returns any extensions beyond SANs as raw (OID, value) pairs.
///
/// This allows access to extensions that kryptos doesn't have typed
/// representations for.
pub fn extensions(csr: Csr(Parsed)) -> List(#(Oid, BitArray)) {
  let assert ParsedCsr(extensions:, ..) = csr
  extensions
}

/// Returns any non-extension attributes as raw (OID, value) pairs.
///
/// Most CSRs only have the extensionRequest attribute, so this is
/// typically empty.
pub fn attributes(csr: Csr(Parsed)) -> List(#(Oid, BitArray)) {
  let assert ParsedCsr(attributes:, ..) = csr
  attributes
}

fn decode_pem(pem: String) -> Result(BitArray, CsrError) {
  let lines = string.split(pem, "\n")
  let lines = list.map(lines, string.trim)

  use #(body_lines, _found_end) <- result.try(
    extract_pem_body(lines, False, []) |> result.replace_error(InvalidPem),
  )

  let body = string.join(body_lines, "")
  bit_array.base64_decode(body) |> result.replace_error(InvalidPem)
}

fn extract_pem_body(
  lines: List(String),
  in_body: Bool,
  acc: List(String),
) -> Result(#(List(String), Bool), Nil) {
  case lines, in_body {
    [], _ -> Error(Nil)
    [line, ..rest], False -> {
      let is_begin =
        string.starts_with(line, "-----BEGIN CERTIFICATE REQUEST-----")
        || string.starts_with(line, "-----BEGIN NEW CERTIFICATE REQUEST-----")
      case is_begin {
        True -> extract_pem_body(rest, True, acc)
        False -> extract_pem_body(rest, False, acc)
      }
    }
    [line, ..rest], True -> {
      let is_end =
        string.starts_with(line, "-----END CERTIFICATE REQUEST-----")
        || string.starts_with(line, "-----END NEW CERTIFICATE REQUEST-----")
      case is_end {
        True -> Ok(#(list.reverse(acc), True))
        False -> extract_pem_body(rest, True, [line, ..acc])
      }
    }
  }
}

fn extract_sequence_with_header(
  bytes: BitArray,
) -> Result(#(BitArray, BitArray), Nil) {
  // We need to return the full SEQUENCE including tag and length
  case bytes {
    <<0x30, _:bits>> -> {
      use #(inner, remaining) <- result.try(der.parse_sequence(bytes))
      // Reconstruct the full sequence with header
      let inner_len = bit_array.byte_size(inner)
      let header_len =
        bit_array.byte_size(bytes) - bit_array.byte_size(remaining) - inner_len
      let total_len = header_len + inner_len
      let assert Ok(full_seq) = bit_array.slice(bytes, 0, total_len)
      Ok(#(full_seq, remaining))
    }
    _ -> Error(Nil)
  }
}

fn parse_version(bytes: BitArray) -> Result(Int, CsrError) {
  case bytes {
    <<0>> -> Ok(0)
    <<v>> -> Error(UnsupportedVersion(v))
    _ -> Error(InvalidStructure)
  }
}

fn parse_name(bytes: BitArray) -> Result(Name, CsrError) {
  parse_rdns(bytes, [])
  |> result.replace_error(InvalidStructure)
  |> result.map(Name)
}

fn parse_rdns(bytes: BitArray, acc: List(Rdn)) -> Result(List(Rdn), Nil) {
  use <- bool.guard(when: bytes == <<>>, return: Ok(list.reverse(acc)))
  use #(rdn_bytes, rest) <- result.try(der.parse_set(bytes))
  use attrs <- result.try(parse_rdn_attributes(rdn_bytes, []))
  parse_rdns(rest, [Rdn(attributes: attrs), ..acc])
}

fn parse_rdn_attributes(
  bytes: BitArray,
  acc: List(#(Oid, x509.AttributeValue)),
) -> Result(List(#(Oid, x509.AttributeValue)), Nil) {
  use <- bool.guard(when: bytes == <<>>, return: Ok(list.reverse(acc)))
  use #(attr_bytes, rest) <- result.try(der.parse_sequence(bytes))
  use #(oid_components, after_oid) <- result.try(der.parse_oid(attr_bytes))
  use #(value, _) <- result.try(parse_attribute_value(after_oid))
  parse_rdn_attributes(rest, [#(Oid(oid_components), value), ..acc])
}

fn parse_attribute_value(
  bytes: BitArray,
) -> Result(#(x509.AttributeValue, BitArray), Nil) {
  case bytes {
    <<0x0c, _:bits>> -> {
      use #(s, rest) <- result.try(der.parse_utf8_string(bytes))
      Ok(#(x509.utf8_string(s), rest))
    }
    <<0x13, _:bits>> -> {
      use #(s, rest) <- result.try(der.parse_printable_string(bytes))
      Ok(#(x509.printable_string(s), rest))
    }
    <<0x16, _:bits>> -> {
      use #(s, rest) <- result.try(der.parse_ia5_string(bytes))
      Ok(#(x509.ia5_string(s), rest))
    }
    _ -> Error(Nil)
  }
}

fn parse_public_key(spki_bytes: BitArray) -> Result(PublicKey, CsrError) {
  // Parse the SPKI structure
  use #(spki_content, _) <- result.try(
    der.parse_sequence(spki_bytes) |> result.replace_error(InvalidStructure),
  )

  // Parse algorithm identifier
  use #(alg_id_bytes, after_alg) <- result.try(
    der.parse_sequence(spki_content) |> result.replace_error(InvalidStructure),
  )

  // Get the algorithm OID
  use #(alg_oid, _alg_params) <- result.try(
    der.parse_oid(alg_id_bytes) |> result.replace_error(InvalidStructure),
  )

  // Parse the public key bit string
  use #(_key_bits, _) <- result.try(
    der.parse_bit_string(after_alg) |> result.replace_error(InvalidStructure),
  )

  // Dispatch based on algorithm OID
  case alg_oid {
    [1, 2, 840, 10_045, 2, 1] -> {
      // EC public key - use the FFI to parse
      use key <- result.try(
        ec.public_key_from_der(spki_bytes)
        |> result.replace_error(InvalidStructure),
      )
      Ok(EcPublicKey(key))
    }
    [1, 2, 840, 113_549, 1, 1, 1] -> {
      // RSA public key
      use key <- result.try(
        rsa.public_key_from_der(spki_bytes, rsa.Spki)
        |> result.replace_error(InvalidStructure),
      )
      Ok(RsaPublicKey(key))
    }
    [1, 3, 101, 112] -> {
      // Ed25519
      use key <- result.try(
        eddsa.public_key_from_der(spki_bytes)
        |> result.replace_error(InvalidStructure),
      )
      Ok(EdPublicKey(key))
    }
    [1, 3, 101, 113] -> {
      // Ed448
      use key <- result.try(
        eddsa.public_key_from_der(spki_bytes)
        |> result.replace_error(InvalidStructure),
      )
      Ok(EdPublicKey(key))
    }
    _ -> Error(UnsupportedKeyType(Oid(alg_oid)))
  }
}

fn parse_signature_algorithm(
  bytes: BitArray,
) -> Result(SignatureAlgorithm, CsrError) {
  use #(oid_components, _params) <- result.try(
    der.parse_oid(bytes) |> result.replace_error(InvalidStructure),
  )

  case oid_components {
    // RSA with SHA-*
    [1, 2, 840, 113_549, 1, 1, 5] -> Ok(RsaSha1)
    [1, 2, 840, 113_549, 1, 1, 11] -> Ok(RsaSha256)
    [1, 2, 840, 113_549, 1, 1, 12] -> Ok(RsaSha384)
    [1, 2, 840, 113_549, 1, 1, 13] -> Ok(RsaSha512)
    // ECDSA with SHA-*
    [1, 2, 840, 10_045, 4, 1] -> Ok(EcdsaSha1)
    [1, 2, 840, 10_045, 4, 3, 2] -> Ok(EcdsaSha256)
    [1, 2, 840, 10_045, 4, 3, 3] -> Ok(EcdsaSha384)
    [1, 2, 840, 10_045, 4, 3, 4] -> Ok(EcdsaSha512)
    // EdDSA
    [1, 3, 101, 112] -> Ok(Ed25519)
    [1, 3, 101, 113] -> Ok(Ed448)
    _ -> Error(UnsupportedSignatureAlgorithm(Oid(oid_components)))
  }
}

fn parse_attributes(
  bytes: BitArray,
) -> Result(
  #(List(SubjectAltName), List(#(Oid, BitArray)), List(#(Oid, BitArray))),
  Nil,
) {
  case der.parse_context_tag(bytes, 0) {
    Ok(#(attrs_content, _)) ->
      parse_attributes_content(attrs_content, [], [], [])
    Error(_) -> Ok(#([], [], []))
  }
}

fn parse_attributes_content(
  bytes: BitArray,
  sans: List(SubjectAltName),
  exts: List(#(Oid, BitArray)),
  attrs: List(#(Oid, BitArray)),
) -> Result(
  #(List(SubjectAltName), List(#(Oid, BitArray)), List(#(Oid, BitArray))),
  Nil,
) {
  case bytes {
    <<>> -> Ok(#(list.reverse(sans), list.reverse(exts), list.reverse(attrs)))
    _ -> {
      use #(attr_bytes, rest) <- result.try(der.parse_sequence(bytes))
      use #(oid, value) <- result.try(parse_single_attribute(attr_bytes))
      case oid {
        Oid([1, 2, 840, 113_549, 1, 9, 14]) -> {
          use #(new_sans, new_exts) <- result.try(parse_extension_request(value))
          parse_attributes_content(
            rest,
            list.append(sans, new_sans),
            list.append(exts, new_exts),
            attrs,
          )
        }
        _ ->
          parse_attributes_content(rest, sans, exts, [#(oid, value), ..attrs])
      }
    }
  }
}

fn parse_single_attribute(bytes: BitArray) -> Result(#(Oid, BitArray), Nil) {
  use #(oid_components, after_oid) <- result.try(der.parse_oid(bytes))
  // The value is in a SET
  use #(value, _) <- result.try(der.parse_set(after_oid))
  Ok(#(Oid(oid_components), value))
}

fn parse_extension_request(
  bytes: BitArray,
) -> Result(#(List(SubjectAltName), List(#(Oid, BitArray))), Nil) {
  use <- bool.guard(when: bytes == <<>>, return: Ok(#([], [])))
  use #(exts_content, _) <- result.try(der.parse_sequence(bytes))
  parse_extensions(exts_content, [], [])
}

fn parse_extensions(
  bytes: BitArray,
  sans: List(SubjectAltName),
  exts: List(#(Oid, BitArray)),
) -> Result(#(List(SubjectAltName), List(#(Oid, BitArray))), Nil) {
  case bytes {
    <<>> -> Ok(#(list.reverse(sans), list.reverse(exts)))
    _ -> {
      use #(ext_bytes, rest) <- result.try(der.parse_sequence(bytes))
      use #(oid, value) <- result.try(parse_single_extension(ext_bytes))
      case oid {
        Oid([2, 5, 29, 17]) -> {
          use new_sans <- result.try(parse_san_extension(value))
          parse_extensions(rest, list.append(sans, new_sans), exts)
        }
        _ -> parse_extensions(rest, sans, [#(oid, value), ..exts])
      }
    }
  }
}

fn parse_single_extension(bytes: BitArray) -> Result(#(Oid, BitArray), Nil) {
  use #(oid_components, after_oid) <- result.try(der.parse_oid(bytes))
  // Skip optional critical flag if present (BOOLEAN)
  let after_critical = case after_oid {
    <<0x01, 0x01, _, rest:bits>> -> rest
    other -> other
  }
  // Parse the value (OCTET STRING)
  use #(value, _) <- result.try(der.parse_octet_string(after_critical))
  Ok(#(Oid(oid_components), value))
}

fn parse_san_extension(bytes: BitArray) -> Result(List(SubjectAltName), Nil) {
  use #(san_content, _) <- result.try(der.parse_sequence(bytes))
  parse_general_names(san_content, [])
}

fn parse_general_names(
  bytes: BitArray,
  acc: List(SubjectAltName),
) -> Result(List(SubjectAltName), Nil) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    _ -> {
      use #(san, rest) <- result.try(parse_general_name(bytes))
      parse_general_names(rest, [san, ..acc])
    }
  }
}

fn parse_general_name(
  bytes: BitArray,
) -> Result(#(SubjectAltName, BitArray), Nil) {
  use #(tag, value, rest) <- result.try(der.parse_tlv(bytes))

  case tag {
    // rfc822Name (email) - tag [1]
    0x81 -> {
      use s <- result.try(bit_array.to_string(value))
      Ok(#(Email(s), rest))
    }
    // dNSName - tag [2]
    0x82 -> {
      use s <- result.try(bit_array.to_string(value))
      Ok(#(DnsName(s), rest))
    }
    // iPAddress - tag [7]
    0x87 -> Ok(#(IpAddress(value), rest))
    // Unknown general name types
    _ -> Ok(#(Unknown(tag, value), rest))
  }
}

fn verify_signature(csr: Csr(Parsed)) -> Result(Nil, CsrError) {
  let assert ParsedCsr(der:, public_key:, signature_algorithm:, ..) = csr

  // Extract the CertificationRequestInfo and signature from the DER
  use #(csr_content, _) <- result.try(
    der.parse_sequence(der) |> result.replace_error(InvalidStructure),
  )

  use #(cert_req_info_bytes, after_info) <- result.try(
    extract_sequence_with_header(csr_content)
    |> result.replace_error(InvalidStructure),
  )

  // Skip signature algorithm
  use #(_, after_sig_alg) <- result.try(
    der.parse_sequence(after_info) |> result.replace_error(InvalidStructure),
  )

  // Get signature
  use #(signature, _) <- result.try(
    der.parse_bit_string(after_sig_alg)
    |> result.replace_error(InvalidStructure),
  )

  // Verify based on algorithm and key type
  let verified = case public_key, signature_algorithm {
    EcPublicKey(key), EcdsaSha1 ->
      ecdsa.verify(key, cert_req_info_bytes, signature, hash.Sha1)
    EcPublicKey(key), EcdsaSha256 ->
      ecdsa.verify(key, cert_req_info_bytes, signature, hash.Sha256)
    EcPublicKey(key), EcdsaSha384 ->
      ecdsa.verify(key, cert_req_info_bytes, signature, hash.Sha384)
    EcPublicKey(key), EcdsaSha512 ->
      ecdsa.verify(key, cert_req_info_bytes, signature, hash.Sha512)
    RsaPublicKey(key), RsaSha1 ->
      rsa.verify(key, cert_req_info_bytes, signature, hash.Sha1, rsa.Pkcs1v15)
    RsaPublicKey(key), RsaSha256 ->
      rsa.verify(key, cert_req_info_bytes, signature, hash.Sha256, rsa.Pkcs1v15)
    RsaPublicKey(key), RsaSha384 ->
      rsa.verify(key, cert_req_info_bytes, signature, hash.Sha384, rsa.Pkcs1v15)
    RsaPublicKey(key), RsaSha512 ->
      rsa.verify(key, cert_req_info_bytes, signature, hash.Sha512, rsa.Pkcs1v15)
    EdPublicKey(key), Ed25519 ->
      eddsa.verify(key, cert_req_info_bytes, signature)
    EdPublicKey(key), Ed448 -> eddsa.verify(key, cert_req_info_bytes, signature)
    _, _ -> False
  }

  use <- bool.guard(when: !verified, return: Error(SignatureVerificationFailed))
  Ok(Nil)
}

fn encode_csr(
  cert_request_info: BitArray,
  sig_alg: SigAlgInfo,
  signature: BitArray,
) -> Result(BitArray, Nil) {
  let SigAlgInfo(oid, include_null_params) = sig_alg
  use oid_encoded <- result.try(der.encode_oid(oid.components))
  use sig_alg_der <- result.try(case include_null_params {
    True -> der.encode_sequence(bit_array.concat([oid_encoded, <<0x05, 0x00>>]))
    False -> der.encode_sequence(oid_encoded)
  })
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
  use subject <- result.try(encode_name(builder.subject))
  use attributes <- result.try(encode_attributes(builder.extensions))
  der.encode_sequence(bit_array.concat([version, subject, spki, attributes]))
}

fn encode_name(name: Name) -> Result(BitArray, Nil) {
  use encoded_rdns <- result.try(list.try_map(name.rdns, encode_rdn))
  der.encode_sequence(bit_array.concat(encoded_rdns))
}

fn encode_rdn(rdn: x509.Rdn) -> Result(BitArray, Nil) {
  use encoded_attrs <- result.try(list.try_map(
    rdn.attributes,
    encode_attribute_type_and_value,
  ))
  let sorted_attrs = list.sort(encoded_attrs, bit_array.compare)
  der.encode_set(bit_array.concat(sorted_attrs))
}

fn encode_attribute_type_and_value(
  attr: #(Oid, x509.AttributeValue),
) -> Result(BitArray, Nil) {
  let #(Oid(oid_components), value) = attr
  use encoded_value <- result.try(x509.encode_attribute_value(value))
  use oid_encoded <- result.try(der.encode_oid(oid_components))
  der.encode_sequence(bit_array.concat([oid_encoded, encoded_value]))
}

fn encode_attributes(extensions: Extensions) -> Result(BitArray, Nil) {
  use <- bool.guard(
    when: list.is_empty(extensions.subject_alt_names),
    return: der.encode_context_tag(0, <<>>),
  )

  use ext_request <- result.try(encode_extension_request(extensions))
  der.encode_context_tag(0, ext_request)
}

fn encode_extension_request(extensions: Extensions) -> Result(BitArray, Nil) {
  let Oid(ext_req_components) = oid_extension_request
  use exts <- result.try(encode_extensions(extensions))
  use oid_encoded <- result.try(der.encode_oid(ext_req_components))
  use set_encoded <- result.try(der.encode_set(exts))
  der.encode_sequence(bit_array.concat([oid_encoded, set_encoded]))
}

fn encode_extensions(extensions: Extensions) -> Result(BitArray, Nil) {
  let Extensions(sans) = extensions
  use san_ext <- result.try(encode_san_extension(sans))
  der.encode_sequence(san_ext)
}

fn encode_san_extension(sans: List(SubjectAltName)) -> Result(BitArray, Nil) {
  let Oid(san_oid_components) = oid_subject_alt_name
  use san_value <- result.try(encode_general_names(sans))
  use oid_encoded <- result.try(der.encode_oid(san_oid_components))
  use octet_encoded <- result.try(der.encode_octet_string(san_value))
  der.encode_sequence(bit_array.concat([oid_encoded, octet_encoded]))
}

fn encode_general_names(sans: List(SubjectAltName)) -> Result(BitArray, Nil) {
  use encoded <- result.try(
    sans |> list.reverse |> list.try_map(encode_general_name),
  )
  der.encode_sequence(bit_array.concat(encoded))
}

fn encode_general_name(san: SubjectAltName) -> Result(BitArray, Nil) {
  case san {
    DnsName(name) ->
      der.encode_context_primitive_tag(2, bit_array.from_string(name))
    Email(email) ->
      der.encode_context_primitive_tag(1, bit_array.from_string(email))
    IpAddress(ip) -> der.encode_context_primitive_tag(7, ip)
    Unknown(_, _) -> Error(Nil)
  }
}

/// Internal type for signature algorithm encoding.
/// ECDSA algorithms must NOT include NULL parameters, while RSA algorithms MUST include them.
type SigAlgInfo {
  SigAlgInfo(oid: Oid, include_null_params: Bool)
}

fn ecdsa_sig_alg_info(hash: HashAlgorithm) -> Result(SigAlgInfo, Nil) {
  case hash {
    hash.Sha1 -> Ok(SigAlgInfo(oid_ecdsa_with_sha1, False))
    hash.Sha256 -> Ok(SigAlgInfo(oid_ecdsa_with_sha256, False))
    hash.Sha384 -> Ok(SigAlgInfo(oid_ecdsa_with_sha384, False))
    hash.Sha512 -> Ok(SigAlgInfo(oid_ecdsa_with_sha512, False))
    _ -> Error(Nil)
  }
}

fn rsa_sig_alg_info(hash: HashAlgorithm) -> Result(SigAlgInfo, Nil) {
  case hash {
    hash.Sha1 -> Ok(SigAlgInfo(oid_rsa_with_sha1, True))
    hash.Sha256 -> Ok(SigAlgInfo(oid_rsa_with_sha256, True))
    hash.Sha384 -> Ok(SigAlgInfo(oid_rsa_with_sha384, True))
    hash.Sha512 -> Ok(SigAlgInfo(oid_rsa_with_sha512, True))
    _ -> Error(Nil)
  }
}

fn parse_ip(ip: String) -> Result(BitArray, Nil) {
  case string.contains(ip, ":") {
    True -> parse_ipv6(ip)
    False -> parse_ipv4(ip)
  }
}

fn parse_ipv4(ip: String) -> Result(BitArray, Nil) {
  let parts = string.split(ip, ".")
  use <- bool.guard(when: list.length(parts) != 4, return: Error(Nil))
  use bytes <- result.try(list.try_map(parts, parse_ipv4_octet))
  Ok(bit_array.concat(list.map(bytes, fn(b) { <<b:8>> })))
}

fn parse_ipv4_octet(s: String) -> Result(Int, Nil) {
  use n <- result.try(int.parse(s))
  use <- bool.guard(when: n < 0 || n > 255, return: Error(Nil))
  Ok(n)
}

fn parse_ipv6(ip: String) -> Result(BitArray, Nil) {
  let ip = case string.starts_with(ip, "::") {
    True -> "0" <> ip
    False -> ip
  }
  let ip = case string.ends_with(ip, "::") {
    True -> ip <> "0"
    False -> ip
  }

  case string.contains(ip, "::") {
    True -> parse_ipv6_compressed(ip)
    False -> parse_ipv6_full(ip)
  }
}

fn parse_ipv6_full(ip: String) -> Result(BitArray, Nil) {
  let parts = string.split(ip, ":")
  use <- bool.guard(when: list.length(parts) != 8, return: Error(Nil))
  use words <- result.try(list.try_map(parts, parse_ipv6_word))
  Ok(bit_array.concat(list.map(words, fn(w) { <<w:16>> })))
}

fn parse_ipv6_compressed(ip: String) -> Result(BitArray, Nil) {
  use #(left, right) <- result.try(case string.split(ip, "::") {
    [l, r] -> Ok(#(l, r))
    _ -> Error(Nil)
  })

  let left_parts = case left {
    "" -> []
    _ -> string.split(left, ":")
  }
  let right_parts = case right {
    "" -> []
    _ -> string.split(right, ":")
  }

  let total = list.length(left_parts) + list.length(right_parts)
  use <- bool.guard(when: total > 7, return: Error(Nil))

  let zeros = list.repeat(0, 8 - total)
  use left_words <- result.try(list.try_map(left_parts, parse_ipv6_word))
  use right_words <- result.try(list.try_map(right_parts, parse_ipv6_word))
  let all_words = list.flatten([left_words, zeros, right_words])
  Ok(bit_array.concat(list.map(all_words, fn(w) { <<w:16>> })))
}

fn parse_ipv6_word(s: String) -> Result(Int, Nil) {
  use n <- result.try(int.base_parse(s, 16))
  use <- bool.guard(when: n < 0 || n > 0xffff, return: Error(Nil))
  Ok(n)
}
