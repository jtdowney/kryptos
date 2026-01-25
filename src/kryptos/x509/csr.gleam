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
import kryptos/hash.{type HashAlgorithm}
import kryptos/internal/der
import kryptos/internal/utils
import kryptos/rsa
import kryptos/x509.{
  type Extensions, type Name, type Oid, type SubjectAltName, DnsName, Email,
  Extensions, IpAddress, Oid,
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

/// A signed Certificate Signing Request.
pub opaque type Csr {
  Csr(der: BitArray)
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
/// - `Ok(Csr)` containing the signed CSR
/// - `Error(Nil)` if the hash algorithm is not supported or the public key
///   cannot be encoded
pub fn sign_with_ecdsa(
  builder: Builder,
  key: ec.PrivateKey,
  hash: HashAlgorithm,
) -> Result(Csr, Nil) {
  use sig_alg <- result.try(ecdsa_signature_alg(hash))
  let public_key = ec.public_key_from_private_key(key)
  use spki <- result.try(ec.public_key_to_der(public_key))
  let cert_request_info = encode_certification_request_info(builder, spki)
  let signature = ecdsa.sign(key, cert_request_info, hash)
  let csr_der = encode_csr(cert_request_info, sig_alg, signature)
  Ok(Csr(csr_der))
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
/// - `Ok(Csr)` containing the signed CSR
/// - `Error(Nil)` if the hash algorithm is not supported or the public key
///   cannot be encoded
pub fn sign_with_rsa(
  builder: Builder,
  key: rsa.PrivateKey,
  hash: HashAlgorithm,
) -> Result(Csr, Nil) {
  use sig_alg <- result.try(rsa_signature_alg(hash))
  let public_key = rsa.public_key_from_private_key(key)
  use spki <- result.try(rsa.public_key_to_der(public_key, rsa.Spki))
  let cert_request_info = encode_certification_request_info(builder, spki)
  let signature = rsa.sign(key, cert_request_info, hash, rsa.Pkcs1v15)
  let csr_der = encode_csr(cert_request_info, sig_alg, signature)
  Ok(Csr(csr_der))
}

/// Exports the CSR as DER-encoded bytes.
///
/// DER (Distinguished Encoding Rules) is a binary format commonly used
/// for programmatic certificate handling.
///
/// ## Parameters
/// - `csr`: The signed CSR
///
/// ## Returns
/// The raw DER-encoded CSR bytes.
pub fn to_der(csr: Csr) -> BitArray {
  csr.der
}

/// Exports the CSR as a PEM-encoded string.
///
/// PEM (Privacy-Enhanced Mail) is a Base64-encoded format with header and
/// footer lines. This is the format typically required when submitting
/// a CSR to a Certificate Authority.
///
/// ## Parameters
/// - `csr`: The signed CSR
///
/// ## Returns
/// A PEM-encoded string with `-----BEGIN CERTIFICATE REQUEST-----` headers.
pub fn to_pem(csr: Csr) -> String {
  let encoded = bit_array.base64_encode(csr.der, True)
  let lines =
    utils.chunk_string(encoded, 64)
    |> list.map(fn(line) { line <> "\n" })

  string_tree.new()
  |> string_tree.append("-----BEGIN CERTIFICATE REQUEST-----\n")
  |> string_tree.append_tree(string_tree.from_strings(lines))
  |> string_tree.append("-----END CERTIFICATE REQUEST-----\n\n")
  |> string_tree.to_string
}

fn encode_csr(
  cert_request_info: BitArray,
  sig_alg: SignatureAlgorithm,
  signature: BitArray,
) -> BitArray {
  let SignatureAlgorithm(oid, include_null_params) = sig_alg
  let sig_alg_der = case include_null_params {
    True ->
      der.encode_sequence(
        bit_array.concat([der.encode_oid(oid.components), <<0x05, 0x00>>]),
      )
    False -> der.encode_sequence(der.encode_oid(oid.components))
  }
  let sig_bits = der.encode_bit_string(signature)
  der.encode_sequence(
    bit_array.concat([cert_request_info, sig_alg_der, sig_bits]),
  )
}

fn encode_certification_request_info(
  builder: Builder,
  spki: BitArray,
) -> BitArray {
  let version = der.encode_integer(<<0>>)
  let subject = encode_name(builder.subject)
  let attributes = encode_attributes(builder.extensions)
  der.encode_sequence(bit_array.concat([version, subject, spki, attributes]))
}

fn encode_name(name: Name) -> BitArray {
  let encoded_rdns = list.map(name.rdns, encode_rdn)
  der.encode_sequence(bit_array.concat(encoded_rdns))
}

fn encode_rdn(rdn: x509.Rdn) -> BitArray {
  let encoded_attrs = list.map(rdn.attributes, encode_attribute_type_and_value)
  let sorted_attrs = list.sort(encoded_attrs, bit_array.compare)
  der.encode_set(bit_array.concat(sorted_attrs))
}

fn encode_attribute_type_and_value(
  attr: #(Oid, x509.AttributeValue),
) -> BitArray {
  let #(Oid(oid_components), value) = attr
  let encoded_value = x509.encode_attribute_value(value)
  der.encode_sequence(
    bit_array.concat([
      der.encode_oid(oid_components),
      encoded_value,
    ]),
  )
}

fn encode_attributes(extensions: Extensions) -> BitArray {
  use <- bool.guard(
    when: list.is_empty(extensions.subject_alt_names),
    return: der.encode_context_tag(0, <<>>),
  )

  let ext_request = encode_extension_request(extensions)
  der.encode_context_tag(0, ext_request)
}

fn encode_extension_request(extensions: Extensions) -> BitArray {
  let Oid(ext_req_components) = oid_extension_request
  let exts = encode_extensions(extensions)
  der.encode_sequence(
    bit_array.concat([
      der.encode_oid(ext_req_components),
      der.encode_set(exts),
    ]),
  )
}

fn encode_extensions(extensions: Extensions) -> BitArray {
  let Extensions(sans) = extensions
  let san_ext = encode_san_extension(sans)
  der.encode_sequence(san_ext)
}

fn encode_san_extension(sans: List(SubjectAltName)) -> BitArray {
  let Oid(san_oid_components) = oid_subject_alt_name
  let san_value = encode_general_names(sans)
  der.encode_sequence(
    bit_array.concat([
      der.encode_oid(san_oid_components),
      der.encode_octet_string(san_value),
    ]),
  )
}

fn encode_general_names(sans: List(SubjectAltName)) -> BitArray {
  let encoded = sans |> list.reverse |> list.map(encode_general_name)
  der.encode_sequence(bit_array.concat(encoded))
}

fn encode_general_name(san: SubjectAltName) -> BitArray {
  case san {
    DnsName(name) ->
      der.encode_context_primitive_tag(2, bit_array.from_string(name))
    Email(email) ->
      der.encode_context_primitive_tag(1, bit_array.from_string(email))
    IpAddress(ip) -> der.encode_context_primitive_tag(7, ip)
  }
}

/// Internal type for signature algorithm encoding.
/// ECDSA algorithms must NOT include NULL parameters, while RSA algorithms MUST include them.
type SignatureAlgorithm {
  SignatureAlgorithm(oid: Oid, include_null_params: Bool)
}

fn ecdsa_signature_alg(hash: HashAlgorithm) -> Result(SignatureAlgorithm, Nil) {
  case hash {
    hash.Sha1 -> Ok(SignatureAlgorithm(oid_ecdsa_with_sha1, False))
    hash.Sha256 -> Ok(SignatureAlgorithm(oid_ecdsa_with_sha256, False))
    hash.Sha384 -> Ok(SignatureAlgorithm(oid_ecdsa_with_sha384, False))
    hash.Sha512 -> Ok(SignatureAlgorithm(oid_ecdsa_with_sha512, False))
    _ -> Error(Nil)
  }
}

fn rsa_signature_alg(hash: HashAlgorithm) -> Result(SignatureAlgorithm, Nil) {
  case hash {
    hash.Sha1 -> Ok(SignatureAlgorithm(oid_rsa_with_sha1, True))
    hash.Sha256 -> Ok(SignatureAlgorithm(oid_rsa_with_sha256, True))
    hash.Sha384 -> Ok(SignatureAlgorithm(oid_rsa_with_sha384, True))
    hash.Sha512 -> Ok(SignatureAlgorithm(oid_rsa_with_sha512, True))
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
  case string.split(ip, "::") {
    [left, right] -> {
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
    _ -> Error(Nil)
  }
}

fn parse_ipv6_word(s: String) -> Result(Int, Nil) {
  use n <- result.try(int.base_parse(s, 16))
  use <- bool.guard(when: n < 0 || n > 0xffff, return: Error(Nil))
  Ok(n)
}
