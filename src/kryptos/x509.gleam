//// X.509 certificate types and utilities.
////
//// This module provides types for building X.509 distinguished names and
//// extensions. Use these with the `x509/csr` module to generate Certificate
//// Signing Requests.
////
//// Distinguished names identify subjects in X.509 certificates. They consist
//// of attribute-value pairs like Common Name (CN), Organization (O), and
//// Country (C). This module provides helper functions to construct these
//// attributes in a type-safe way.
////
//// ## Example
////
//// ```gleam
//// import kryptos/x509
////
//// let subject = x509.name([
////   x509.cn("example.com"),
////   x509.organization("Acme Inc"),
////   x509.country("US"),
//// ])
//// ```

import gleam/int
import gleam/list
import gleam/string
import kryptos/ec
import kryptos/eddsa
import kryptos/internal/der
import kryptos/rsa

const oid_common_name = Oid([2, 5, 4, 3])

const oid_organization = Oid([2, 5, 4, 10])

const oid_organizational_unit = Oid([2, 5, 4, 11])

const oid_country = Oid([2, 5, 4, 6])

const oid_state = Oid([2, 5, 4, 8])

const oid_locality = Oid([2, 5, 4, 7])

const oid_email_address = Oid([1, 2, 840, 113_549, 1, 9, 1])

/// An ASN.1 Object Identifier represented as a list of integer components.
pub type Oid {
  Oid(components: List(Int))
}

/// An X.509 distinguished name, consisting of a sequence of RDNs.
pub type Name {
  Name(rdns: List(Rdn))
}

/// A Relative Distinguished Name, containing one or more attribute-value pairs.
pub type Rdn {
  Rdn(attributes: List(#(Oid, AttributeValue)))
}

/// An attribute value in a distinguished name.
///
/// This type is opaque to ensure values are properly validated for their
/// encoding requirements (e.g., PrintableString for country codes,
/// IA5String for email addresses).
pub opaque type AttributeValue {
  /// UTF-8 encoded string (most common for CN, O, OU, L, ST).
  Utf8String(String)
  /// ASCII subset string (required for country codes per X.520).
  PrintableString(String)
  /// ASCII string (required for emailAddress per PKCS#9/RFC 2985).
  Ia5String(String)
}

/// A Subject Alternative Name entry for X.509 extensions.
pub type SubjectAltName {
  /// A DNS hostname (e.g., "example.com").
  DnsName(String)
  /// An IP address (4 bytes for IPv4, 16 bytes for IPv6).
  IpAddress(BitArray)
  /// An email address (e.g., "user@example.com").
  Email(String)
  /// An unknown GeneralName type with its raw tag byte and value.
  /// Returned when parsing encounters an unrecognized SAN type.
  Unknown(tag: Int, value: BitArray)
}

/// X.509 certificate extensions.
pub type Extensions {
  Extensions(subject_alt_names: List(SubjectAltName))
}

/// A public key extracted from an X.509 structure (CSR or certificate).
pub type PublicKey {
  EcPublicKey(ec.PublicKey)
  RsaPublicKey(rsa.PublicKey)
  EdPublicKey(eddsa.PublicKey)
}

/// Signature algorithm used in X.509 structures.
pub type SignatureAlgorithm {
  RsaSha1
  RsaSha256
  RsaSha384
  RsaSha512
  EcdsaSha1
  EcdsaSha256
  EcdsaSha384
  EcdsaSha512
  Ed25519
  Ed448
}

/// Builds a distinguished name from a list of attribute-value pairs.
///
/// Creates a Name with each attribute in its own Relative Distinguished Name
/// (RDN). This produces the standard X.509 format where attributes are
/// displayed as "CN = x, O = y" rather than multi-valued RDNs.
///
/// ## Parameters
/// - `attributes`: A list of OID and value tuples (use helper functions like
///   `cn`, `organization`, `country`, etc.)
///
/// ## Returns
/// A Name suitable for use as a CSR subject.
pub fn name(attributes: List(#(Oid, AttributeValue))) -> Name {
  Name(list.map(attributes, fn(attr) { Rdn([attr]) }))
}

/// Creates a Common Name (CN) attribute.
///
/// The Common Name typically contains the primary identifier for the subject,
/// such as a domain name for server certificates or a person's name for
/// client certificates.
///
/// ## Parameters
/// - `value`: The common name value (e.g., "example.com")
///
/// ## Returns
/// A Common Name attribute tuple.
pub fn cn(value: String) -> #(Oid, AttributeValue) {
  #(oid_common_name, Utf8String(value))
}

/// Creates an Organization (O) attribute.
///
/// Identifies the organization or company name associated with the certificate.
///
/// ## Parameters
/// - `value`: The organization name (e.g., "Acme Inc")
///
/// ## Returns
/// An Organization attribute tuple.
pub fn organization(value: String) -> #(Oid, AttributeValue) {
  #(oid_organization, Utf8String(value))
}

/// Creates an Organizational Unit (OU) attribute.
///
/// Identifies a subdivision within an organization, such as a department
/// or team name.
///
/// ## Parameters
/// - `value`: The organizational unit name (e.g., "Engineering")
///
/// ## Returns
/// An Organizational Unit attribute tuple.
pub fn organizational_unit(value: String) -> #(Oid, AttributeValue) {
  #(oid_organizational_unit, Utf8String(value))
}

/// Creates a Country (C) attribute.
///
/// Uses PrintableString encoding as required by X.520.
///
/// **Important:** The value must be a two-letter uppercase ISO 3166-1 alpha-2
/// country code (e.g., "US", "GB", "DE"). Non-ASCII or incorrectly formatted
/// values will produce non-compliant DER that may be rejected by CAs and clients.
///
/// ## Parameters
/// - `value`: The two-letter country code (e.g., "US", "GB", "DE")
///
/// ## Returns
/// A Country attribute tuple.
pub fn country(value: String) -> #(Oid, AttributeValue) {
  #(oid_country, PrintableString(value))
}

/// Creates a State or Province (ST) attribute.
///
/// ## Parameters
/// - `value`: The state or province name (e.g., "California")
///
/// ## Returns
/// A State/Province attribute tuple.
pub fn state(value: String) -> #(Oid, AttributeValue) {
  #(oid_state, Utf8String(value))
}

/// Creates a Locality (L) attribute.
///
/// ## Parameters
/// - `value`: The city or locality name (e.g., "San Francisco")
///
/// ## Returns
/// A Locality attribute tuple.
pub fn locality(value: String) -> #(Oid, AttributeValue) {
  #(oid_locality, Utf8String(value))
}

/// Creates an Email Address attribute.
///
/// Uses IA5String encoding as required by PKCS#9 (RFC 2985).
/// Note: emailAddress in the DN is deprecated; prefer using
/// Subject Alternative Names via `csr.with_email` instead.
///
/// **Important:** The value must contain only ASCII characters.
/// Non-ASCII values will produce non-compliant DER that may be rejected
/// by CAs and clients.
///
/// ## Parameters
/// - `value`: The email address (e.g., "admin@example.com")
///
/// ## Returns
/// An Email Address attribute tuple.
pub fn email_address(value: String) -> #(Oid, AttributeValue) {
  #(oid_email_address, Ia5String(value))
}

/// Encodes an AttributeValue to its DER representation.
///
/// This is an internal function for use by the csr module.
@internal
pub fn encode_attribute_value(value: AttributeValue) -> Result(BitArray, Nil) {
  case value {
    Utf8String(s) -> der.encode_utf8_string(s)
    PrintableString(s) -> der.encode_printable_string(s)
    Ia5String(s) -> der.encode_ia5_string(s)
  }
}

/// Creates a UTF-8 string attribute value.
///
/// This is an internal function for use by the csr module when parsing.
@internal
pub fn utf8_string(value: String) -> AttributeValue {
  Utf8String(value)
}

/// Creates a printable string attribute value.
///
/// This is an internal function for use by the csr module when parsing.
@internal
pub fn printable_string(value: String) -> AttributeValue {
  PrintableString(value)
}

/// Creates an IA5 string attribute value.
///
/// This is an internal function for use by the csr module when parsing.
@internal
pub fn ia5_string(value: String) -> AttributeValue {
  Ia5String(value)
}

/// Extracts the string value from an AttributeValue.
///
/// Returns the underlying string regardless of encoding type
/// (UTF8String, PrintableString, or IA5String).
pub fn attribute_value_to_string(value: AttributeValue) -> String {
  case value {
    Utf8String(s) -> s
    PrintableString(s) -> s
    Ia5String(s) -> s
  }
}

/// Converts a distinguished name to a human-readable string.
///
/// Formats the name in OpenSSL style: "CN=example.com, O=Acme Inc, C=US"
///
/// Known OIDs are displayed with their standard abbreviations (CN, O, OU, C, ST, L).
/// Unknown OIDs are displayed in dotted-decimal notation (e.g., "1.2.3.4=value").
pub fn name_to_string(name: Name) -> String {
  let Name(rdns) = name
  rdns
  |> list.flat_map(fn(rdn) {
    let Rdn(attributes) = rdn
    list.map(attributes, fn(attr) {
      let #(oid, value) = attr
      oid_to_abbrev(oid) <> "=" <> attribute_value_to_string(value)
    })
  })
  |> string.join(", ")
}

fn oid_to_abbrev(oid: Oid) -> String {
  case oid {
    Oid([2, 5, 4, 3]) -> "CN"
    Oid([2, 5, 4, 6]) -> "C"
    Oid([2, 5, 4, 7]) -> "L"
    Oid([2, 5, 4, 8]) -> "ST"
    Oid([2, 5, 4, 10]) -> "O"
    Oid([2, 5, 4, 11]) -> "OU"
    Oid([1, 2, 840, 113_549, 1, 9, 1]) -> "emailAddress"
    Oid(components) -> string.join(list.map(components, int.to_string), ".")
  }
}
