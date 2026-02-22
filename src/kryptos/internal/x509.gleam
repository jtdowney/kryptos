//// Shared X.509 parsing and encoding utilities for CSR and Certificate modules.

import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string
import gleam/string_tree
import kryptos/ec
import kryptos/ecdsa
import kryptos/eddsa
import kryptos/hash
import kryptos/internal/der
import kryptos/internal/utils
import kryptos/rsa
import kryptos/x509
import kryptos/xdh

const oid_rsa_with_sha1 = x509.Oid([1, 2, 840, 113_549, 1, 1, 5])

const oid_rsa_with_sha256 = x509.Oid([1, 2, 840, 113_549, 1, 1, 11])

const oid_rsa_with_sha384 = x509.Oid([1, 2, 840, 113_549, 1, 1, 12])

const oid_rsa_with_sha512 = x509.Oid([1, 2, 840, 113_549, 1, 1, 13])

const oid_ecdsa_with_sha1 = x509.Oid([1, 2, 840, 10_045, 4, 1])

const oid_ecdsa_with_sha256 = x509.Oid([1, 2, 840, 10_045, 4, 3, 2])

const oid_ecdsa_with_sha384 = x509.Oid([1, 2, 840, 10_045, 4, 3, 3])

const oid_ecdsa_with_sha512 = x509.Oid([1, 2, 840, 10_045, 4, 3, 4])

const oid_ed25519 = x509.Oid([1, 3, 101, 112])

const oid_ed448 = x509.Oid([1, 3, 101, 113])

type PemError {
  PemNotFound
  PemMalformed
}

pub type SigAlgInfo {
  SigAlgInfo(oid: x509.Oid, include_null_params: Bool)
}

/// Map a hash algorithm to ECDSA signature algorithm information.
pub fn ecdsa_sig_alg_info(hash: hash.HashAlgorithm) -> Result(SigAlgInfo, Nil) {
  case hash {
    hash.Sha1 -> Ok(SigAlgInfo(oid_ecdsa_with_sha1, False))
    hash.Sha256 -> Ok(SigAlgInfo(oid_ecdsa_with_sha256, False))
    hash.Sha384 -> Ok(SigAlgInfo(oid_ecdsa_with_sha384, False))
    hash.Sha512 -> Ok(SigAlgInfo(oid_ecdsa_with_sha512, False))
    _ -> Error(Nil)
  }
}

/// Map a hash algorithm to RSA signature algorithm information.
pub fn rsa_sig_alg_info(hash: hash.HashAlgorithm) -> Result(SigAlgInfo, Nil) {
  case hash {
    hash.Sha1 -> Ok(SigAlgInfo(oid_rsa_with_sha1, True))
    hash.Sha256 -> Ok(SigAlgInfo(oid_rsa_with_sha256, True))
    hash.Sha384 -> Ok(SigAlgInfo(oid_rsa_with_sha384, True))
    hash.Sha512 -> Ok(SigAlgInfo(oid_rsa_with_sha512, True))
    _ -> Error(Nil)
  }
}

/// Map an EdDSA curve to signature algorithm information.
pub fn eddsa_sig_alg_info(curve: eddsa.Curve) -> SigAlgInfo {
  case curve {
    eddsa.Ed25519 -> SigAlgInfo(oid_ed25519, False)
    eddsa.Ed448 -> SigAlgInfo(oid_ed448, False)
  }
}

/// Verify a signature using the appropriate algorithm based on public key and signature algorithm.
pub fn verify_signature(
  public_key: x509.PublicKey,
  data: BitArray,
  signature: BitArray,
  signature_algorithm: x509.SignatureAlgorithm,
) -> Bool {
  case public_key, signature_algorithm {
    x509.EcPublicKey(key), x509.EcdsaSha1 ->
      ecdsa.verify(key, data, signature, hash.Sha1)
    x509.EcPublicKey(key), x509.EcdsaSha256 ->
      ecdsa.verify(key, data, signature, hash.Sha256)
    x509.EcPublicKey(key), x509.EcdsaSha384 ->
      ecdsa.verify(key, data, signature, hash.Sha384)
    x509.EcPublicKey(key), x509.EcdsaSha512 ->
      ecdsa.verify(key, data, signature, hash.Sha512)
    x509.RsaPublicKey(key), x509.RsaSha1 ->
      rsa.verify(key, data, signature, hash.Sha1, rsa.Pkcs1v15)
    x509.RsaPublicKey(key), x509.RsaSha256 ->
      rsa.verify(key, data, signature, hash.Sha256, rsa.Pkcs1v15)
    x509.RsaPublicKey(key), x509.RsaSha384 ->
      rsa.verify(key, data, signature, hash.Sha384, rsa.Pkcs1v15)
    x509.RsaPublicKey(key), x509.RsaSha512 ->
      rsa.verify(key, data, signature, hash.Sha512, rsa.Pkcs1v15)
    x509.EdPublicKey(key), x509.Ed25519 -> eddsa.verify(key, data, signature)
    x509.EdPublicKey(key), x509.Ed448 -> eddsa.verify(key, data, signature)
    x509.EcPublicKey(_), _ -> False
    x509.RsaPublicKey(_), _ -> False
    x509.EdPublicKey(_), _ -> False
    x509.XdhPublicKey(_), _ -> False
  }
}

/// Parse a DER SEQUENCE including its tag and length header.
///
/// Returns the complete SEQUENCE (tag + length + content) and remaining bytes.
/// Returns Error(Nil) if the input does not start with a SEQUENCE tag.
pub fn parse_sequence_with_header(
  bytes: BitArray,
) -> Result(#(BitArray, BitArray), Nil) {
  case bytes {
    <<0x30, _:bits>> -> {
      use #(inner, remaining) <- result.try(der.parse_sequence(bytes))

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

/// Parse an X.509 signature algorithm from DER-encoded AlgorithmIdentifier.
///
/// Decodes the OID and returns the corresponding SignatureAlgorithm variant.
/// Returns Error with the unknown OID if the algorithm is not recognized.
pub fn parse_signature_algorithm(
  bytes: BitArray,
) -> Result(x509.SignatureAlgorithm, x509.Oid) {
  case der.parse_oid(bytes) {
    Ok(#(oid_components, _params)) ->
      case oid_components {
        [1, 2, 840, 113_549, 1, 1, 5] -> Ok(x509.RsaSha1)
        [1, 2, 840, 113_549, 1, 1, 11] -> Ok(x509.RsaSha256)
        [1, 2, 840, 113_549, 1, 1, 12] -> Ok(x509.RsaSha384)
        [1, 2, 840, 113_549, 1, 1, 13] -> Ok(x509.RsaSha512)
        [1, 2, 840, 10_045, 4, 1] -> Ok(x509.EcdsaSha1)
        [1, 2, 840, 10_045, 4, 3, 2] -> Ok(x509.EcdsaSha256)
        [1, 2, 840, 10_045, 4, 3, 3] -> Ok(x509.EcdsaSha384)
        [1, 2, 840, 10_045, 4, 3, 4] -> Ok(x509.EcdsaSha512)
        [1, 3, 101, 112] -> Ok(x509.Ed25519)
        [1, 3, 101, 113] -> Ok(x509.Ed448)
        _ -> Error(x509.Oid(oid_components))
      }
    Error(_) -> Error(x509.Oid([]))
  }
}

/// Parse an X.509 distinguished name (DN) from DER encoding.
///
/// Decodes a Name structure containing RDNs (relative distinguished names).
/// Returns Error(Nil) if the encoding is invalid.
pub fn parse_name(bytes: BitArray) -> Result(x509.Name, Nil) {
  parse_rdns(bytes, [])
  |> result.map(x509.Name)
}

fn parse_rdns(
  bytes: BitArray,
  acc: List(x509.Rdn),
) -> Result(List(x509.Rdn), Nil) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    _ -> {
      use #(rdn_bytes, rest) <- result.try(der.parse_set(bytes))

      parse_rdn_attributes(rdn_bytes, [])
      |> result.try(fn(attributes) {
        parse_rdns(rest, [x509.Rdn(attributes:), ..acc])
      })
    }
  }
}

fn parse_rdn_attributes(
  bytes: BitArray,
  acc: List(#(x509.Oid, x509.AttributeValue)),
) -> Result(List(#(x509.Oid, x509.AttributeValue)), Nil) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    _ -> {
      use #(attr_bytes, rest) <- result.try(der.parse_sequence(bytes))
      use #(oid_components, after_oid) <- result.try(der.parse_oid(attr_bytes))
      use #(value, _) <- result.try(parse_attribute_value(after_oid))

      parse_rdn_attributes(rest, [#(x509.Oid(oid_components), value), ..acc])
    }
  }
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
    <<0x14, _:bits>> -> {
      // TeletexString - normalize to UTF8String
      use #(s, rest) <- result.try(der.parse_teletex_string(bytes))
      Ok(#(x509.utf8_string(s), rest))
    }
    <<0x16, _:bits>> -> {
      use #(s, rest) <- result.try(der.parse_ia5_string(bytes))
      Ok(#(x509.ia5_string(s), rest))
    }
    <<0x1c, _:bits>> -> {
      // UniversalString - normalize to UTF8String
      use #(s, rest) <- result.try(der.parse_universal_string(bytes))
      Ok(#(x509.utf8_string(s), rest))
    }
    <<0x1e, _:bits>> -> {
      // BMPString - normalize to UTF8String
      use #(s, rest) <- result.try(der.parse_bmp_string(bytes))
      Ok(#(x509.utf8_string(s), rest))
    }
    _ -> Error(Nil)
  }
}

/// Encode an X.509 distinguished name to DER format.
///
/// Produces a DER-encoded Name structure with RDN attributes sorted per RFC 5280.
/// Returns Error(Nil) if encoding fails.
pub fn encode_name(name: x509.Name) -> Result(BitArray, Nil) {
  let x509.Name(rdns) = name

  list.try_map(rdns, encode_rdn)
  |> result.try(fn(encoded_rdns) {
    der.encode_sequence(bit_array.concat(encoded_rdns))
  })
}

fn encode_rdn(rdn: x509.Rdn) -> Result(BitArray, Nil) {
  let x509.Rdn(attributes) = rdn
  use encoded_attrs <- result.try(list.try_map(
    attributes,
    encode_attribute_type_and_value,
  ))
  let sorted_attrs = list.sort(encoded_attrs, bit_array.compare)
  der.encode_set(bit_array.concat(sorted_attrs))
}

fn encode_attribute_type_and_value(
  attr: #(x509.Oid, x509.AttributeValue),
) -> Result(BitArray, Nil) {
  let #(x509.Oid(oid_components), value) = attr
  use encoded_value <- result.try(x509.encode_attribute_value(value))
  use oid_encoded <- result.try(der.encode_oid(oid_components))
  der.encode_sequence(bit_array.concat([oid_encoded, encoded_value]))
}

/// Parse a public key from DER-encoded SubjectPublicKeyInfo.
///
/// Decodes the algorithm identifier and dispatches to the appropriate key parser (RSA, EC, Ed25519, etc.).
/// Returns Error with the unknown OID if the algorithm is not supported.
pub fn parse_public_key(
  spki_bytes: BitArray,
) -> Result(x509.PublicKey, x509.Oid) {
  let result =
    {
      use #(spki_content, _) <- result.try(der.parse_sequence(spki_bytes))
      use #(alg_id_bytes, after_alg) <- result.try(der.parse_sequence(
        spki_content,
      ))
      use #(alg_oid, _alg_params) <- result.try(der.parse_oid(alg_id_bytes))
      use _ <- result.try(der.parse_bit_string(after_alg))

      Ok(alg_oid)
    }
    |> result.replace_error(x509.Oid([]))

  result
  |> result.try(dispatch_public_key_parse(_, spki_bytes))
}

fn dispatch_public_key_parse(
  alg_oid: List(Int),
  spki_bytes: BitArray,
) -> Result(x509.PublicKey, x509.Oid) {
  case alg_oid {
    // id-ecPublicKey
    [1, 2, 840, 10_045, 2, 1] ->
      ec.public_key_from_der(spki_bytes)
      |> result.map(x509.EcPublicKey)
      |> result.replace_error(x509.Oid(alg_oid))
    // rsaEncryption
    [1, 2, 840, 113_549, 1, 1, 1] ->
      rsa.public_key_from_der(spki_bytes, rsa.Spki)
      |> result.map(x509.RsaPublicKey)
      |> result.replace_error(x509.Oid(alg_oid))
    // id-X25519 (RFC 8410)
    [1, 3, 101, 110] ->
      xdh.public_key_from_der(spki_bytes)
      |> result.map(x509.XdhPublicKey)
      |> result.replace_error(x509.Oid(alg_oid))
    // id-X448 (RFC 8410)
    [1, 3, 101, 111] ->
      xdh.public_key_from_der(spki_bytes)
      |> result.map(x509.XdhPublicKey)
      |> result.replace_error(x509.Oid(alg_oid))
    // id-Ed25519 (RFC 8410)
    [1, 3, 101, 112] ->
      eddsa.public_key_from_der(spki_bytes)
      |> result.map(x509.EdPublicKey)
      |> result.replace_error(x509.Oid(alg_oid))
    // id-Ed448 (RFC 8410)
    [1, 3, 101, 113] ->
      eddsa.public_key_from_der(spki_bytes)
      |> result.map(x509.EdPublicKey)
      |> result.replace_error(x509.Oid(alg_oid))
    _ -> Error(x509.Oid(alg_oid))
  }
}

/// Recursively parse a sequence of Subject Alternative Name entries.
///
/// Accumulates SAN entries from DER-encoded GeneralNames structure.
/// Returns Error(Nil) if parsing fails for any entry.
/// When is_critical is True, unknown GeneralName types cause an error.
pub fn parse_general_names(
  bytes: BitArray,
  acc: List(x509.SubjectAltName),
  is_critical: Bool,
) -> Result(List(x509.SubjectAltName), Nil) {
  case bytes {
    <<>> -> Ok(list.reverse(acc))
    _ -> {
      use #(san, rest) <- result.try(parse_general_name(bytes, is_critical))
      parse_general_names(rest, [san, ..acc], is_critical)
    }
  }
}

/// Parse a single Subject Alternative Name entry.
///
/// Decodes one GeneralName from DER encoding (DNS name, email, IP address, etc.).
/// Returns Error(Nil) if the entry is malformed.
/// When is_critical is True, unknown GeneralName types return Error.
pub fn parse_general_name(
  bytes: BitArray,
  is_critical: Bool,
) -> Result(#(x509.SubjectAltName, BitArray), Nil) {
  use #(tag, value, rest) <- result.try(der.parse_tlv(bytes))

  case tag {
    // [0] otherName - SEQUENCE { type-id OID, [0] value ANY }
    0xa0 -> {
      use #(oid_components, after_oid) <- result.try(der.parse_oid(value))
      use #(other_value, _) <- result.try(der.parse_context_tag(after_oid, 0))
      Ok(#(x509.OtherName(x509.Oid(oid_components), other_value), rest))
    }
    // [1] rfc822Name (email)
    0x81 -> {
      bit_array.to_string(value)
      |> result.map(fn(s) { #(x509.Email(s), rest) })
    }
    // [2] dNSName
    0x82 -> {
      bit_array.to_string(value)
      |> result.map(fn(s) { #(x509.DnsName(s), rest) })
    }
    // [4] directoryName - explicit Name (SEQUENCE of RDNs)
    0xa4 -> {
      use #(name_content, _) <- result.try(der.parse_sequence(value))
      use name <- result.try(parse_name(name_content))
      Ok(#(x509.DirectoryName(name), rest))
    }
    // [6] uniformResourceIdentifier (URI)
    0x86 -> {
      bit_array.to_string(value)
      |> result.map(fn(s) { #(x509.Uri(s), rest) })
    }
    // [7] iPAddress
    0x87 -> Ok(#(x509.IpAddress(value), rest))
    // [8] registeredID - implicit OID
    0x88 -> {
      // The value contains raw OID content bytes (without tag/length)
      use oid_components <- result.try(der.decode_oid_components(value))
      Ok(#(x509.RegisteredId(x509.Oid(oid_components)), rest))
    }
    _ ->
      case is_critical {
        True -> Error(Nil)
        False -> Ok(#(x509.Unknown(tag, value), rest))
      }
  }
}

/// Encode a single Subject Alternative Name entry to DER format.
///
/// Produces a context-specific tagged value for supported GeneralName types:
/// DNS names, email addresses, IP addresses, URIs, directory names,
/// registered IDs, and otherName entries.
/// Returns Error(Nil) for Unknown SAN types.
pub fn encode_general_name(san: x509.SubjectAltName) -> Result(BitArray, Nil) {
  case san {
    x509.DnsName(name) ->
      der.encode_context_primitive_tag(2, bit_array.from_string(name))
    x509.Email(email) ->
      der.encode_context_primitive_tag(1, bit_array.from_string(email))
    x509.IpAddress(ip) -> der.encode_context_primitive_tag(7, ip)
    x509.Uri(uri) ->
      der.encode_context_primitive_tag(6, bit_array.from_string(uri))
    x509.DirectoryName(name) -> {
      use encoded_name <- result.try(encode_name(name))
      der.encode_context_tag(4, encoded_name)
    }
    x509.RegisteredId(x509.Oid(components)) -> {
      use oid_encoded <- result.try(der.encode_oid(components))
      // Extract just the OID content (skip tag and length) for implicit tagging
      use #(_, oid_content, _) <- result.try(der.parse_tlv(oid_encoded))
      der.encode_context_primitive_tag(8, oid_content)
    }
    x509.OtherName(x509.Oid(oid_components), value) -> {
      use oid_encoded <- result.try(der.encode_oid(oid_components))
      use value_tagged <- result.try(der.encode_context_tag(0, value))
      let content = bit_array.concat([oid_encoded, value_tagged])
      der.encode_context_tag(0, content)
    }
    x509.Unknown(_, _) -> Error(Nil)
  }
}

/// Parse a single X.509 extension from DER encoding.
///
/// Extracts the extension OID, critical flag, and DER-encoded value bytes.
/// Returns Error(Nil) if the extension structure is invalid.
pub fn parse_single_extension(
  bytes: BitArray,
) -> Result(#(x509.Oid, Bool, BitArray), Nil) {
  use #(oid_components, after_oid) <- result.try(der.parse_oid(bytes))
  let #(is_critical, after_critical) = case after_oid {
    <<0x01, 0x01, critical_byte, rest:bits>> -> #(critical_byte != 0, rest)
    other -> #(False, other)
  }
  use #(value, _) <- result.try(der.parse_octet_string(after_critical))
  Ok(#(x509.Oid(oid_components), is_critical, value))
}

/// Parse a Subject Alternative Name extension from DER-encoded bytes.
///
/// Decodes the extension value containing a GeneralNames sequence.
/// Returns Error(Nil) if the extension format is invalid.
/// When is_critical is True, unknown GeneralName types return Error.
pub fn parse_san_extension(
  bytes: BitArray,
  is_critical: Bool,
) -> Result(List(x509.SubjectAltName), Nil) {
  use #(san_content, _) <- result.try(der.parse_sequence(bytes))
  parse_general_names(san_content, [], is_critical)
}

/// Encode an X.509 AlgorithmIdentifier to DER format.
///
/// Produces a DER SEQUENCE with OID and optional NULL parameters (for RSA signatures).
/// Returns Error(Nil) if OID encoding fails.
pub fn encode_algorithm_identifier(sig_alg: SigAlgInfo) -> Result(BitArray, Nil) {
  let SigAlgInfo(oid, include_null_params) = sig_alg
  let x509.Oid(components) = oid
  use oid_encoded <- result.try(der.encode_oid(components))
  case include_null_params {
    True -> der.encode_sequence(bit_array.concat([oid_encoded, <<0x05, 0x00>>]))
    False -> der.encode_sequence(oid_encoded)
  }
}

/// Extract raw public key bytes from a SubjectPublicKeyInfo structure.
///
/// Skips the algorithm identifier and returns only the BIT STRING key data.
/// Returns Error(Nil) if the SPKI structure is invalid.
pub fn extract_spki_public_key_bytes(spki: BitArray) -> Result(BitArray, Nil) {
  use #(spki_content, _) <- result.try(der.parse_sequence(spki))
  use #(_, after_alg) <- result.try(der.parse_sequence(spki_content))
  use #(pub_key_bytes, _) <- result.try(der.parse_bit_string(after_alg))
  Ok(pub_key_bytes)
}

/// Decode PEM-encoded data to DER bytes.
///
/// Extracts base64 data between begin and end markers and decodes to binary.
/// Returns Error(Nil) if markers are not found or base64 decoding fails.
pub fn decode_pem(
  pem: String,
  begin_marker: String,
  end_marker: String,
) -> Result(BitArray, Nil) {
  decode_pem_all(pem, begin_marker, end_marker)
  |> result.try(list.first)
}

/// Decode all PEM blocks matching the given markers to DER bytes.
///
/// Returns all matching blocks in order. Returns Ok([]) if no blocks found.
/// Returns Error(Nil) if any block has invalid base64.
pub fn decode_pem_all(
  pem: String,
  begin_marker: String,
  end_marker: String,
) -> Result(List(BitArray), Nil) {
  let lines = string.split(pem, "\n")
  let lines = list.map(lines, string.trim)
  use blocks <- result.try(
    extract_all_pem_bodies(lines, begin_marker, end_marker, []),
  )
  list.try_map(blocks, fn(body_lines) {
    let body = string.join(body_lines, "")
    bit_array.base64_decode(body)
  })
}

fn extract_all_pem_bodies(
  lines: List(String),
  begin_marker: String,
  end_marker: String,
  acc: List(List(String)),
) -> Result(List(List(String)), Nil) {
  case extract_pem_body(lines, False, [], begin_marker, end_marker) {
    Error(PemNotFound) -> Ok(list.reverse(acc))
    Error(PemMalformed) -> Error(Nil)
    Ok(#(body, remaining)) ->
      extract_all_pem_bodies(remaining, begin_marker, end_marker, [body, ..acc])
  }
}

fn extract_pem_body(
  lines: List(String),
  in_body: Bool,
  acc: List(String),
  begin_marker: String,
  end_marker: String,
) -> Result(#(List(String), List(String)), PemError) {
  case lines, in_body {
    [], False -> Error(PemNotFound)
    [], True -> Error(PemMalformed)
    [line, ..rest], False -> {
      case string.starts_with(line, begin_marker) {
        True -> extract_pem_body(rest, True, acc, begin_marker, end_marker)
        False -> extract_pem_body(rest, False, acc, begin_marker, end_marker)
      }
    }
    [line, ..rest], True -> {
      case string.starts_with(line, end_marker) {
        True -> Ok(#(list.reverse(acc), rest))
        False ->
          extract_pem_body(rest, True, [line, ..acc], begin_marker, end_marker)
      }
    }
  }
}

/// Encode DER bytes to PEM format with the specified markers.
///
/// Produces a base64-encoded string wrapped in the given begin and end markers,
/// with lines wrapped at 64 characters per RFC 7468.
pub fn encode_pem(
  der: BitArray,
  begin_marker: String,
  end_marker: String,
) -> String {
  let encoded = bit_array.base64_encode(der, True)
  let lines =
    utils.chunk_string(encoded, 64)
    |> list.map(fn(line) { line <> "\n" })

  string_tree.new()
  |> string_tree.append(begin_marker <> "\n")
  |> string_tree.append_tree(string_tree.from_strings(lines))
  |> string_tree.append(end_marker <> "\n\n")
  |> string_tree.to_string
}

/// Encode a Subject Alternative Name extension to DER format.
///
/// Produces a DER-encoded extension structure with OID, optional critical flag,
/// and the encoded GeneralNames sequence.
/// Returns Error(Nil) if encoding fails (e.g., Unknown SAN types).
pub fn encode_san_extension(
  sans: List(x509.SubjectAltName),
  critical: Bool,
) -> Result(BitArray, Nil) {
  let oid_components = [2, 5, 29, 17]
  use oid_encoded <- result.try(der.encode_oid(oid_components))

  sans
  |> list.reverse
  |> list.try_map(encode_general_name)
  |> result.map(bit_array.concat)
  |> result.try(der.encode_sequence)
  |> result.try(der.encode_octet_string)
  |> result.map(fn(value_octet) {
    case critical {
      True ->
        bit_array.concat([oid_encoded, der.encode_bool(True), value_octet])
      False -> bit_array.concat([oid_encoded, value_octet])
    }
  })
  |> result.try(der.encode_sequence)
}
