//// Shared X.509 parsing and encoding utilities for CSR and Certificate modules.

import bitty as p
import bitty/bytes as b
import gleam/bit_array
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/string_tree
import gleam/time/timestamp.{type Timestamp}
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
    _, _ -> False
  }
}

/// Encode an X.509 distinguished name to DER format.
///
/// Produces a DER-encoded Name structure with RDN attributes sorted per RFC 5280.
/// Returns Error(Nil) if encoding fails.
pub fn encode_name(name: x509.Name) -> Result(BitArray, Nil) {
  let x509.Name(rdns) = name

  use encoded_rdns <- result.try(list.try_map(rdns, encode_rdn))
  der.encode_sequence(bit_array.concat(encoded_rdns))
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

pub fn dispatch_public_key_parse(
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
      use #(_, oid_content) <- result.try(
        p.run(der.tlv(), on: oid_encoded)
        |> result.replace_error(Nil),
      )
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

pub fn attribute_value() -> p.Parser(x509.AttributeValue) {
  p.one_of([
    der.utf8_string() |> p.map(x509.utf8_string),
    der.numeric_string() |> p.map(x509.utf8_string),
    der.printable_string() |> p.map(x509.printable_string),
    der.teletex_string() |> p.map(x509.utf8_string),
    der.ia5_string() |> p.map(x509.ia5_string),
    der.universal_string() |> p.map(x509.utf8_string),
    der.bmp_string() |> p.map(x509.utf8_string),
  ])
}

fn rdn_attribute() -> p.Parser(#(x509.Oid, x509.AttributeValue)) {
  der.sequence(p.pair(der.oid() |> p.map(x509.Oid), attribute_value()))
}

fn rdn() -> p.Parser(x509.Rdn) {
  der.set(p.many(rdn_attribute())) |> p.map(x509.Rdn)
}

pub fn name() -> p.Parser(x509.Name) {
  p.many(rdn()) |> p.map(x509.Name)
}

pub fn signature_algorithm_oid() -> p.Parser(List(Int)) {
  p.terminated(der.oid(), b.rest())
}

pub fn lookup_signature_algorithm(
  oid: List(Int),
) -> Result(x509.SignatureAlgorithm, x509.Oid) {
  case oid {
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
    _ -> Error(x509.Oid(oid))
  }
}

pub fn general_name(is_critical: Bool) -> p.Parser(x509.SubjectAltName) {
  use #(tag, value) <- p.then(der.tlv())
  case tag {
    0xa0 -> {
      let parser = {
        use oid_components <- p.then(der.oid())
        use other_value <- p.then(der.context_tag(0, b.rest()))
        p.success(x509.OtherName(x509.Oid(oid_components), other_value))
      }
      p.from_result(p.run(parser, on: value) |> result.replace_error(Nil))
    }
    0x81 -> p.from_result(bit_array.to_string(value) |> result.map(x509.Email))
    0x82 ->
      p.from_result(bit_array.to_string(value) |> result.map(x509.DnsName))
    0xa4 -> {
      p.from_result(
        p.run(der.sequence(name()), on: value)
        |> result.replace_error(Nil)
        |> result.map(x509.DirectoryName),
      )
    }
    0x86 -> p.from_result(bit_array.to_string(value) |> result.map(x509.Uri))
    0x87 -> p.success(x509.IpAddress(value))
    0x88 ->
      p.from_result(
        der.decode_oid_components(value)
        |> result.map(fn(c) { x509.RegisteredId(x509.Oid(c)) }),
      )
    _ ->
      case is_critical {
        True -> p.fail("unknown critical general name tag")
        False -> p.success(x509.Unknown(tag, value))
      }
  }
}

pub fn general_names(is_critical: Bool) -> p.Parser(List(x509.SubjectAltName)) {
  p.many(general_name(is_critical))
}

pub fn single_extension() -> p.Parser(#(x509.Oid, Bool, BitArray)) {
  use oid_components <- p.then(der.oid())
  use is_critical <- p.then(
    p.optional(der.boolean())
    |> p.map(option.unwrap(_, False)),
  )
  use value <- p.then(der.octet_string())
  p.success(#(x509.Oid(oid_components), is_critical, value))
}

pub fn san_extension(is_critical: Bool) -> p.Parser(List(x509.SubjectAltName)) {
  der.sequence(general_names(is_critical))
}

pub fn time() -> p.Parser(Timestamp) {
  p.one_of([der.utc_time(), der.generalized_time()])
}

pub fn public_key_info() -> p.Parser(#(List(Int), BitArray)) {
  der.sequence_with_raw(p.terminated(
    der.sequence(signature_algorithm_oid()),
    der.bit_string(),
  ))
  |> p.map(fn(pair) {
    let #(raw, alg_oid) = pair
    #(alg_oid, raw)
  })
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
  let parser =
    der.sequence(p.preceded(der.sequence(b.rest()), der.bit_string()))
  p.run(parser, on: spki) |> result.replace_error(Nil)
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
