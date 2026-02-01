import birdie
import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/regexp
import gleam/result
import gleam/time/timestamp
import kryptos/crypto
import kryptos/ec
import kryptos/eddsa
import kryptos/hash
import kryptos/rsa
import kryptos/x509.{DigitalSignature, KeyCertSign, ServerAuth, Validity}
import kryptos/x509/certificate
import kryptos/x509/test_helpers.{
  mask_dynamic_values, mask_serial, mask_signature, normalize_subject,
}
import kryptos/xdh
import qcheck
import shellout
import simplifile

fn mask_dynamic_values_with_serial(output: String) -> String {
  let output = mask_dynamic_values(output)
  let assert Ok(serial_re) =
    regexp.from_string("(INTEGER\\s+:)[0-9A-Fa-f]{20,}")
  regexp.replace(serial_re, output, "INTEGER           :[MASKED]")
}

pub fn builder_with_dns_name_rejects_non_ascii_test() {
  assert certificate.new() |> certificate.with_dns_name("exämple.com")
    == Error(Nil)
}

pub fn generated_serial_is_positive_property_test() {
  qcheck.run(qcheck.default_config(), qcheck.return(Nil), fn(_) {
    let serial = certificate.generate_serial_number()

    let assert <<first_byte:8, _:bits>> = serial
    assert first_byte <= 0x7f
    assert bit_array.byte_size(serial) == 20
  })
}

pub fn from_pem_no_certificates_test() {
  assert certificate.from_pem("not a pem") == Ok([])
}

pub fn from_der_truncated_test() {
  assert certificate.from_der(<<0x30, 0x82, 0x01, 0x00>>)
    == Error(certificate.ParseError)
}

pub fn from_der_trailing_bytes_rejected_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("trailing.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_dns_name("trailing.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let valid_der = certificate.to_der(cert)
  let der_with_trailing = bit_array.concat([valid_der, <<0xaa, 0xbb, 0xcc>>])

  assert certificate.from_der(der_with_trailing)
    == Error(certificate.ParseError)
}

pub fn verify_with_issuer_key_test() {
  let #(private_key, public_key) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("verify.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_dns_name("verify.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))
  let assert Ok(_) = certificate.verify(parsed, x509.EcPublicKey(public_key))
}

pub fn verify_fails_with_wrong_key_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let #(_, wrong_public_key) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("verify.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_dns_name("verify.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))
  assert certificate.verify(parsed, x509.EcPublicKey(wrong_public_key))
    == Error(certificate.SignatureVerificationFailed)
}

pub fn verify_fails_with_xdh_key_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let #(_, xdh_public_key) = xdh.generate_key_pair(xdh.X25519)
  let subject = x509.name([x509.cn("verify.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_dns_name("verify.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))

  assert certificate.verify(parsed, x509.XdhPublicKey(xdh_public_key))
    == Error(certificate.UnsupportedAlgorithm(x509.Oid([1, 3, 101, 110])))
}

pub fn self_signed_rsa_roundtrip_test() {
  let assert Ok(#(private_key, _)) = rsa.generate_key_pair(2048)
  let subject = x509.name([x509.cn("rsa.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_dns_name("rsa.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_rsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))
  assert certificate.version(parsed) == 2
  let assert x509.RsaPublicKey(_) = certificate.public_key(parsed)
  assert certificate.signature_algorithm(parsed) == x509.RsaSha256
  let assert Ok(_) = certificate.verify_self_signed(parsed)
}

pub fn self_signed_eddsa_roundtrip_test() {
  let #(ed25519_key, _) = eddsa.generate_key_pair(eddsa.Ed25519)
  let subject = x509.name([x509.cn("ed25519.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_dns_name("ed25519.example.com")

  let assert Ok(cert) = certificate.self_signed_with_eddsa(builder, ed25519_key)
  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))

  assert certificate.version(parsed) == 2
  assert certificate.signature_algorithm(parsed) == x509.Ed25519
  let assert Ok(_) = certificate.verify_self_signed(parsed)

  let #(ed448_key, _) = eddsa.generate_key_pair(eddsa.Ed448)
  let subject448 = x509.name([x509.cn("ed448.example.com")])

  let assert Ok(builder448) =
    certificate.new()
    |> certificate.with_subject(subject448)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_dns_name("ed448.example.com")

  let assert Ok(cert448) =
    certificate.self_signed_with_eddsa(builder448, ed448_key)
  let assert Ok(parsed448) = certificate.from_der(certificate.to_der(cert448))
  assert certificate.version(parsed448) == 2
  assert certificate.signature_algorithm(parsed448) == x509.Ed448
  let assert Ok(_) = certificate.verify_self_signed(parsed448)
}

// TODO: enable on javascript when shellout is fixed
// https://github.com/tynanbe/shellout/pull/14
@target(erlang)
pub fn cert_ecdsa_verified_by_openssl_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p256_pkcs8.pem")
  let assert Ok(#(private_key, _)) = ec.from_pem(pem)

  let subject =
    x509.name([
      x509.cn("example.com"),
      x509.organization("Acme Inc"),
      x509.country("US"),
    ])

  let not_before = timestamp.from_unix_seconds_and_nanoseconds(0, 0)
  let not_after = timestamp.from_unix_seconds_and_nanoseconds(31_536_000, 0)

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(
      not_before: not_before,
      not_after: not_after,
    ))
    |> certificate.with_basic_constraints(ca: False, path_len_constraint: None)
    |> certificate.with_key_usage(DigitalSignature)
    |> certificate.with_extended_key_usage(ServerAuth)
    |> certificate.with_subject_key_identifier(certificate.SkiAuto)
    |> certificate.with_dns_name("example.com")
    |> result.try(certificate.with_dns_name(_, "www.example.com"))

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let cert_pem = certificate.to_pem(cert)

  let cmd = "echo '" <> cert_pem <> "' | openssl asn1parse -i"
  let assert Ok(output) =
    shellout.command(run: "sh", with: ["-c", cmd], in: ".", opt: [])

  birdie.snap(
    mask_dynamic_values_with_serial(output),
    title: "cert ecdsa openssl asn1parse",
  )

  let text_cmd = "echo '" <> cert_pem <> "' | openssl x509 -text -noout"
  let assert Ok(text_output) =
    shellout.command(run: "sh", with: ["-c", text_cmd], in: ".", opt: [])

  text_output
  |> mask_signature
  |> mask_serial
  |> normalize_subject
  |> birdie.snap(title: "cert ecdsa openssl text")
}

// TODO: enable on javascript when shellout is fixed
// https://github.com/tynanbe/shellout/pull/14
@target(erlang)
pub fn cert_rsa_verified_by_openssl_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa2048_pkcs8.pem")
  let assert Ok(#(private_key, _)) = rsa.from_pem(pem, rsa.Pkcs8)

  let subject =
    x509.name([
      x509.cn("rsa.example.com"),
      x509.organization("RSA Corp"),
      x509.country("US"),
    ])

  let not_before = timestamp.from_unix_seconds_and_nanoseconds(0, 0)
  let not_after = timestamp.from_unix_seconds_and_nanoseconds(31_536_000, 0)

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(
      not_before: not_before,
      not_after: not_after,
    ))
    |> certificate.with_basic_constraints(
      ca: True,
      path_len_constraint: Some(0),
    )
    |> certificate.with_key_usage(DigitalSignature)
    |> certificate.with_key_usage(KeyCertSign)
    |> certificate.with_subject_key_identifier(certificate.SkiAuto)
    |> certificate.with_dns_name("rsa.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_rsa(builder, private_key, hash.Sha256)

  let cert_pem = certificate.to_pem(cert)

  let cmd = "echo '" <> cert_pem <> "' | openssl asn1parse -i"
  let assert Ok(output) =
    shellout.command(run: "sh", with: ["-c", cmd], in: ".", opt: [])

  birdie.snap(
    mask_dynamic_values_with_serial(output),
    title: "cert rsa openssl asn1parse",
  )

  let text_cmd = "echo '" <> cert_pem <> "' | openssl x509 -text -noout"
  let assert Ok(text_output) =
    shellout.command(run: "sh", with: ["-c", text_cmd], in: ".", opt: [])

  text_output
  |> mask_signature
  |> mask_serial
  |> normalize_subject
  |> birdie.snap(title: "cert rsa openssl text")
}

pub fn xdh_x25519_from_rfc8410_certificate_can_do_key_agreement_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/x509/rfc8410-x25519.pem")
  let assert Ok([parsed]) = certificate.from_pem(pem)

  let assert x509.XdhPublicKey(x25519_pub) = certificate.public_key(parsed)
  assert xdh.public_key_curve(x25519_pub) == xdh.X25519

  let #(my_private, _my_public) = xdh.generate_key_pair(xdh.X25519)
  let assert Ok(_shared_secret) =
    xdh.compute_shared_secret(my_private, x25519_pub)
}

pub fn xdh_x25519_certificate_roundtrip_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/x509/rfc8410-x25519.pem")
  let assert Ok([parsed]) = certificate.from_pem(pem)

  let der = certificate.to_der(parsed)
  let assert Ok(reparsed) = certificate.from_der(der)

  let assert x509.XdhPublicKey(orig_pub) = certificate.public_key(parsed)
  let assert x509.XdhPublicKey(new_pub) = certificate.public_key(reparsed)

  let #(test_private, _) = xdh.generate_key_pair(xdh.X25519)
  let assert Ok(shared1) = xdh.compute_shared_secret(test_private, orig_pub)
  let assert Ok(shared2) = xdh.compute_shared_secret(test_private, new_pub)
  assert shared1 == shared2
}

pub fn xdh_x25519_key_agreement_property_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/x509/rfc8410-x25519.pem")
  let assert Ok([parsed]) = certificate.from_pem(pem)
  let assert x509.XdhPublicKey(cert_pub) = certificate.public_key(parsed)

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    qcheck.return(Nil),
    fn(_) {
      let #(alice_private, _alice_public) = xdh.generate_key_pair(xdh.X25519)
      let assert Ok(shared_with_cert) =
        xdh.compute_shared_secret(alice_private, cert_pub)
      assert bit_array.byte_size(shared_with_cert) == 32

      let #(bob_private, _) = xdh.generate_key_pair(xdh.X25519)
      let assert Ok(bob_shared) =
        xdh.compute_shared_secret(bob_private, cert_pub)
      assert shared_with_cert != bob_shared

      let pub_bytes = xdh.public_key_to_bytes(cert_pub)
      let assert Ok(reimported_pub) =
        xdh.public_key_from_bytes(xdh.X25519, pub_bytes)
      let assert Ok(shared_reimported) =
        xdh.compute_shared_secret(alice_private, reimported_pub)
      assert shared_with_cert == shared_reimported

      Nil
    },
  )
}

pub fn xdh_x25519_spki_fixture_roundtrip_test() {
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/x25519_spki_pub.der")
  let assert Ok(original_pub) = xdh.public_key_from_der(pub_der)
  let assert Ok(exported_der) = xdh.public_key_to_der(original_pub)
  let assert Ok(reimported_pub) = xdh.public_key_from_der(exported_der)

  let #(test_private, _) = xdh.generate_key_pair(xdh.X25519)
  let assert Ok(shared1) = xdh.compute_shared_secret(test_private, original_pub)
  let assert Ok(shared2) =
    xdh.compute_shared_secret(test_private, reimported_pub)
  assert shared1 == shared2
}

pub fn xdh_x448_spki_fixture_roundtrip_test() {
  let assert Ok(pub_der) =
    simplifile.read_bits("test/fixtures/x448_spki_pub.der")
  let assert Ok(original_pub) = xdh.public_key_from_der(pub_der)
  assert xdh.public_key_curve(original_pub) == xdh.X448

  let assert Ok(exported_der) = xdh.public_key_to_der(original_pub)
  let assert Ok(reimported_pub) = xdh.public_key_from_der(exported_der)

  let #(test_private, _) = xdh.generate_key_pair(xdh.X448)
  let assert Ok(shared1) = xdh.compute_shared_secret(test_private, original_pub)
  let assert Ok(shared2) =
    xdh.compute_shared_secret(test_private, reimported_pub)
  assert shared1 == shared2
}

pub fn from_pem_unknown_critical_extension_rejected_test() {
  let assert Ok(pem) =
    simplifile.read(
      "test/cryptography_testvectors/vectors/x509/certificates/custom/unsupported_extension_critical.pem",
    )
  assert certificate.from_pem(pem)
    == Error(certificate.UnrecognizedCriticalExtension(x509.Oid([1, 2, 3, 4])))
}

pub fn from_pem_unknown_noncritical_extension_allowed_test() {
  let assert Ok(pem) =
    simplifile.read(
      "test/cryptography_testvectors/vectors/x509/certificates/custom/unsupported_extension.pem",
    )
  let assert Ok([_parsed]) = certificate.from_pem(pem)
}

pub fn eku_with_unknown_oids_non_critical_allowed_test() {
  let assert Ok(pem) =
    simplifile.read(
      "test/cryptography_testvectors/vectors/x509/certificates/custom/extended_key_usage.pem",
    )
  let assert Ok([parsed]) = certificate.from_pem(pem)
  let eku = certificate.extended_key_usage(parsed)
  assert list.length(eku) >= 0
}

pub fn extensions_includes_all_extensions_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("ext.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_basic_constraints(ca: False, path_len_constraint: None)
    |> certificate.with_key_usage(DigitalSignature)
    |> certificate.with_extended_key_usage(ServerAuth)
    |> certificate.with_subject_key_identifier(certificate.SkiAuto)
    |> certificate.with_dns_name("ext.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))

  let exts = certificate.extensions(parsed)

  // Verify extensions() includes all extensions
  // Basic Constraints (2.5.29.19)
  let assert Ok(_) =
    list.find(exts, fn(ext) {
      let #(x509.Oid(c), _, _) = ext
      c == [2, 5, 29, 19]
    })
  // Key Usage (2.5.29.15)
  let assert Ok(_) =
    list.find(exts, fn(ext) {
      let #(x509.Oid(c), _, _) = ext
      c == [2, 5, 29, 15]
    })
  // Extended Key Usage (2.5.29.37)
  let assert Ok(_) =
    list.find(exts, fn(ext) {
      let #(x509.Oid(c), _, _) = ext
      c == [2, 5, 29, 37]
    })
  // Subject Alt Name (2.5.29.17)
  let assert Ok(_) =
    list.find(exts, fn(ext) {
      let #(x509.Oid(c), _, _) = ext
      c == [2, 5, 29, 17]
    })
  // Subject Key Identifier (2.5.29.14)
  let assert Ok(_) =
    list.find(exts, fn(ext) {
      let #(x509.Oid(c), _, _) = ext
      c == [2, 5, 29, 14]
    })
  // Authority Key Identifier (2.5.29.35)
  let assert Ok(_) =
    list.find(exts, fn(ext) {
      let #(x509.Oid(c), _, _) = ext
      c == [2, 5, 29, 35]
    })
}

pub fn ecdsa_certificate_roundtrip_property_test() {
  let curve_gen =
    qcheck.from_generators(qcheck.return(ec.P256), [
      qcheck.return(ec.P384),
      qcheck.return(ec.P521),
    ])

  let hash_for_curve = fn(curve) {
    case curve {
      ec.P256 -> hash.Sha256
      ec.P384 -> hash.Sha384
      ec.P521 -> hash.Sha512
      _ -> hash.Sha256
    }
  }

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(10),
    curve_gen,
    fn(curve) {
      let #(private_key, _) = ec.generate_key_pair(curve)
      let subject =
        x509.name([
          x509.cn("test.example.com"),
          x509.organization("Test Org"),
        ])
      let now = timestamp.system_time()
      let later =
        timestamp.from_unix_seconds_and_nanoseconds(
          seconds: 2_000_000_000,
          nanoseconds: 0,
        )

      let assert Ok(builder) =
        certificate.new()
        |> certificate.with_subject(subject)
        |> certificate.with_validity(Validity(not_before: now, not_after: later))
        |> certificate.with_basic_constraints(
          ca: False,
          path_len_constraint: None,
        )
        |> certificate.with_key_usage(DigitalSignature)
        |> certificate.with_extended_key_usage(ServerAuth)
        |> certificate.with_dns_name("test.example.com")
        |> result.try(certificate.with_dns_name(_, "www.test.example.com"))

      let assert Ok(cert) =
        certificate.self_signed_with_ecdsa(
          builder,
          private_key,
          hash_for_curve(curve),
        )

      let der = certificate.to_der(cert)
      let assert Ok(parsed) = certificate.from_der(der)

      assert certificate.version(parsed) == 2
      let assert x509.EcPublicKey(_) = certificate.public_key(parsed)
      assert list.length(certificate.subject_alt_names(parsed)) == 2

      let assert Ok(bc) = certificate.basic_constraints(parsed)
      assert !bc.ca

      let ku = certificate.key_usage(parsed)
      assert list.contains(ku, DigitalSignature)

      let eku = certificate.extended_key_usage(parsed)
      assert list.contains(eku, ServerAuth)

      let assert Ok(_) = certificate.verify_self_signed(parsed)

      let pem = certificate.to_pem(cert)
      let assert Ok([parsed_pem]) = certificate.from_pem(pem)
      assert certificate.version(parsed_pem) == 2

      Nil
    },
  )
}

pub fn parse_subject_key_identifier_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/x509/rfc8410-x25519.pem")
  let assert Ok([parsed]) = certificate.from_pem(pem)

  let assert Ok(expected_ski) =
    bit_array.base16_decode("9B1F5EEDED043385E4F7BC623C5975B90BC8BB3B")

  let assert Ok(ski) = certificate.subject_key_identifier(parsed)
  assert ski == expected_ski
}

pub fn parse_authority_key_identifier_test() {
  let assert Ok(pem) =
    simplifile.read(
      "test/cryptography_testvectors/vectors/x509/certificates/cryptography.io.pem",
    )
  let assert Ok([parsed]) = certificate.from_pem(pem)

  let assert Ok(expected_key_id) =
    bit_array.base16_decode("C39CF3FCD3460834BBCE467FA07C5BF3E208CB59")

  let assert Ok(aki) = certificate.authority_key_identifier(parsed)
  assert aki.key_identifier == Some(expected_key_id)
  assert aki.authority_cert_issuer == None
  assert aki.authority_cert_serial_number == None
}

pub fn generated_certificate_has_ski_test() {
  let #(private_key, public_key) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("ski-test.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_subject_key_identifier(certificate.SkiAuto)
    |> certificate.with_dns_name("ski-test.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))
  let assert Ok(ski) = certificate.subject_key_identifier(parsed)

  let pub_bytes = ec.public_key_to_raw_point(public_key)
  let assert Ok(expected_ski) = crypto.hash(hash.Sha1, pub_bytes)

  assert ski == expected_ski
}

pub fn self_signed_certificate_has_aki_matching_ski_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("aki-test.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_subject_key_identifier(certificate.SkiAuto)
    |> certificate.with_dns_name("aki-test.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))
  let assert Ok(ski) = certificate.subject_key_identifier(parsed)
  let assert Ok(aki) = certificate.authority_key_identifier(parsed)

  assert aki.key_identifier == Some(ski)
  assert aki.authority_cert_issuer == None
  assert aki.authority_cert_serial_number == None
}

pub fn certificate_has_aki_by_default_test() {
  let #(private_key, public_key) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("default-aki.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_dns_name("default-aki.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))
  let assert Ok(aki) = certificate.authority_key_identifier(parsed)

  let pub_bytes = ec.public_key_to_raw_point(public_key)
  let assert Ok(expected_key_id) = crypto.hash(hash.Sha1, pub_bytes)

  assert aki.key_identifier == Some(expected_key_id)
}

pub fn certificate_without_aki_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("no-aki.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_authority_key_identifier(certificate.AkiExclude)
    |> certificate.with_dns_name("no-aki.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))

  assert certificate.authority_key_identifier(parsed) == Error(Nil)
}

pub fn certificate_with_explicit_aki_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("explicit-aki.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(custom_aki) =
    bit_array.base16_decode("DEADBEEF0102030405060708090A0B0C0D0E0F10")

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_authority_key_identifier(certificate.AkiExplicit(
      custom_aki,
    ))
    |> certificate.with_dns_name("explicit-aki.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))
  let assert Ok(aki) = certificate.authority_key_identifier(parsed)

  assert aki.key_identifier == Some(custom_aki)
}

pub fn from_pem_single_cert_returns_list_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/x509/rfc8410-x25519.pem")
  let assert Ok([cert]) = certificate.from_pem(pem)
  let assert x509.XdhPublicKey(_) = certificate.public_key(cert)
}

pub fn from_pem_multiple_certs_returns_all_in_order_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/x509/chain.pem")
  let assert Ok(certs) = certificate.from_pem(pem)
  assert list.length(certs) == 2
}

pub fn from_pem_empty_string_returns_empty_list_test() {
  assert certificate.from_pem("") == Ok([])
}

pub fn from_pem_no_cert_blocks_returns_empty_list_test() {
  let pem =
    "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIHcHbQpzGKV9PBbBclGyZkXfTC+q68Uh5s5XhGrTOpfX\n-----END PRIVATE KEY-----\n"
  assert certificate.from_pem(pem) == Ok([])
}

pub fn from_pem_partial_failure_returns_error_test() {
  let assert Ok(valid_pem) =
    simplifile.read("test/fixtures/x509/rfc8410-x25519.pem")
  let garbage_cert =
    "-----BEGIN CERTIFICATE-----\nnotvalidbase64!!!\n-----END CERTIFICATE-----\n"
  let combined = valid_pem <> "\n" <> garbage_cert
  assert certificate.from_pem(combined) == Error(certificate.ParseError)
}

pub fn custom_ski_override_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("custom-ski.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(custom_ski) =
    bit_array.base16_decode("DEADBEEF0102030405060708090A0B0C0D0E0F10")

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_subject_key_identifier(certificate.SkiExplicit(
      custom_ski,
    ))
    |> certificate.with_authority_key_identifier(certificate.AkiExplicit(
      custom_ski,
    ))
    |> certificate.with_dns_name("custom-ski.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))

  let assert Ok(ski) = certificate.subject_key_identifier(parsed)
  assert ski == custom_ski

  let assert Ok(aki) = certificate.authority_key_identifier(parsed)
  assert aki.key_identifier == Some(custom_ski)
}

pub fn certificate_without_ski_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("no-ski.example.com")])
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_dns_name("no-ski.example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))

  assert certificate.subject_key_identifier(parsed) == Error(Nil)
  let assert Ok(_aki) = certificate.authority_key_identifier(parsed)
}

pub fn parse_certificate_with_issuer_unique_id_test() {
  let assert Ok(pem) =
    simplifile.read("test/fixtures/x509/cert_with_issuer_unique_id.pem")
  let assert Ok([parsed]) = certificate.from_pem(pem)

  assert certificate.version(parsed) == 2

  let assert Ok(bc) = certificate.basic_constraints(parsed)
  assert bc.ca
}

pub fn parse_aki_with_authority_cert_issuer_test() {
  let assert Ok(pem) =
    simplifile.read(
      "test/cryptography_testvectors/vectors/x509/certificates/custom/authority_key_identifier.pem",
    )
  let assert Ok([parsed]) = certificate.from_pem(pem)

  let assert Ok(aki) = certificate.authority_key_identifier(parsed)
  let assert Some(key_id) = aki.key_identifier
  assert bit_array.byte_size(key_id) == 20

  let assert Some(issuers) = aki.authority_cert_issuer
  assert list.length(issuers) >= 1

  let assert Some(serial) = aki.authority_cert_serial_number
  assert serial == <<3>>
}

pub fn san_critical_when_subject_empty_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_dns_name("example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))
  let assert Ok(#(_, is_critical, _)) =
    list.find(certificate.extensions(parsed), fn(ext) {
      let #(x509.Oid(components), _, _) = ext
      components == [2, 5, 29, 17]
    })

  assert is_critical
}

pub fn empty_subject_without_san_rejected_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let builder =
    certificate.new()
    |> certificate.with_validity(Validity(not_before: now, not_after: later))

  assert certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)
    == Error(Nil)
}

pub fn san_not_critical_when_subject_present_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let now = timestamp.system_time()
  let later =
    timestamp.from_unix_seconds_and_nanoseconds(
      seconds: 2_000_000_000,
      nanoseconds: 0,
    )

  let subject = x509.name([x509.cn("example.com")])

  let assert Ok(builder) =
    certificate.new()
    |> certificate.with_subject(subject)
    |> certificate.with_validity(Validity(not_before: now, not_after: later))
    |> certificate.with_dns_name("example.com")

  let assert Ok(cert) =
    certificate.self_signed_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = certificate.from_der(certificate.to_der(cert))
  let assert Ok(#(_, is_critical, _)) =
    list.find(certificate.extensions(parsed), fn(ext) {
      let #(x509.Oid(components), _, _) = ext
      components == [2, 5, 29, 17]
    })

  assert !is_critical
}
