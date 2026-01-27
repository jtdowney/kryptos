import birdie
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/regexp
import gleam/result
import gleam/string
import kryptos/ec
import kryptos/hash
import kryptos/rsa
import kryptos/x509.{
  DnsName, EcPublicKey, EcdsaSha256, RsaPublicKey, RsaSha256, Unknown,
}
import kryptos/x509/csr
import qcheck
import shellout
import simplifile

fn mask_dynamic_values(output: String) -> String {
  let assert Ok(offset_re) = regexp.from_string("^ *\\d+:")
  let lines = string.split(output, "\n")
  let masked_lines =
    list.map(lines, fn(line) { regexp.replace(offset_re, line, "   N:") })

  let output = string.join(masked_lines, "\n")
  let assert Ok(len_re) = regexp.from_string("hl=\\d l= *\\d+")
  regexp.replace(len_re, output, "hl=N l= NNN")
}

fn mask_signature(output: String) -> String {
  let assert Ok(sig_re) =
    regexp.from_string("(Signature Value:\\n)((?:\\s+[0-9a-f:]+\\n?)+)")
  regexp.replace(sig_re, output, "Signature Value:\n        [MASKED]\n")
}

/// Normalize Subject line formatting across OpenSSL versions
/// OpenSSL 3.0.x uses "CN = foo" while 3.6.x uses "CN=foo"
fn normalize_subject(output: String) -> String {
  string.replace(output, " = ", "=")
}

fn contains_subsequence(haystack: BitArray, needle: BitArray) -> Bool {
  let needle_size = bit_array.byte_size(needle)
  let haystack_size = bit_array.byte_size(haystack)
  contains_subsequence_loop(haystack, needle, needle_size, haystack_size, 0)
}

fn contains_subsequence_loop(
  haystack: BitArray,
  needle: BitArray,
  needle_size: Int,
  haystack_size: Int,
  offset: Int,
) -> Bool {
  case offset + needle_size > haystack_size {
    True -> False
    False -> {
      case bit_array.slice(haystack, offset, needle_size) {
        Ok(slice) if slice == needle -> True
        _ ->
          contains_subsequence_loop(
            haystack,
            needle,
            needle_size,
            haystack_size,
            offset + 1,
          )
      }
    }
  }
}

pub fn csr_ecdsa_produces_valid_der_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("test.example.com")])

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.with_dns_name("test.example.com")

  let assert Ok(my_csr) = csr.sign_with_ecdsa(builder, private_key, hash.Sha256)

  let pem = csr.to_pem(my_csr)
  assert string.starts_with(pem, "-----BEGIN CERTIFICATE REQUEST-----")
  assert string.contains(pem, "-----END CERTIFICATE REQUEST-----")

  let der = csr.to_der(my_csr)
  let assert <<0x30, _:bits>> = der
}

pub fn csr_rsa_produces_valid_der_test() {
  let assert Ok(#(private_key, _)) = rsa.generate_key_pair(2048)
  let subject = x509.name([x509.cn("test.example.com")])

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.with_dns_name("test.example.com")

  let assert Ok(my_csr) = csr.sign_with_rsa(builder, private_key, hash.Sha256)

  let pem = csr.to_pem(my_csr)
  assert string.starts_with(pem, "-----BEGIN CERTIFICATE REQUEST-----")
  assert string.contains(pem, "-----END CERTIFICATE REQUEST-----")

  let der = csr.to_der(my_csr)
  let assert <<0x30, _:bits>> = der
}

pub fn ipv4_parsing_property_test() {
  let gen =
    qcheck.tuple4(
      qcheck.bounded_int(0, 255),
      qcheck.bounded_int(0, 255),
      qcheck.bounded_int(0, 255),
      qcheck.bounded_int(0, 255),
    )

  qcheck.run(
    qcheck.default_config() |> qcheck.with_test_count(50),
    gen,
    fn(octets) {
      let #(a, b, c, d) = octets
      let ip =
        int.to_string(a)
        <> "."
        <> int.to_string(b)
        <> "."
        <> int.to_string(c)
        <> "."
        <> int.to_string(d)

      let assert Ok(_) = csr.new() |> csr.with_ip(ip)
      Nil
    },
  )
}

pub fn ipv4_rejects_invalid_test() {
  assert csr.new() |> csr.with_ip("256.0.0.1") == Error(Nil)
  assert csr.new() |> csr.with_ip("192.168.1") == Error(Nil)
  assert csr.new() |> csr.with_ip("192.168.1.1.1") == Error(Nil)
}

pub fn ipv6_accepts_valid_test() {
  let assert Ok(_) = csr.new() |> csr.with_ip("::1")
  let assert Ok(_) = csr.new() |> csr.with_ip("::")
  let assert Ok(_) = csr.new() |> csr.with_ip("2001:db8::1")
  let assert Ok(_) =
    csr.new() |> csr.with_ip("2001:0db8:0000:0000:0000:0000:0000:0001")
}

pub fn ipv6_rejects_invalid_test() {
  assert csr.new() |> csr.with_ip("2001:db8:::1") == Error(Nil)
  assert csr.new() |> csr.with_ip("gggg::1") == Error(Nil)
}

pub fn unsupported_hash_algorithm_returns_error_test() {
  let #(ec_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("test.example.com")])

  let result =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.sign_with_ecdsa(ec_key, hash.Sha512x256)

  assert result == Error(Nil)
}

pub fn pem_lines_wrap_at_64_characters_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("test.example.com")])

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.with_dns_name("test.example.com")

  let assert Ok(my_csr) = csr.sign_with_ecdsa(builder, private_key, hash.Sha256)

  let pem = csr.to_pem(my_csr)
  let lines = string.split(pem, "\n")

  let body_lines =
    lines
    |> list.drop(1)
    |> list.take_while(fn(line) { !string.starts_with(line, "-----END") })

  let all_except_last = list.take(body_lines, list.length(body_lines) - 1)
  list.each(all_except_last, fn(line) {
    assert string.length(line) == 64
  })

  let assert [last, ..] = list.reverse(body_lines)
  assert string.length(last) <= 64
  assert string.length(last) > 0
}

// TODO: enable on javascript when shellout is fixed
// https://github.com/tynanbe/shellout/pull/14
@target(erlang)
pub fn csr_ecdsa_dns_san_verified_by_openssl_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p256_pkcs8.pem")
  let assert Ok(#(private_key, _)) = ec.from_pem(pem)

  let subject =
    x509.name([
      x509.cn("example.com"),
      x509.organization("Acme Inc"),
      x509.country("US"),
    ])

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.with_dns_name("example.com")
    |> result.try(csr.with_dns_name(_, "www.example.com"))

  let assert Ok(my_csr) = csr.sign_with_ecdsa(builder, private_key, hash.Sha256)

  let csr_pem = csr.to_pem(my_csr)

  let cmd = "echo '" <> csr_pem <> "' | openssl asn1parse -i"
  let assert Ok(output) =
    shellout.command(run: "sh", with: ["-c", cmd], in: ".", opt: [])

  birdie.snap(
    mask_dynamic_values(output),
    title: "csr ecdsa dns san openssl output",
  )

  let text_cmd = "echo '" <> csr_pem <> "' | openssl req -text -noout"
  let assert Ok(text_output) =
    shellout.command(run: "sh", with: ["-c", text_cmd], in: ".", opt: [])

  text_output
  |> mask_signature
  |> normalize_subject
  |> birdie.snap(title: "csr ecdsa dns san text")
}

pub fn ecdsa_csr_omits_null_params_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("test.example.com")])

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.with_dns_name("test.example.com")

  let assert Ok(my_csr) = csr.sign_with_ecdsa(builder, private_key, hash.Sha256)
  let der = csr.to_der(my_csr)

  let ecdsa_sha256_oid_with_null = <<
    0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x05,
    0x00,
  >>
  assert !contains_subsequence(der, ecdsa_sha256_oid_with_null)

  let ecdsa_sha256_oid_correct = <<
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
  >>
  assert contains_subsequence(der, ecdsa_sha256_oid_correct)
}

pub fn rsa_csr_includes_null_params_test() {
  let assert Ok(#(private_key, _)) = rsa.generate_key_pair(2048)
  let subject = x509.name([x509.cn("test.example.com")])

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.with_dns_name("test.example.com")

  let assert Ok(my_csr) = csr.sign_with_rsa(builder, private_key, hash.Sha256)
  let der = csr.to_der(my_csr)

  let rsa_sha256_oid_with_null = <<
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
    0x05, 0x00,
  >>
  assert contains_subsequence(der, rsa_sha256_oid_with_null)
}

// TODO: enable on javascript when shellout is fixed
// https://github.com/tynanbe/shellout/pull/14
@target(erlang)
pub fn csr_rsa_dns_san_verified_by_openssl_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/rsa2048_pkcs8.pem")
  let assert Ok(#(private_key, _)) = rsa.from_pem(pem, rsa.Pkcs8)

  let subject =
    x509.name([
      x509.cn("rsa.example.com"),
      x509.organization("RSA Corp"),
      x509.country("US"),
    ])

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.with_dns_name("rsa.example.com")

  let assert Ok(my_csr) = csr.sign_with_rsa(builder, private_key, hash.Sha256)
  let csr_pem = csr.to_pem(my_csr)

  let cmd = "echo '" <> csr_pem <> "' | openssl asn1parse -i"
  let assert Ok(output) =
    shellout.command(run: "sh", with: ["-c", cmd], in: ".", opt: [])

  birdie.snap(
    mask_dynamic_values(output),
    title: "csr rsa dns san openssl output",
  )

  let text_cmd = "echo '" <> csr_pem <> "' | openssl req -text -noout"
  let assert Ok(text_output) =
    shellout.command(run: "sh", with: ["-c", text_cmd], in: ".", opt: [])

  text_output
  |> mask_signature
  |> normalize_subject
  |> birdie.snap(title: "csr rsa dns san text")
}

// TODO: enable on javascript when shellout is fixed
// https://github.com/tynanbe/shellout/pull/14
@target(erlang)
pub fn csr_ecdsa_email_san_verified_by_openssl_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p256_pkcs8.pem")
  let assert Ok(#(private_key, _)) = ec.from_pem(pem)

  let subject = x509.name([x509.cn("user@example.com")])

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.with_email("user@example.com")

  let assert Ok(my_csr) = csr.sign_with_ecdsa(builder, private_key, hash.Sha256)
  let csr_pem = csr.to_pem(my_csr)

  let cmd = "echo '" <> csr_pem <> "' | openssl asn1parse -i"
  let assert Ok(output) =
    shellout.command(run: "sh", with: ["-c", cmd], in: ".", opt: [])

  birdie.snap(
    mask_dynamic_values(output),
    title: "csr ecdsa email san openssl output",
  )

  let text_cmd = "echo '" <> csr_pem <> "' | openssl req -text -noout"
  let assert Ok(text_output) =
    shellout.command(run: "sh", with: ["-c", text_cmd], in: ".", opt: [])

  text_output
  |> mask_signature
  |> normalize_subject
  |> birdie.snap(title: "csr ecdsa email san text")
}

// TODO: enable on javascript when shellout is fixed
// https://github.com/tynanbe/shellout/pull/14
@target(erlang)
pub fn csr_ecdsa_ipv4_san_verified_by_openssl_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p256_pkcs8.pem")
  let assert Ok(#(private_key, _)) = ec.from_pem(pem)

  let subject = x509.name([x509.cn("server.local")])

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.with_ip("192.168.1.1")

  let assert Ok(my_csr) = csr.sign_with_ecdsa(builder, private_key, hash.Sha256)
  let csr_pem = csr.to_pem(my_csr)

  let cmd = "echo '" <> csr_pem <> "' | openssl asn1parse -i"
  let assert Ok(output) =
    shellout.command(run: "sh", with: ["-c", cmd], in: ".", opt: [])

  birdie.snap(
    mask_dynamic_values(output),
    title: "csr ecdsa ipv4 san openssl output",
  )

  let text_cmd = "echo '" <> csr_pem <> "' | openssl req -text -noout"
  let assert Ok(text_output) =
    shellout.command(run: "sh", with: ["-c", text_cmd], in: ".", opt: [])

  text_output
  |> mask_signature
  |> normalize_subject
  |> birdie.snap(title: "csr ecdsa ipv4 san text")
}

// TODO: enable on javascript when shellout is fixed
// https://github.com/tynanbe/shellout/pull/14
@target(erlang)
pub fn csr_ecdsa_ipv6_san_verified_by_openssl_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p256_pkcs8.pem")
  let assert Ok(#(private_key, _)) = ec.from_pem(pem)

  let subject = x509.name([x509.cn("server.local")])

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.with_ip("::1")

  let assert Ok(my_csr) = csr.sign_with_ecdsa(builder, private_key, hash.Sha256)
  let csr_pem = csr.to_pem(my_csr)

  let cmd = "echo '" <> csr_pem <> "' | openssl asn1parse -i"
  let assert Ok(output) =
    shellout.command(run: "sh", with: ["-c", cmd], in: ".", opt: [])

  birdie.snap(
    mask_dynamic_values(output),
    title: "csr ecdsa ipv6 san openssl output",
  )

  let text_cmd = "echo '" <> csr_pem <> "' | openssl req -text -noout"
  let assert Ok(text_output) =
    shellout.command(run: "sh", with: ["-c", text_cmd], in: ".", opt: [])

  text_output
  |> mask_signature
  |> normalize_subject
  |> birdie.snap(title: "csr ecdsa ipv6 san text")
}

pub fn dns_name_accepts_ascii_test() {
  let assert Ok(_) = csr.new() |> csr.with_dns_name("example.com")
}

pub fn dns_name_rejects_non_ascii_test() {
  assert csr.new() |> csr.with_dns_name("exämple.com") == Error(Nil)
}

pub fn email_accepts_ascii_test() {
  let assert Ok(_) = csr.new() |> csr.with_email("user@example.com")
}

pub fn email_rejects_non_ascii_test() {
  assert csr.new() |> csr.with_email("üser@example.com") == Error(Nil)
}

pub fn ipv6_full_form_parsing_property_test() {
  let hex_word = qcheck.bounded_int(0, 0xFFFF)
  let gen =
    qcheck.tuple4(
      qcheck.tuple4(hex_word, hex_word, hex_word, hex_word),
      qcheck.tuple4(hex_word, hex_word, hex_word, hex_word),
      qcheck.return(Nil),
      qcheck.return(Nil),
    )
    |> qcheck.map(fn(parts) {
      let #(#(a, b, c, d), #(e, f, g, h), _, _) = parts
      [a, b, c, d, e, f, g, h]
      |> list.map(int.to_base16)
      |> string.join(":")
    })

  qcheck.run(qcheck.default_config() |> qcheck.with_test_count(50), gen, fn(ip) {
    let assert Ok(_) = csr.new() |> csr.with_ip(ip)
    Nil
  })
}

pub fn ecdsa_csr_roundtrip_property_test() {
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
        x509.name([x509.cn("test.example.com"), x509.organization("Test Org")])

      let assert Ok(builder) =
        csr.new()
        |> csr.with_subject(subject)
        |> csr.with_dns_name("test.example.com")
        |> result.try(csr.with_dns_name(_, "www.test.example.com"))

      let assert Ok(built_csr) =
        csr.sign_with_ecdsa(builder, private_key, hash_for_curve(curve))

      let der = csr.to_der(built_csr)
      let assert Ok(parsed) = csr.from_der(der)

      assert csr.version(parsed) == 0
      let assert EcPublicKey(_) = csr.public_key(parsed)
      assert list.length(csr.subject_alt_names(parsed)) == 2

      let pem = csr.to_pem(built_csr)
      let assert Ok(parsed_from_pem) = csr.from_pem(pem)
      assert csr.version(parsed_from_pem) == 0

      Nil
    },
  )
}

pub fn rsa_csr_roundtrip_test() {
  let assert Ok(#(private_key, _)) = rsa.generate_key_pair(2048)
  let subject = x509.name([x509.cn("rsa.example.com")])

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.with_dns_name("rsa.example.com")

  let assert Ok(built_csr) =
    csr.sign_with_rsa(builder, private_key, hash.Sha256)

  let der = csr.to_der(built_csr)
  let assert Ok(parsed) = csr.from_der(der)

  assert csr.version(parsed) == 0
  let assert RsaPublicKey(_) = csr.public_key(parsed)
  assert csr.signature_algorithm(parsed) == RsaSha256
  assert csr.subject_alt_names(parsed) == [DnsName("rsa.example.com")]
}

pub fn from_pem_invalid_label_test() {
  let bad_pem =
    "-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALH9sWPdA4KSMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVu
dXNlZDAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnVudXNlZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJFfsRbq/cfLmz5X9Q7B
test
-----END CERTIFICATE-----"

  assert csr.from_pem(bad_pem) == Error(csr.InvalidPem)
}

pub fn from_der_truncated_test() {
  let truncated = <<0x30, 0x82, 0x01, 0x00>>
  assert csr.from_der(truncated) == Error(csr.InvalidStructure)
}

pub fn from_der_bad_signature_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("test.example.com")])

  let assert Ok(built_csr) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.sign_with_ecdsa(private_key, hash.Sha256)

  let der = csr.to_der(built_csr)
  let size = bit_array.byte_size(der)

  let assert Ok(prefix) = bit_array.slice(der, 0, size - 4)
  let corrupted = bit_array.concat([prefix, <<0xFF, 0xFF, 0xFF, 0xFF>>])

  assert csr.from_der(corrupted) == Error(csr.SignatureVerificationFailed)
}

pub fn from_der_unverified_accepts_bad_signature_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)
  let subject = x509.name([x509.cn("test.example.com")])

  let assert Ok(built_csr) =
    csr.new()
    |> csr.with_subject(subject)
    |> csr.sign_with_ecdsa(private_key, hash.Sha256)

  let der = csr.to_der(built_csr)
  let size = bit_array.byte_size(der)

  let assert Ok(prefix) = bit_array.slice(der, 0, size - 4)
  let corrupted = bit_array.concat([prefix, <<0xFF, 0xFF, 0xFF, 0xFF>>])

  let assert Ok(parsed) = csr.from_der_unverified(corrupted)
  assert csr.version(parsed) == 0
}

pub fn parsed_csr_subject_alt_names_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)

  let assert Ok(builder) =
    csr.new()
    |> csr.with_subject(x509.name([x509.cn("test")]))
    |> csr.with_dns_name("example.com")
    |> result.try(csr.with_dns_name(_, "www.example.com"))
    |> result.try(csr.with_email(_, "admin@example.com"))

  let assert Ok(built_csr) =
    csr.sign_with_ecdsa(builder, private_key, hash.Sha256)

  let assert Ok(parsed) = csr.from_der(csr.to_der(built_csr))

  let sans = csr.subject_alt_names(parsed)
  assert list.length(sans) == 3

  assert list.contains(sans, DnsName("example.com"))
  assert list.contains(sans, DnsName("www.example.com"))
  assert list.contains(sans, x509.Email("admin@example.com"))
}

pub fn parsed_csr_signature_algorithm_test() {
  let #(private_key, _) = ec.generate_key_pair(ec.P256)

  let assert Ok(built_csr) =
    csr.new()
    |> csr.with_subject(x509.name([x509.cn("test")]))
    |> csr.sign_with_ecdsa(private_key, hash.Sha256)

  let assert Ok(parsed) = csr.from_der(csr.to_der(built_csr))
  assert csr.signature_algorithm(parsed) == EcdsaSha256
}

/// Interop test: parse an OpenSSL-generated CSR and verify all fields
pub fn parse_openssl_generated_csr_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/p256_csr.pem")
  let assert Ok(parsed) = csr.from_pem(pem)

  // Verify version
  assert csr.version(parsed) == 0

  assert csr.signature_algorithm(parsed) == EcdsaSha256

  let assert EcPublicKey(_) = csr.public_key(parsed)

  let subject_str =
    parsed
    |> csr.subject
    |> x509.name_to_string
  assert subject_str == "CN=openssl-test.example.com, O=OpenSSL Test Org, C=US"

  let sans = csr.subject_alt_names(parsed)
  assert list.length(sans) == 5
  assert list.contains(sans, DnsName("openssl-test.example.com"))
  assert list.contains(sans, DnsName("www.openssl-test.example.com"))
  assert list.contains(sans, x509.Email("admin@example.com"))
  assert list.contains(sans, x509.IpAddress(<<192, 168, 1, 100>>))
  assert list.contains(
    sans,
    x509.IpAddress(<<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>),
  )
}

/// Security test: Unknown SAN types should be returned as Unknown,
/// and subsequent SANs should NOT be silently dropped.
///
/// This CSR has: DNS:legitimate.example.com, URI:..., DNS:also-legit.example.com
/// The URI (tag [6] = 0x86) is not a supported type, so it should be parsed
/// as Unknown. Critically, the DNS name AFTER the URI must still be returned.
pub fn parse_csr_with_unknown_san_type_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/csr_with_uri.pem")
  let assert Ok(parsed) = csr.from_pem(pem)

  let sans = csr.subject_alt_names(parsed)

  // Must have 3 SANs: DNS, Unknown (URI), DNS
  assert list.length(sans) == 3

  // First DNS name
  assert list.contains(sans, DnsName("legitimate.example.com"))

  // Second DNS name - this was previously dropped due to the security bug
  assert list.contains(sans, DnsName("also-legit.example.com"))

  // The URI should be returned as Unknown with tag 0x86 (context-specific [6])
  let has_unknown =
    list.any(sans, fn(san) {
      case san {
        Unknown(0x86, _) -> True
        _ -> False
      }
    })
  assert has_unknown
}

pub fn san_after_unknown_type_must_be_returned_test() {
  let assert Ok(pem) = simplifile.read("test/fixtures/csr_with_uri.pem")
  let assert Ok(parsed) = csr.from_pem(pem)

  let sans = csr.subject_alt_names(parsed)
  assert list.length(sans) == 3

  let dns_names =
    list.filter_map(sans, fn(san) {
      case san {
        DnsName(name) -> Ok(name)
        _ -> Error(Nil)
      }
    })

  assert list.length(dns_names) == 2
  assert list.contains(dns_names, "legitimate.example.com")
  assert list.contains(dns_names, "also-legit.example.com")
}
