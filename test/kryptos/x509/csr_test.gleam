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
import kryptos/x509
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
