import bitty as p
import gleam/list
import gleam/result
import kryptos/internal/x509 as internal_x509
import kryptos/x509.{DnsName, Email, Unknown}

const dns_example_com = <<0x82, 0x0b, "example.com":utf8>>

const dns_test_com = <<0x82, 0x08, "test.com":utf8>>

pub fn parse_unknown_san_type_continues_parsing_test() {
  let san_extension_bytes = <<
    0x30, 0x13, 0xa3, 0x04, "test":utf8, dns_example_com:bits,
  >>

  let assert Ok(sans) =
    p.run(internal_x509.san_extension(False), on: san_extension_bytes)
    |> result.replace_error(Nil)

  assert list.length(sans) == 2
  assert list.contains(sans, Unknown(0xa3, <<"test":utf8>>))
  assert list.contains(sans, DnsName("example.com"))
}

pub fn parse_unknown_san_type_in_critical_extension_fails_test() {
  let san_extension_bytes = <<
    0x30, 0x13, 0xa3, 0x04, "test":utf8, dns_example_com:bits,
  >>

  let result =
    p.run(internal_x509.san_extension(True), on: san_extension_bytes)
    |> result.replace_error(Nil)
  assert result == Error(Nil)
}

pub fn parse_edi_party_name_as_unknown_test() {
  let san_extension_bytes = <<
    0x30, 0x12, 0xa5, 0x03, 0x01, 0x02, 0x03, dns_example_com:bits,
  >>

  let assert Ok(sans) =
    p.run(internal_x509.san_extension(False), on: san_extension_bytes)
    |> result.replace_error(Nil)

  assert list.length(sans) == 2
  assert list.contains(sans, Unknown(0xa5, <<0x01, 0x02, 0x03>>))
  assert list.contains(sans, DnsName("example.com"))
}

const begin_marker = "-----BEGIN CERTIFICATE-----"

const end_marker = "-----END CERTIFICATE-----"

pub fn decode_pem_all_truncated_single_block_test() {
  let pem = begin_marker <> "\nAGVsbG8=\n"
  assert internal_x509.decode_pem_all(pem, begin_marker, end_marker)
    == Error(Nil)
}

pub fn decode_pem_all_valid_then_truncated_test() {
  let pem =
    begin_marker
    <> "\nAGVsbG8=\n"
    <> end_marker
    <> "\n"
    <> begin_marker
    <> "\nd29ybGQ=\n"
  assert internal_x509.decode_pem_all(pem, begin_marker, end_marker)
    == Error(Nil)
}

pub fn decode_pem_all_valid_single_block_test() {
  let pem = begin_marker <> "\naGVsbG8=\n" <> end_marker <> "\n"
  let assert Ok(blocks) =
    internal_x509.decode_pem_all(pem, begin_marker, end_marker)
  assert list.length(blocks) == 1
  let assert Ok(first) = list.first(blocks)
  assert first == <<"hello":utf8>>
}

pub fn decode_pem_all_valid_multiple_blocks_test() {
  let pem =
    begin_marker
    <> "\naGVsbG8=\n"
    <> end_marker
    <> "\n"
    <> begin_marker
    <> "\nd29ybGQ=\n"
    <> end_marker
    <> "\n"
  let assert Ok(blocks) =
    internal_x509.decode_pem_all(pem, begin_marker, end_marker)
  assert blocks == [<<"hello":utf8>>, <<"world":utf8>>]
}

pub fn decode_pem_all_no_blocks_test() {
  let pem = "just some text\nno PEM here\n"
  assert internal_x509.decode_pem_all(pem, begin_marker, end_marker) == Ok([])
  assert internal_x509.decode_pem_all("", begin_marker, end_marker) == Ok([])
}

pub fn parse_multiple_unknown_san_types_test() {
  let san_extension_bytes = <<
    0x30, 0x1b, 0xa3, 0x02, 0xab, 0xcd, 0xa5, 0x02, 0x12, 0x34,
    dns_test_com:bits, 0x81, 0x07, "a@b.com":utf8,
  >>

  let assert Ok(sans) =
    p.run(internal_x509.san_extension(False), on: san_extension_bytes)
    |> result.replace_error(Nil)

  assert list.length(sans) == 4
  assert list.contains(sans, Unknown(0xa3, <<0xab, 0xcd>>))
  assert list.contains(sans, Unknown(0xa5, <<0x12, 0x34>>))
  assert list.contains(sans, DnsName("test.com"))
  assert list.contains(sans, Email("a@b.com"))
}
