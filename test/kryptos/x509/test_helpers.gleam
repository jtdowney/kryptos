/// Shared test utilities for x509 tests.
import gleam/list
import gleam/regexp
import gleam/string
import kryptos/x509.{type Oid, Oid}

pub fn has_oid(items: List(#(Oid, Bool, BitArray)), target: List(Int)) -> Bool {
  list.any(items, fn(item) { item.0 == Oid(target) })
}

pub fn count_oid(items: List(#(Oid, Bool, BitArray)), target: List(Int)) -> Int {
  list.count(items, fn(item) { item.0 == Oid(target) })
}

/// Check if an attribute (without critical flag) matches a target OID.
pub fn has_attr_oid(items: List(#(Oid, BitArray)), target: List(Int)) -> Bool {
  list.any(items, fn(item) { item.0 == Oid(target) })
}

pub fn mask_dynamic_values(output: String) -> String {
  let assert Ok(offset_re) = regexp.from_string("^ *\\d+:")
  let lines = string.split(output, "\n")
  let masked_lines =
    list.map(lines, fn(line) { regexp.replace(offset_re, line, "   N:") })

  let output = string.join(masked_lines, "\n")
  let assert Ok(len_re) = regexp.from_string("hl=\\d l= *\\d+")
  regexp.replace(len_re, output, "hl=N l= NNN")
}

pub fn mask_signature(output: String) -> String {
  let assert Ok(sig_re) =
    regexp.from_string("(Signature Value:\\n)((?:\\s+[0-9a-f:]+\\n?)+)")
  regexp.replace(sig_re, output, "Signature Value:\n        [MASKED]\n")
}

pub fn mask_serial(output: String) -> String {
  let assert Ok(serial_re) =
    regexp.from_string("Serial Number:\\n\\s+[0-9a-f:]+")
  regexp.replace(serial_re, output, "Serial Number:\n        [MASKED]")
}

/// Normalize Subject line formatting across OpenSSL versions.
/// OpenSSL 3.0.x uses "CN = foo" while 3.6.x uses "CN=foo".
pub fn normalize_subject(output: String) -> String {
  string.replace(output, " = ", "=")
}
