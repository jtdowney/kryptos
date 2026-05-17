import birdie
import gleam/bit_array
import gleam/int
import gleam/list
import kryptos/crypto
import kryptos/internal/der
import kryptos/mldsa.{type ParameterSet}
import qcheck
import simplifile

const test_count = 10

const all_params = [mldsa.Mldsa44, mldsa.Mldsa65, mldsa.Mldsa87]

fn config() -> qcheck.Config {
  qcheck.default_config() |> qcheck.with_test_count(test_count)
}

fn param_gen() -> qcheck.Generator(ParameterSet) {
  qcheck.from_generators(qcheck.return(mldsa.Mldsa44), [
    qcheck.return(mldsa.Mldsa65),
    qcheck.return(mldsa.Mldsa87),
  ])
}

fn param_name(param: ParameterSet) -> String {
  case param {
    mldsa.Mldsa44 -> "mldsa44"
    mldsa.Mldsa65 -> "mldsa65"
    mldsa.Mldsa87 -> "mldsa87"
  }
}

fn load_key(param: ParameterSet) -> String {
  let assert Ok(pem) =
    simplifile.read("test/fixtures/" <> param_name(param) <> "_pkcs8.pem")
  pem
}

fn load_key_der(param: ParameterSet) -> BitArray {
  let assert Ok(der) =
    simplifile.read_bits("test/fixtures/" <> param_name(param) <> "_pkcs8.der")
  der
}

pub fn mldsa_sign_verify_roundtrip_property_test() {
  let gen = qcheck.tuple2(param_gen(), qcheck.byte_aligned_bit_array())

  qcheck.run(config(), gen, fn(input) {
    let #(param, message) = input
    let #(private_key, public_key) = mldsa.generate_key_pair(param)
    let signature = mldsa.sign(private_key, message)
    assert mldsa.verify(public_key, message, signature)
  })
}

pub fn mldsa_wrong_key_fails_property_test() {
  let gen = qcheck.tuple2(param_gen(), qcheck.byte_aligned_bit_array())

  qcheck.run(config(), gen, fn(input) {
    let #(param, message) = input
    let #(private_key, _) = mldsa.generate_key_pair(param)
    let #(_, other_public_key) = mldsa.generate_key_pair(param)
    let signature = mldsa.sign(private_key, message)
    assert !mldsa.verify(other_public_key, message, signature)
  })
}

pub fn mldsa_tampered_message_fails_property_test() {
  let gen =
    qcheck.tuple2(param_gen(), qcheck.non_empty_byte_aligned_bit_array())

  qcheck.run(config(), gen, fn(input) {
    let #(param, message) = input
    let #(private_key, public_key) = mldsa.generate_key_pair(param)
    let signature = mldsa.sign(private_key, message)

    let assert <<first_byte:8, rest:bits>> = message
    let tampered = <<{ int.bitwise_exclusive_or(first_byte, 1) }:8, rest:bits>>

    assert !mldsa.verify(public_key, tampered, signature)
  })
}

pub fn mldsa_tampered_signature_fails_test() {
  let #(private_key, public_key) = mldsa.generate_key_pair(mldsa.Mldsa44)
  let message = <<"message":utf8>>
  let signature = mldsa.sign(private_key, message)

  let assert <<first_byte:8, rest:bits>> = signature
  let tampered_byte = int.bitwise_exclusive_or(first_byte, 1)
  let tampered_signature = <<tampered_byte:8, rest:bits>>

  assert !mldsa.verify(public_key, message, tampered_signature)
}

pub fn mldsa_cross_parameter_set_verify_fails_test() {
  let #(priv44, _) = mldsa.generate_key_pair(mldsa.Mldsa44)
  let #(_, pub65) = mldsa.generate_key_pair(mldsa.Mldsa65)
  let sig = mldsa.sign(priv44, <<"cross":utf8>>)
  assert !mldsa.verify(pub65, <<"cross":utf8>>, sig)
}

pub fn mldsa_empty_message_sign_verify_test() {
  let #(private, public) = mldsa.generate_key_pair(mldsa.Mldsa44)
  let sig = mldsa.sign(private, <<>>)
  assert mldsa.verify(public, <<>>, sig)
}

pub fn mldsa_parameter_set_introspection_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let #(private, public) = mldsa.generate_key_pair(param)
    assert mldsa.parameter_set(private) == param
    assert mldsa.public_key_parameter_set(public) == param
  })
}

pub fn mldsa_public_key_from_private_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let #(private_key, public_key) = mldsa.generate_key_pair(param)
    let derived = mldsa.public_key_from_private_key(private_key)
    assert mldsa.public_key_to_bytes(derived)
      == mldsa.public_key_to_bytes(public_key)
  })
}

pub fn mldsa_signature_sizes_test() {
  let msg = <<"test":utf8>>
  list.each(all_params, fn(param) {
    let #(private, _) = mldsa.generate_key_pair(param)
    assert bit_array.byte_size(mldsa.sign(private, msg))
      == mldsa.signature_size(param)
  })
}

pub fn mldsa_public_key_sizes_test() {
  list.each(all_params, fn(param) {
    let #(_, public) = mldsa.generate_key_pair(param)
    assert bit_array.byte_size(mldsa.public_key_to_bytes(public))
      == mldsa.key_size(param)
  })
}

pub fn mldsa_public_key_bytes_roundtrip_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let #(_, public_key) = mldsa.generate_key_pair(param)
    let bytes = mldsa.public_key_to_bytes(public_key)
    let assert Ok(restored) = mldsa.public_key_from_bytes(param, bytes)
    assert mldsa.public_key_to_bytes(restored) == bytes
  })
}

pub fn mldsa_public_key_from_bytes_wrong_size_test() {
  let assert Error(Nil) =
    mldsa.public_key_from_bytes(mldsa.Mldsa44, <<"too short":utf8>>)
}

pub fn mldsa_import_private_key_pem_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let assert Ok(#(private, public)) = mldsa.from_pem(load_key(param))
    let message = <<"too many secrets":utf8>>
    let signature = mldsa.sign(private, message)
    assert mldsa.verify(public, message, signature: signature)
  })
}

pub fn mldsa_import_private_key_der_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let assert Ok(#(private, public)) = mldsa.from_der(load_key_der(param))
    let message = <<"too many secrets":utf8>>
    let signature = mldsa.sign(private, message)
    assert mldsa.verify(public, message, signature: signature)
  })
}

pub fn mldsa_from_pem_invalid_test() {
  assert mldsa.from_pem("garbage") == Error(Nil)
  assert mldsa.from_pem(
      "-----BEGIN PRIVATE KEY-----\nnotbase64\n-----END PRIVATE KEY-----",
    )
    == Error(Nil)
}

pub fn mldsa_from_der_invalid_test() {
  assert mldsa.from_der(<<0, 1, 2, 3>>) == Error(Nil)
  assert mldsa.from_der(<<>>) == Error(Nil)
}

pub fn mldsa_export_private_key_pem_roundtrip_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let name = param_name(param)
    let assert Ok(#(private_key, original_public)) =
      mldsa.from_pem(load_key(param))
    let pem = mldsa.to_pem(private_key)
    let assert Ok(#(imported_private, _)) = mldsa.from_pem(pem)
    let message = <<{ name <> " pem export roundtrip" }:utf8>>
    let signature = mldsa.sign(imported_private, message)
    assert mldsa.verify(original_public, message, signature: signature)
  })
}

pub fn mldsa_export_private_key_der_roundtrip_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let name = param_name(param)
    let assert Ok(#(private_key, original_public)) =
      mldsa.from_pem(load_key(param))
    let der = mldsa.to_der(private_key)
    let assert Ok(#(imported_private, _)) = mldsa.from_der(der)
    let message = <<{ name <> " der export roundtrip" }:utf8>>
    let signature = mldsa.sign(imported_private, message)
    assert mldsa.verify(original_public, message, signature: signature)
  })
}

pub fn mldsa_export_public_key_pem_snapshot_test() {
  list.each(all_params, fn(param) {
    let assert Ok(#(_, public_key)) = mldsa.from_pem(load_key(param))
    let pem = mldsa.public_key_to_pem(public_key)
    birdie.snap(pem, title: param_name(param) <> " public key pem")
  })
}

pub fn mldsa_export_public_key_der_snapshot_test() {
  list.each(all_params, fn(param) {
    let assert Ok(#(_, public_key)) = mldsa.from_pem(load_key(param))
    let der = mldsa.public_key_to_der(public_key)
    birdie.snap(
      bit_array.base16_encode(der),
      title: param_name(param) <> " public key der",
    )
  })
}

pub fn mldsa_public_key_pem_roundtrip_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let assert Ok(#(_, public_key)) = mldsa.from_pem(load_key(param))
    let pem = mldsa.public_key_to_pem(public_key)
    let assert Ok(imported_public) = mldsa.public_key_from_pem(pem)
    assert mldsa.public_key_to_bytes(imported_public)
      == mldsa.public_key_to_bytes(public_key)
  })
}

pub fn mldsa_public_key_der_roundtrip_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let assert Ok(#(_, public_key)) = mldsa.from_pem(load_key(param))
    let der = mldsa.public_key_to_der(public_key)
    let assert Ok(imported_public) = mldsa.public_key_from_der(der)
    assert mldsa.public_key_to_bytes(imported_public)
      == mldsa.public_key_to_bytes(public_key)
  })
}

fn build_spki_der(oid_components: List(Int), key_bytes: BitArray) -> BitArray {
  let assert Ok(oid_der) = der.encode_oid(oid_components)
  let assert Ok(alg_id) = der.encode_sequence(oid_der)
  let assert Ok(bit_string) = der.encode_bit_string(key_bytes)
  let assert Ok(spki) =
    der.encode_sequence(bit_array.concat([alg_id, bit_string]))
  spki
}

fn param_oid(param: ParameterSet) -> List(Int) {
  case param {
    mldsa.Mldsa44 -> [2, 16, 840, 1, 101, 3, 4, 3, 17]
    mldsa.Mldsa65 -> [2, 16, 840, 1, 101, 3, 4, 3, 18]
    mldsa.Mldsa87 -> [2, 16, 840, 1, 101, 3, 4, 3, 19]
  }
}

pub fn mldsa_public_key_from_der_wrong_key_length_test() {
  list.each(all_params, fn(param) {
    let too_short = build_spki_der(param_oid(param), <<0:64>>)
    assert mldsa.public_key_from_der(too_short) == Error(Nil)
  })
}

pub fn mldsa_public_key_from_pem_wrong_key_length_test() {
  let spki_der = build_spki_der(param_oid(mldsa.Mldsa44), <<0x42>>)
  let base64 = bit_array.base64_encode(spki_der, True)
  let pem =
    "-----BEGIN PUBLIC KEY-----\n" <> base64 <> "\n-----END PUBLIC KEY-----\n"
  assert mldsa.public_key_from_pem(pem) == Error(Nil)
}

pub fn mldsa_public_key_from_der_empty_key_test() {
  let empty_key = build_spki_der(param_oid(mldsa.Mldsa44), <<>>)
  assert mldsa.public_key_from_der(empty_key) == Error(Nil)
}

pub fn mldsa_from_seed_sign_verify_test() {
  let seed = crypto.random_bytes(32)
  let assert Ok(#(private, public)) = mldsa.from_seed(mldsa.Mldsa44, seed)
  let message = <<"from seed test":utf8>>
  let signature = mldsa.sign(private, message)
  assert mldsa.verify(public, message, signature: signature)
}

pub fn mldsa_from_seed_wrong_size_test() {
  assert mldsa.from_seed(mldsa.Mldsa44, <<1, 2, 3>>) == Error(Nil)
  assert mldsa.from_seed(mldsa.Mldsa44, <<>>) == Error(Nil)
}

pub fn mldsa_from_seed_public_key_from_private_test() {
  let seed = crypto.random_bytes(32)
  let assert Ok(#(private, public)) = mldsa.from_seed(mldsa.Mldsa44, seed)
  let derived = mldsa.public_key_from_private_key(private)
  assert mldsa.public_key_to_bytes(derived) == mldsa.public_key_to_bytes(public)
}

pub fn mldsa_from_seed_deterministic_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let seed = crypto.random_bytes(32)
    let assert Ok(#(_, pub1)) = mldsa.from_seed(param, seed)
    let assert Ok(#(_, pub2)) = mldsa.from_seed(param, seed)
    assert mldsa.public_key_to_bytes(pub1) == mldsa.public_key_to_bytes(pub2)
  })
}

pub fn mldsa_from_seed_parameter_set_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let seed = crypto.random_bytes(32)
    let assert Ok(#(private, _)) = mldsa.from_seed(param, seed)
    assert mldsa.parameter_set(private) == param
  })
}

pub fn mldsa_import_seed_pem_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let assert Ok(pem) =
      simplifile.read(
        "test/fixtures/" <> param_name(param) <> "_seed_pkcs8.pem",
      )
    let assert Ok(#(private, public)) = mldsa.from_pem(pem)
    let signature = mldsa.sign(private, <<"seed key test":utf8>>)
    assert mldsa.verify(public, <<"seed key test":utf8>>, signature: signature)
  })
}

pub fn mldsa_import_seed_der_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let assert Ok(der) =
      simplifile.read_bits(
        "test/fixtures/" <> param_name(param) <> "_seed_pkcs8.der",
      )
    let assert Ok(#(private, public)) = mldsa.from_der(der)
    let signature = mldsa.sign(private, <<"seed key test":utf8>>)
    assert mldsa.verify(public, <<"seed key test":utf8>>, signature: signature)
  })
}

pub fn mldsa_from_seed_der_roundtrip_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let seed = crypto.random_bytes(32)
    let assert Ok(#(private, public)) = mldsa.from_seed(param, seed)
    let der = mldsa.to_der(private)
    let assert Ok(#(reimported_private, reimported_public)) =
      mldsa.from_der(der)
    assert mldsa.public_key_to_bytes(public)
      == mldsa.public_key_to_bytes(reimported_public)
    let sig = mldsa.sign(reimported_private, <<"roundtrip":utf8>>)
    assert mldsa.verify(public, <<"roundtrip":utf8>>, signature: sig)
  })
}

pub fn mldsa_from_seed_pem_roundtrip_property_test() {
  qcheck.run(config(), param_gen(), fn(param) {
    let seed = crypto.random_bytes(32)
    let assert Ok(#(private, public)) = mldsa.from_seed(param, seed)
    let pem = mldsa.to_pem(private)
    let assert Ok(#(reimported_private, _)) = mldsa.from_pem(pem)
    let sig = mldsa.sign(reimported_private, <<"pem roundtrip":utf8>>)
    assert mldsa.verify(public, <<"pem roundtrip":utf8>>, signature: sig)
  })
}
