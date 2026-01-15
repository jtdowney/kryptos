import gleam/bit_array
import gleam/list
import kryptos/crypto
import kryptos/hash
import kryptos/hmac
import kryptos/utils
import qcheck

// RFC 4231 Test Vectors - keep as example-based
pub fn hmac_sha256_rfc4231_test_case_1_test() {
  let assert Ok(key) =
    bit_array.base16_decode("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
  let data = <<"Hi There":utf8>>

  let assert Ok(result) = crypto.hmac(hash.Sha256, key, data)

  assert bit_array.base16_encode(result)
    == "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7"
}

pub fn hmac_sha256_rfc4231_test_case_2_test() {
  let key = <<"Jefe":utf8>>
  let data = <<"what do ya want for nothing?":utf8>>

  let assert Ok(result) = crypto.hmac(hash.Sha256, key, data)

  assert bit_array.base16_encode(result)
    == "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843"
}

pub fn hmac_sha256_rfc4231_test_case_3_test() {
  let assert Ok(key) =
    bit_array.base16_decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
  let assert Ok(data) =
    bit_array.base16_decode(
      "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
    )

  let assert Ok(result) = crypto.hmac(hash.Sha256, key, data)

  assert bit_array.base16_encode(result)
    == "773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED565FE"
}

pub fn hmac_sha512_rfc4231_test_case_1_test() {
  let assert Ok(key) =
    bit_array.base16_decode("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
  let data = <<"Hi There":utf8>>

  let assert Ok(result) = crypto.hmac(hash.Sha512, key, data)

  assert bit_array.base16_encode(result)
    == "87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854"
}

pub fn hmac_sha512_rfc4231_test_case_2_test() {
  let key = <<"Jefe":utf8>>
  let data = <<"what do ya want for nothing?":utf8>>

  let assert Ok(result) = crypto.hmac(hash.Sha512, key, data)

  assert bit_array.base16_encode(result)
    == "164B7A7BFCF819E2E395FBE73B56E0A387BD64222E831FD610270CD7EA2505549758BF75C05A994A6D034F65F8F0E6FDCAEAB1A34D4A6B4B636E070A38BCE737"
}

pub fn hmac_sha1_test() {
  let key = <<"key":utf8>>
  let data = <<"The quick brown fox jumps over the lazy dog":utf8>>

  let assert Ok(result) = crypto.hmac(hash.Sha1, key, data)

  assert bit_array.base16_encode(result)
    == "DE7C9B85B8B78AA6BC8A7A36F70A90701C9DB4D9"
}

pub fn hmac_md5_test() {
  let key = <<"key":utf8>>
  let data = <<"The quick brown fox jumps over the lazy dog":utf8>>

  let assert Ok(result) = crypto.hmac(hash.Md5, key, data)

  assert bit_array.base16_encode(result) == "80070713463E7749B90C2DC24911E275"
}

pub fn hmac_algorithms_table_test() {
  let key = <<"secret key":utf8>>
  let data = <<"too many secrets":utf8>>

  [
    #(hash.Md5, "D227C4587CDA0681B779EBEFE5443DD7"),
    #(hash.Sha1, "CB69ED7FFDA35AFECB0FB134A0E6BAA22E6F4B44"),
    #(
      hash.Sha256,
      "315C75AEFF2E8136180E99997A06CC9691A4BA84418F3BF2156B5D87771DB623",
    ),
    #(
      hash.Sha384,
      "B8F8B13B500CD430B77ACA328226F5F4A7CD8E7CA2AA732DC81EFAA639BC3224D2693739CBD58E440A6AF45CCBE1BCBF",
    ),
    #(
      hash.Sha512,
      "292F79E162FB60EBCA7652A9F46D107DAFD3057884577D0AA3F6B7C61135AD1E4274A044D6D018AF63636CF968B7CF0B5E4F803E81C717E7CB3DBAB9AF3B51CD",
    ),
    #(
      hash.Sha512x224,
      "B6B4C9B0BCE726416D1B41747ACBF9ED886CC93AEEBFA82A847A8113",
    ),
    #(
      hash.Sha512x256,
      "16CCF3457238D495235D582DA8EE594E841EDC3D25F076B37E566AFA87DBB58A",
    ),
  ]
  |> list.each(fn(pair) {
    let #(algorithm, expected) = pair
    let assert Ok(output) = crypto.hmac(algorithm, key, data)
    assert bit_array.base16_encode(output) == expected
      as hash.algorithm_name(algorithm)
  })
}

// Property: HMAC in chunks produces same result as HMAC all at once
pub fn hmac_chunking_invariant_property_test() {
  let gen =
    qcheck.tuple3(
      qcheck.from_generators(qcheck.return(hash.Sha256), [
        qcheck.return(hash.Sha512),
        qcheck.return(hash.Sha1),
      ]),
      qcheck.non_empty_byte_aligned_bit_array(),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(algorithm, key, data) = input
    let data_size = bit_array.byte_size(data)
    let assert Ok(expected) = crypto.hmac(algorithm, key, data)

    list.each([0, data_size / 2, data_size], fn(split_point) {
      let split_point = case split_point > data_size {
        True -> data_size
        False -> split_point
      }
      let assert Ok(first) = bit_array.slice(data, 0, split_point)
      let assert Ok(second) =
        bit_array.slice(data, split_point, data_size - split_point)

      let assert Ok(hmac_state) = hmac.new(algorithm, key)
      let result =
        hmac_state
        |> hmac.update(first)
        |> hmac.update(second)
        |> hmac.final()

      assert result == expected
    })
  })
}

// Property: verify(hmac(key, data), key, data) == True
pub fn hmac_verify_roundtrip_property_test() {
  let gen =
    qcheck.tuple3(
      qcheck.from_generators(qcheck.return(hash.Sha256), [
        qcheck.return(hash.Sha512),
        qcheck.return(hash.Sha1),
      ]),
      qcheck.non_empty_byte_aligned_bit_array(),
      qcheck.byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(algorithm, key, data) = input
    let assert Ok(mac) = crypto.hmac(algorithm, key, data)
    let assert Ok(valid) = hmac.verify(algorithm, key, data, mac)
    assert valid
  })
}

// Property: wrong key fails verification
pub fn hmac_wrong_key_fails_property_test() {
  let gen =
    qcheck.tuple3(
      qcheck.non_empty_byte_aligned_bit_array(),
      qcheck.non_empty_byte_aligned_bit_array(),
      qcheck.non_empty_byte_aligned_bit_array(),
    )

  qcheck.run(qcheck.default_config(), gen, fn(input) {
    let #(key1, key2, data) = input
    // HMAC pads keys shorter than the block size with zeros, so keys that
    // differ only by trailing zeros are HMAC-equivalent. We compare the
    // canonical form (trailing zeros stripped) to detect this.
    case utils.strip_trailing_zeros(key1) == utils.strip_trailing_zeros(key2) {
      True -> Nil
      False -> {
        let assert Ok(mac) = crypto.hmac(hash.Sha256, key1, data)
        let assert Ok(valid) = hmac.verify(hash.Sha256, key2, data, mac)
        assert !valid
      }
    }
  })
}

// Edge case: empty data produces valid HMAC
pub fn empty_data_test() {
  let key = <<"key":utf8>>
  let data = <<>>

  let assert Ok(result) = crypto.hmac(hash.Sha256, key, data)

  assert bit_array.base16_encode(result)
    == "5D5D139563C95B5967B9BD9A8C9B233A9DEDB45072794CD232DC1B74832607D0"
}

pub fn unsupported_algorithm_new_test() {
  let key = <<"key":utf8>>
  let result = hmac.new(hash.Sha3x256, key)
  assert result == Error(Nil)
}

pub fn unsupported_algorithm_hmac_test() {
  let key = <<"key":utf8>>
  let data = <<"data":utf8>>
  let result = crypto.hmac(hash.Sha3x256, key, data)
  assert result == Error(Nil)
}

pub fn unsupported_algorithm_verify_test() {
  let key = <<"key":utf8>>
  let data = <<"data":utf8>>
  let mac = <<"mac":utf8>>
  let result = hmac.verify(hash.Sha3x256, key, data, mac)
  assert result == Error(Nil)
}

// HMAC keys shorter than the block size are zero-padded, so keys differing
// only by trailing zeros produce identical MACs. This is expected behavior.
pub fn keys_differing_by_trailing_zeros_are_equivalent_test() {
  let key1 = <<65>>
  let key2 = <<65, 0>>
  let key3 = <<65, 0, 0, 0>>
  let data = <<0>>

  let assert Ok(mac1) = crypto.hmac(hash.Sha256, key1, data)
  let assert Ok(mac2) = crypto.hmac(hash.Sha256, key2, data)
  let assert Ok(mac3) = crypto.hmac(hash.Sha256, key3, data)

  // All three keys are HMAC-equivalent due to zero-padding
  assert mac1 == mac2
  assert mac2 == mac3
}

// Keys differing by non-zero bytes produce different MACs
pub fn keys_differing_by_nonzero_bytes_produce_different_macs_test() {
  let key1 = <<65>>
  let key2 = <<65, 1>>
  let data = <<0>>

  let assert Ok(mac1) = crypto.hmac(hash.Sha256, key1, data)
  let assert Ok(mac2) = crypto.hmac(hash.Sha256, key2, data)

  assert mac1 != mac2
}
