import gleam/bit_array
import gleam/dict
import kryptos/crypto
import kryptos/hash
import kryptos/hmac

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

  dict.from_list([
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
  ])
  |> dict.each(fn(algorithm, expected) {
    let assert Ok(output) = crypto.hmac(algorithm, key, data)
    assert bit_array.base16_encode(output) == expected
      as hash.algorithm_name(algorithm)
  })
}

pub fn incremental_hmac_test() {
  let key = <<"secret":utf8>>
  let data = <<"hello world":utf8>>
  let assert Ok(expected) = crypto.hmac(hash.Sha256, key, data)

  let assert Ok(hmac_state) = hmac.new(hash.Sha256, key)
  let result =
    hmac_state
    |> hmac.update(<<"hello ":utf8>>)
    |> hmac.update(<<"world":utf8>>)
    |> hmac.final()

  assert result == expected
}

pub fn incremental_single_byte_chunks_test() {
  let key = <<"key":utf8>>
  let data = <<"abc":utf8>>
  let assert Ok(expected) = crypto.hmac(hash.Sha256, key, data)

  let assert Ok(hmac_state) = hmac.new(hash.Sha256, key)
  let result =
    hmac_state
    |> hmac.update(<<"a":utf8>>)
    |> hmac.update(<<"b":utf8>>)
    |> hmac.update(<<"c":utf8>>)
    |> hmac.final()

  assert result == expected
}

pub fn empty_data_test() {
  let key = <<"key":utf8>>
  let data = <<>>

  let assert Ok(result) = crypto.hmac(hash.Sha256, key, data)

  assert bit_array.base16_encode(result)
    == "5D5D139563C95B5967B9BD9A8C9B233A9DEDB45072794CD232DC1B74832607D0"
}

pub fn incremental_empty_updates_test() {
  let key = <<"secret":utf8>>
  let data = <<"test":utf8>>
  let assert Ok(expected) = crypto.hmac(hash.Sha256, key, data)

  let assert Ok(hmac_state) = hmac.new(hash.Sha256, key)
  let result =
    hmac_state
    |> hmac.update(<<>>)
    |> hmac.update(data)
    |> hmac.update(<<>>)
    |> hmac.final()

  assert result == expected
}

pub fn incremental_no_updates_test() {
  let key = <<"key":utf8>>
  let assert Ok(expected) = crypto.hmac(hash.Sha256, key, <<>>)
  let assert Ok(hmac_state) = hmac.new(hash.Sha256, key)
  let result = hmac.final(hmac_state)

  assert result == expected
}

pub fn verify_valid_mac_test() {
  let key = <<"secret":utf8>>
  let data = <<"message":utf8>>
  let assert Ok(mac) = crypto.hmac(hash.Sha256, key, data)
  let assert Ok(valid) = hmac.verify(hash.Sha256, key, data, mac)
  assert valid
}

pub fn verify_invalid_mac_test() {
  let key = <<"secret":utf8>>
  let data = <<"message":utf8>>
  let wrong_mac = <<"wrong":utf8>>
  let assert Ok(valid) = hmac.verify(hash.Sha256, key, data, wrong_mac)
  assert !valid
}

pub fn verify_wrong_key_test() {
  let key = <<"secret":utf8>>
  let wrong_key = <<"wrong key":utf8>>
  let data = <<"message":utf8>>
  let assert Ok(mac) = crypto.hmac(hash.Sha256, key, data)
  let assert Ok(valid) = hmac.verify(hash.Sha256, wrong_key, data, mac)
  assert !valid
}

pub fn verify_tampered_data_test() {
  let key = <<"secret":utf8>>
  let data = <<"message":utf8>>
  let tampered_data = <<"tampered":utf8>>
  let assert Ok(mac) = crypto.hmac(hash.Sha256, key, data)
  let assert Ok(valid) = hmac.verify(hash.Sha256, key, tampered_data, mac)
  assert !valid
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
