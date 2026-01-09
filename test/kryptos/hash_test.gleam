import gleam/bit_array
import gleam/dict
import gleam/result
import kryptos/crypto
import kryptos/hash

pub fn digest_table_test() {
  let input = <<"too many secrets":utf8>>

  dict.from_list([
    #(
      hash.Blake2b,
      "6D0CD2A033C2C265A0343B1288892CE6DBABF2A4D183AD1AB421B0B8C399FDE8A91FF1CFE1F5DF36545D371869333F2BAD5508584C130CDFF3F16B6307141051",
    ),
    #(
      hash.Blake2s,
      "312CBF51D52F960108095C6C07242FB9E25FAC68D6A1D6073C7D1A64DD634B11",
    ),
    #(hash.Md5, "CF4C8BF5BE504142FD3D75934CC3446C"),
    #(hash.Sha1, "0D18C1DB0F9CDB0F74DEA4A89BD36295D276A9F9"),
    #(
      hash.Sha256,
      "624FA374A759DEFF04DA9E9D99B7E7F9937D9410401C421C38CA78973B98293A",
    ),
    #(
      hash.Sha384,
      "4CA0E6AB068CF4FB5B539B134C1E5816CE20AA77F11B6F5F9BA82DE35B2D4B89ED418B0E4BE82A65EB1FDCBE52DDA327",
    ),
    #(
      hash.Sha512,
      "CC70AEDAD31FDCE63B7C39490BA48ED77110C98AF0DDF67DED4443D300C2C6308D6044985E581B67B8ECB9B73CD0902CF89796FEC37BF3082D238BAFA50A1207",
    ),
    #(
      hash.Sha512x224,
      "F187EA5D2E9E6316D7D202CD4EC2B43A6CEE012CC3D802030D3C4D1C",
    ),
    #(
      hash.Sha512x256,
      "009E5FE2445692EC15292E4D229A029D5C468C36C01784AB40C0B86F23A03948",
    ),
    #(hash.Sha3x224, "AED9B19E5478FAFDD3A2107ABD9E444847ED39347154410BFB47F4C8"),
    #(
      hash.Sha3x256,
      "E97B3EAE077B90761D9A9E746BAD54E9D1200916A807AA2005037AD7D3B507FF",
    ),
    #(
      hash.Sha3x384,
      "3DEA675D413E53444D7BC908EC74C11F09BB217D86DA5EADB012225406AE2EC5A80FC48DF852E488BAB682AC5BBC89BE",
    ),
    #(
      hash.Sha3x512,
      "4C33F4D13255A63B30E242B785CDDEDD11E581E99C78C7C7DA18C5118AFEC348E37BBF9BC928A2C82C8F726719633F0FB2CD428868323BD319830A9B800E18D1",
    ),
  ])
  |> dict.each(fn(algorithm, expected) {
    let assert Ok(output) =
      crypto.hash(algorithm, input) |> result.map(bit_array.base16_encode)
    assert output == expected as hash.algorithm_name(algorithm)
  })
}

pub fn incremental_hash_test() {
  let input = <<"too many secrets":utf8>>
  let assert Ok(expected) = crypto.hash(hash.Sha256, input)

  let assert Ok(hasher) = hash.new(hash.Sha256)
  let result =
    hasher
    |> hash.update(bit_array.from_string("too many "))
    |> hash.update(bit_array.from_string("secrets"))
    |> hash.final()

  assert result == expected
}

pub fn empty_input_test() {
  let empty = <<>>
  let assert Ok(expected) = crypto.hash(hash.Sha256, empty)

  let assert Ok(hasher) = hash.new(hash.Sha256)
  let result =
    hasher
    |> hash.final()

  assert result == expected
}

pub fn single_byte_chunks_test() {
  let input = <<"abc":utf8>>
  let assert Ok(expected) = crypto.hash(hash.Sha256, input)

  let assert Ok(hasher) = hash.new(hash.Sha256)
  let result =
    hasher
    |> hash.update(<<"a":utf8>>)
    |> hash.update(<<"b":utf8>>)
    |> hash.update(<<"c":utf8>>)
    |> hash.final()

  assert result == expected
}
