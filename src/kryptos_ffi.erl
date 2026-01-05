-module(kryptos_ffi).

-export([
    random_bytes/1,
    constant_time_equal/2,
    hash_new/1,
    hmac_new/2,
    pbkdf2_derive/5,
    aead_seal/4,
    aead_open/5
]).

random_bytes(Length) when Length < 0 ->
    crypto:strong_rand_bytes(0);
random_bytes(Length) ->
    crypto:strong_rand_bytes(Length).

constant_time_equal(A, B) when byte_size(A) =:= byte_size(B) ->
    crypto:hash_equals(A, B);
constant_time_equal(_, _) ->
    false.

hash_new(sha1) ->
    hash_new(sha);
hash_new(sha512x224) ->
    hash_new(sha512_224);
hash_new(sha512x256) ->
    hash_new(sha512_256);
hash_new(sha3x224) ->
    hash_new(sha3_224);
hash_new(sha3x256) ->
    hash_new(sha3_256);
hash_new(sha3x384) ->
    hash_new(sha3_384);
hash_new(sha3x512) ->
    hash_new(sha3_512);
hash_new(Algorithm) ->
    crypto:hash_init(Algorithm).

hmac_new(sha1, Key) ->
    hmac_new(sha, Key);
hmac_new(sha512x224, Key) ->
    hmac_new(sha512_224, Key);
hmac_new(sha512x256, Key) ->
    hmac_new(sha512_256, Key);
hmac_new(Algorithm, Key) ->
    crypto:mac_init(hmac, Algorithm, Key).

pbkdf2_derive(sha1, Password, Salt, Iterations, Length) ->
    pbkdf2_derive(sha, Password, Salt, Iterations, Length);
pbkdf2_derive(sha512x224, Password, Salt, Iterations, Length) ->
    pbkdf2_derive(sha512_224, Password, Salt, Iterations, Length);
pbkdf2_derive(sha512x256, Password, Salt, Iterations, Length) ->
    pbkdf2_derive(sha512_256, Password, Salt, Iterations, Length);
pbkdf2_derive(Algorithm, Password, Salt, Iterations, Length) ->
    try
        Key = crypto:pbkdf2_hmac(Algorithm, Password, Salt, Iterations, Length),
        {ok, Key}
    catch
        _:_ ->
            {error, nil}
    end.

aead_cipher_name({gcm, {aes, aes128, _}, _}) ->
    aes_128_gcm;
aead_cipher_name({gcm, {aes, aes192, _}, _}) ->
    aes_192_gcm;
aead_cipher_name({gcm, {aes, aes256, _}, _}) ->
    aes_256_gcm.

aead_seal(Mode, Nonce, Plaintext, AdditionalData) ->
    Cipher = aead_cipher_name(Mode),
    TagSize = kryptos@aead:tag_size(Mode),
    Key = kryptos@aead:aead_cipher_key(Mode),
    try
        {Ciphertext, Tag} =
            crypto:crypto_one_time_aead(
                Cipher,
                Key,
                Nonce,
                Plaintext,
                AdditionalData,
                TagSize,
                true
            ),
        {ok, {Ciphertext, Tag}}
    catch
        error:_ ->
            {error, nil}
    end.

aead_open(Mode, Nonce, Tag, Ciphertext, AdditionalData) ->
    Cipher = aead_cipher_name(Mode),
    Key = kryptos@aead:aead_cipher_key(Mode),
    case
        crypto:crypto_one_time_aead(
            Cipher,
            Key,
            Nonce,
            Ciphertext,
            AdditionalData,
            Tag,
            false
        )
    of
        error ->
            {error, nil};
        Plaintext ->
            {ok, Plaintext}
    end.
