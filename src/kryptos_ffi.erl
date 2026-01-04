-module(kryptos_ffi).

-export([random_bytes/1, constant_time_equal/2, hash_new/1, hmac_new/2]).

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
