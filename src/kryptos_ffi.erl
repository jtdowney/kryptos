-module(kryptos_ffi).

-include_lib("public_key/include/public_key.hrl").

-export([
    random_bytes/1,
    constant_time_equal/2,
    hash_new/1,
    hmac_new/2,
    pbkdf2_derive/5,
    aead_seal/4,
    aead_open/5,
    ec_generate_key_pair/1,
    ec_private_key_from_bytes/2,
    ec_public_key_from_x509/1,
    ecdsa_sign/3,
    ecdsa_verify/4,
    ecdh_compute_shared_secret/2,
    xdh_generate_key_pair/1,
    xdh_compute_shared_secret/2,
    xdh_private_key_from_bytes/2,
    xdh_public_key_from_bytes/2,
    rsa_generate_key_pair/1,
    rsa_sign/4,
    rsa_verify/5,
    rsa_encrypt/3,
    rsa_decrypt/3,
    rsa_private_key_from_pkcs8/1,
    rsa_public_key_from_x509/1
]).

random_bytes(Length) when Length < 0 ->
    crypto:strong_rand_bytes(0);
random_bytes(Length) ->
    crypto:strong_rand_bytes(Length).

constant_time_equal(A, B) when byte_size(A) =:= byte_size(B) ->
    crypto:hash_equals(A, B);
constant_time_equal(_, _) ->
    false.

hash_algorithm_name(sha1) ->
    sha;
hash_algorithm_name(sha224) ->
    sha224;
hash_algorithm_name(sha256) ->
    sha256;
hash_algorithm_name(sha384) ->
    sha384;
hash_algorithm_name(sha512) ->
    sha512;
hash_algorithm_name(sha512x224) ->
    sha512_224;
hash_algorithm_name(sha512x256) ->
    sha512_256;
hash_algorithm_name(sha3x224) ->
    sha3_224;
hash_algorithm_name(sha3x256) ->
    sha3_256;
hash_algorithm_name(sha3x384) ->
    sha3_384;
hash_algorithm_name(sha3x512) ->
    sha3_512;
hash_algorithm_name(Name) ->
    Name.

hash_new(Algorithm) ->
    Name = hash_algorithm_name(Algorithm),
    crypto:hash_init(Name).

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
    aes_256_gcm;
aead_cipher_name({cha_cha20_poly1305, _}) ->
    chacha20_poly1305.

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

ec_curve_name(p256) ->
    secp256r1;
ec_curve_name(p384) ->
    secp384r1;
ec_curve_name(p521) ->
    secp521r1;
ec_curve_name(secp256k1) ->
    secp256k1.

ec_generate_key_pair(Curve) ->
    CurveName = ec_curve_name(Curve),
    OID = ec_curve_oid(CurveName),
    {PubPoint, PrivScalar} = crypto:generate_key(ecdh, CurveName),
    PrivKey =
        {'ECPrivateKey', ecPrivkeyVer1, PrivScalar, {namedCurve, OID}, PubPoint, asn1_NOVALUE},
    PubKey = {{'ECPoint', PubPoint}, {namedCurve, CurveName}},
    {PrivKey, PubKey}.

ec_private_key_from_bytes(Curve, PrivateScalar) ->
    try
        CurveName = ec_curve_name(Curve),
        OID = ec_curve_oid(CurveName),
        % Generate a temporary key to get the public point
        % We need to compute the public key from the private scalar
        {{'ECPoint', _}, {namedCurve, CurveName}} =
            TempPub = ec_compute_public_key(CurveName, PrivateScalar),
        Point = element(2, element(1, TempPub)),
        PrivKey =
            {'ECPrivateKey', ecPrivkeyVer1, PrivateScalar, {namedCurve, OID}, Point, asn1_NOVALUE},
        PubKey = {{'ECPoint', Point}, {namedCurve, CurveName}},
        {ok, {PrivKey, PubKey}}
    catch
        _:_ ->
            {error, nil}
    end.

ec_compute_public_key(CurveName, PrivateScalar) ->
    % Use crypto to compute the public key point from private scalar
    {PublicPoint, _} = crypto:generate_key(ecdh, CurveName, PrivateScalar),
    {{'ECPoint', PublicPoint}, {namedCurve, CurveName}}.

ec_public_key_from_x509(DerBytes) ->
    try
        % Decode the SubjectPublicKeyInfo structure
        {'SubjectPublicKeyInfo', AlgId, PublicKeyBits} =
            public_key:der_decode('SubjectPublicKeyInfo', DerBytes),
        {'AlgorithmIdentifier', _, {namedCurve, OID}} = AlgId,
        CurveName = ec_oid_to_name(OID),
        % PublicKeyBits is the raw EC point
        {ok, {{'ECPoint', PublicKeyBits}, {namedCurve, CurveName}}}
    catch
        _:_ ->
            {error, nil}
    end.

ec_oid_to_name({1, 2, 840, 10045, 3, 1, 7}) ->
    secp256r1;
ec_oid_to_name({1, 3, 132, 0, 34}) ->
    secp384r1;
ec_oid_to_name({1, 3, 132, 0, 35}) ->
    secp521r1;
ec_oid_to_name({1, 3, 132, 0, 10}) ->
    secp256k1.

ecdsa_sign(PrivateKey, Message, HashAlgorithm) ->
    DigestType = hash_algorithm_name(HashAlgorithm),
    public_key:sign(Message, DigestType, PrivateKey).

ecdsa_verify(PubKey, Message, Signature, HashAlgorithm) ->
    try
        DigestType = hash_algorithm_name(HashAlgorithm),
        public_key:verify(Message, DigestType, Signature, PubKey)
    catch
        _:_ ->
            false
    end.

ec_curve_oid(secp256r1) ->
    {1, 2, 840, 10045, 3, 1, 7};
ec_curve_oid(secp384r1) ->
    {1, 3, 132, 0, 34};
ec_curve_oid(secp521r1) ->
    {1, 3, 132, 0, 35};
ec_curve_oid(secp256k1) ->
    {1, 3, 132, 0, 10}.

ecdh_compute_shared_secret(PrivateKey, PeerPublicKey) ->
    try
        {{'ECPoint', PeerPoint}, {namedCurve, PeerCurveName}} = PeerPublicKey,
        {namedCurve, PrivateOID} = element(4, PrivateKey),
        ExpectedOID = ec_curve_oid(PeerCurveName),
        case PrivateOID =:= ExpectedOID of
            false ->
                {error, nil};
            true ->
                PrivateScalar = element(3, PrivateKey),
                SharedSecret = crypto:compute_key(ecdh, PeerPoint, PrivateScalar, PeerCurveName),
                {ok, SharedSecret}
        end
    catch
        _:_ ->
            {error, nil}
    end.

xdh_generate_key_pair(Curve) ->
    {PubKey, PrivKey} = crypto:generate_key(ecdh, Curve),
    {{PrivKey, Curve}, {PubKey, Curve}}.

xdh_compute_shared_secret({PrivKey, PrivCurve}, {PeerPubKey, PeerCurve}) ->
    try
        case PrivCurve =:= PeerCurve of
            false ->
                {error, nil};
            true ->
                SharedSecret = crypto:compute_key(ecdh, PeerPubKey, PrivKey, PrivCurve),
                {ok, SharedSecret}
        end
    catch
        _:_ ->
            {error, nil}
    end.

xdh_private_key_from_bytes(Curve, PrivateBytes) ->
    try
        ExpectedSize = kryptos@xdh:key_size(Curve),
        case byte_size(PrivateBytes) of
            ExpectedSize ->
                {PubKey, PrivKey} = crypto:generate_key(ecdh, Curve, PrivateBytes),
                {ok, {{PrivKey, Curve}, {PubKey, Curve}}};
            _ ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

xdh_public_key_from_bytes(Curve, PublicBytes) ->
    ExpectedSize = kryptos@xdh:key_size(Curve),
    case byte_size(PublicBytes) of
        ExpectedSize ->
            {ok, {PublicBytes, Curve}};
        _ ->
            {error, nil}
    end.

rsa_generate_key_pair(Bits) ->
    {PubKey, PrivKey} = crypto:generate_key(rsa, {Bits, 65537}),
    {rsa_build_private_key(PrivKey), rsa_build_public_key(PubKey)}.

bin_to_int(Bin) ->
    binary:decode_unsigned(Bin).

rsa_build_private_key([E, N, D, P, Q, Dp, Dq, Qi]) ->
    #'RSAPrivateKey'{
        version = 'two-prime',
        modulus = bin_to_int(N),
        publicExponent = bin_to_int(E),
        privateExponent = bin_to_int(D),
        prime1 = bin_to_int(P),
        prime2 = bin_to_int(Q),
        exponent1 = bin_to_int(Dp),
        exponent2 = bin_to_int(Dq),
        coefficient = bin_to_int(Qi)
    };
rsa_build_private_key([E, N, D]) ->
    #'RSAPrivateKey'{
        version = 'two-prime',
        modulus = bin_to_int(N),
        publicExponent = bin_to_int(E),
        privateExponent = bin_to_int(D)
    }.

rsa_build_public_key([E, N | _]) ->
    #'RSAPublicKey'{modulus = bin_to_int(N), publicExponent = bin_to_int(E)}.

rsa_sign_padding_opts(pkcs1v15, _Hash) ->
    [];
rsa_sign_padding_opts({pss, SaltLength}, Hash) ->
    DigestType = hash_algorithm_name(Hash),
    Salt = rsa_pss_salt_length(SaltLength),
    [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, Salt}, {rsa_mgf1_md, DigestType}].

rsa_pss_salt_length(salt_length_hash_len) ->
    -1;
rsa_pss_salt_length(salt_length_max) ->
    -2;
rsa_pss_salt_length({salt_length_explicit, Length}) ->
    Length.

rsa_sign(PrivateKey, Message, Hash, Padding) ->
    DigestType = hash_algorithm_name(Hash),
    Opts = rsa_sign_padding_opts(Padding, Hash),
    public_key:sign(Message, DigestType, PrivateKey, Opts).

rsa_verify(PublicKey, Message, Signature, Hash, Padding) ->
    try
        DigestType = hash_algorithm_name(Hash),
        Opts = rsa_sign_padding_opts(Padding, Hash),
        public_key:verify(Message, DigestType, Signature, PublicKey, Opts)
    catch
        _:_ ->
            false
    end.

rsa_encrypt_padding_opts(encrypt_pkcs1v15) ->
    [{rsa_padding, rsa_pkcs1_padding}];
rsa_encrypt_padding_opts({oaep, Hash, Label}) ->
    DigestType = hash_algorithm_name(Hash),
    Opts = [
        {rsa_padding, rsa_pkcs1_oaep_padding}, {rsa_oaep_md, DigestType}, {rsa_mgf1_md, DigestType}
    ],
    case Label of
        <<>> -> Opts;
        _ -> [{rsa_oaep_label, Label} | Opts]
    end.

rsa_encrypt(PublicKey, Plaintext, Padding) ->
    try
        Opts = rsa_encrypt_padding_opts(Padding),
        Ciphertext = public_key:encrypt_public(Plaintext, PublicKey, Opts),
        {ok, Ciphertext}
    catch
        _:_ ->
            {error, nil}
    end.

rsa_decrypt(PrivateKey, Ciphertext, Padding) ->
    try
        Opts = rsa_encrypt_padding_opts(Padding),
        Plaintext = public_key:decrypt_private(Ciphertext, PrivateKey, Opts),
        {ok, Plaintext}
    catch
        _:_ ->
            {error, nil}
    end.

rsa_private_key_from_pkcs8(DerBytes) ->
    try
        RSAPrivKey = public_key:der_decode('PrivateKeyInfo', DerBytes),
        PubKey = #'RSAPublicKey'{
            modulus = RSAPrivKey#'RSAPrivateKey'.modulus,
            publicExponent = RSAPrivKey#'RSAPrivateKey'.publicExponent
        },
        {ok, {RSAPrivKey, PubKey}}
    catch
        _:_ ->
            {error, nil}
    end.

rsa_public_key_from_x509(DerBytes) ->
    try
        PubKey = public_key:der_decode('SubjectPublicKeyInfo', DerBytes),
        {'SubjectPublicKeyInfo', {'AlgorithmIdentifier', ?'rsaEncryption', _}, PublicKeyDer} =
            PubKey,
        RSAPubKey = public_key:der_decode('RSAPublicKey', PublicKeyDer),
        {ok, RSAPubKey}
    catch
        _:_ ->
            {error, nil}
    end.
