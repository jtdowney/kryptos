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
    cipher_encrypt/2,
    cipher_decrypt/2,
    ec_generate_key_pair/1,
    ec_private_key_from_bytes/2,
    ec_public_key_from_x509/1,
    ec_import_private_key_pem/1,
    ec_import_private_key_der/1,
    ec_import_public_key_pem/1,
    ec_import_public_key_der/1,
    ec_export_private_key_pem/1,
    ec_export_private_key_der/1,
    ec_export_public_key_pem/1,
    ec_export_public_key_der/1,
    ec_public_key_from_private/1,
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
    rsa_public_key_from_x509/1,
    rsa_import_private_key_pem/2,
    rsa_import_private_key_der/2,
    rsa_import_public_key_pem/2,
    rsa_import_public_key_der/2,
    rsa_export_private_key_pem/2,
    rsa_export_private_key_der/2,
    rsa_export_public_key_pem/2,
    rsa_export_public_key_der/2,
    rsa_public_key_from_private/1,
    eddsa_generate_key_pair/1,
    eddsa_sign/2,
    eddsa_verify/3,
    eddsa_private_key_from_bytes/2,
    eddsa_public_key_from_bytes/2,
    eddsa_import_private_key_pem/1,
    eddsa_import_private_key_der/1,
    eddsa_import_public_key_pem/1,
    eddsa_import_public_key_der/1,
    eddsa_export_private_key_pem/1,
    eddsa_export_private_key_der/1,
    eddsa_export_public_key_pem/1,
    eddsa_export_public_key_der/1,
    eddsa_public_key_from_private/1,
    xdh_import_private_key_pem/1,
    xdh_import_private_key_der/1,
    xdh_import_public_key_pem/1,
    xdh_import_public_key_der/1,
    xdh_export_private_key_pem/1,
    xdh_export_private_key_der/1,
    xdh_export_public_key_pem/1,
    xdh_export_public_key_der/1,
    xdh_public_key_from_private/1
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
aead_cipher_name({ccm, {aes, aes128, _}, _, _}) ->
    aes_128_ccm;
aead_cipher_name({ccm, {aes, aes192, _}, _, _}) ->
    aes_192_ccm;
aead_cipher_name({ccm, {aes, aes256, _}, _, _}) ->
    aes_256_ccm;
aead_cipher_name({cha_cha20_poly1305, _}) ->
    chacha20_poly1305.

aead_cipher_key({gcm, {aes, _, Key}, _}) ->
    Key;
aead_cipher_key({ccm, {aes, _, Key}, _, _}) ->
    Key;
aead_cipher_key({cha_cha20_poly1305, Key}) ->
    Key.

aead_seal(Mode, Nonce, Plaintext, AdditionalData) ->
    Cipher = aead_cipher_name(Mode),
    TagSize = kryptos@aead:tag_size(Mode),
    Key = aead_cipher_key(Mode),
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
    Key = aead_cipher_key(Mode),
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

%% Block cipher modes (ECB, CBC, CTR)
cipher_name({ecb, {aes, aes128, _}}) -> aes_128_ecb;
cipher_name({ecb, {aes, aes192, _}}) -> aes_192_ecb;
cipher_name({ecb, {aes, aes256, _}}) -> aes_256_ecb;
cipher_name({cbc, {aes, aes128, _}, _}) -> aes_128_cbc;
cipher_name({cbc, {aes, aes192, _}, _}) -> aes_192_cbc;
cipher_name({cbc, {aes, aes256, _}, _}) -> aes_256_cbc;
cipher_name({ctr, {aes, aes128, _}, _}) -> aes_128_ctr;
cipher_name({ctr, {aes, aes192, _}, _}) -> aes_192_ctr;
cipher_name({ctr, {aes, aes256, _}, _}) -> aes_256_ctr.

cipher_padding({ecb, _}) -> pkcs_padding;
cipher_padding({cbc, _, _}) -> pkcs_padding;
cipher_padding({ctr, _, _}) -> none.

cipher_encrypt(Mode, Plaintext) ->
    Cipher = cipher_name(Mode),
    Key = kryptos@block:cipher_key(Mode),
    Iv = kryptos@block:cipher_iv(Mode),
    Padding = cipher_padding(Mode),
    try
        Ciphertext = crypto:crypto_one_time(Cipher, Key, Iv, Plaintext, [
            {encrypt, true}, {padding, Padding}
        ]),
        {ok, Ciphertext}
    catch
        error:_ ->
            {error, nil}
    end.

cipher_decrypt(Mode, Ciphertext) ->
    Cipher = cipher_name(Mode),
    Key = kryptos@block:cipher_key(Mode),
    Iv = kryptos@block:cipher_iv(Mode),
    Padding = cipher_padding(Mode),
    try
        Plaintext = crypto:crypto_one_time(Cipher, Key, Iv, Ciphertext, [
            {encrypt, false}, {padding, Padding}
        ]),
        {ok, Plaintext}
    catch
        error:_ ->
            {error, nil}
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

%% EC module-specific import/export functions

ec_import_private_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'PrivateKeyInfo', DerBytes, not_encrypted}] ->
                ec_import_private_key_from_der(DerBytes);
            _ ->
                {error, invalid_key_data}
        end
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

ec_import_private_key_der(DerBytes) ->
    try
        ec_import_private_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

ec_import_private_key_from_der(DerBytes) ->
    ECPrivKey = public_key:der_decode('PrivateKeyInfo', DerBytes),
    case ECPrivKey of
        {'ECPrivateKey', _, PrivateScalar, {namedCurve, CurveOID}, PublicPoint, _} ->
            CurveName = ec_oid_to_name(CurveOID),
            PrivKey =
                {'ECPrivateKey', ecPrivkeyVer1, PrivateScalar, {namedCurve, CurveOID}, PublicPoint,
                    asn1_NOVALUE},
            PubKey = {{'ECPoint', PublicPoint}, {namedCurve, CurveName}},
            {ok, {PrivKey, PubKey}};
        _ ->
            {error, invalid_key_data}
    end.

ec_import_public_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'SubjectPublicKeyInfo', DerBytes, not_encrypted}] ->
                ec_import_public_key_from_der(DerBytes);
            _ ->
                {error, invalid_key_data}
        end
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

ec_import_public_key_der(DerBytes) ->
    try
        ec_import_public_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

ec_import_public_key_from_der(DerBytes) ->
    {'SubjectPublicKeyInfo', AlgId, PublicKeyBits} =
        public_key:der_decode('SubjectPublicKeyInfo', DerBytes),
    case AlgId of
        {'AlgorithmIdentifier', ?'id-ecPublicKey', {namedCurve, OID}} ->
            CurveName = ec_oid_to_name(OID),
            {ok, {{'ECPoint', PublicKeyBits}, {namedCurve, CurveName}}};
        _ ->
            {error, invalid_key_data}
    end.

ec_export_private_key_pem(Key) ->
    try
        Der = ec_private_key_to_der(Key),
        PemEntry = {'PrivateKeyInfo', Der, not_encrypted},
        {ok, public_key:pem_encode([PemEntry])}
    catch
        _:_ ->
            {error, nil}
    end.

ec_export_private_key_der(Key) ->
    try
        Der = ec_private_key_to_der(Key),
        {ok, Der}
    catch
        _:_ ->
            {error, nil}
    end.

ec_private_key_to_der(Key) ->
    {'PrivateKeyInfo', Der, not_encrypted} = public_key:pem_entry_encode('PrivateKeyInfo', Key),
    Der.

ec_export_public_key_pem(Key) ->
    try
        Der = ec_public_key_to_der(Key),
        PemEntry = {'SubjectPublicKeyInfo', Der, not_encrypted},
        {ok, public_key:pem_encode([PemEntry])}
    catch
        _:_ ->
            {error, nil}
    end.

ec_export_public_key_der(Key) ->
    try
        Der = ec_public_key_to_der(Key),
        {ok, Der}
    catch
        _:_ ->
            {error, nil}
    end.

ec_public_key_to_der({{'ECPoint', Point}, {namedCurve, CurveName}}) ->
    CurveOID = ec_curve_oid(CurveName),
    Key = {{'ECPoint', Point}, {namedCurve, CurveOID}},
    {'SubjectPublicKeyInfo', Der, not_encrypted} = public_key:pem_entry_encode(
        'SubjectPublicKeyInfo', Key
    ),
    Der.

ec_public_key_from_private({'ECPrivateKey', _, _, _, PublicPoint, _} = _PrivKey) ->
    % Extract curve from private key
    {namedCurve, CurveOID} = element(4, _PrivKey),
    CurveName = ec_oid_to_name(CurveOID),
    {{'ECPoint', PublicPoint}, {namedCurve, CurveName}}.

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

%% RSA module-specific import/export functions

rsa_import_private_key_pem(PemData, Format) ->
    try
        {PemType, DerType} = rsa_private_format_types(Format),
        case public_key:pem_decode(PemData) of
            [{PemType, DerBytes, not_encrypted}] ->
                rsa_import_private_key_from_der(DerBytes, DerType);
            _ ->
                {error, invalid_key_data}
        end
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

rsa_import_private_key_der(DerBytes, Format) ->
    try
        {_, DerType} = rsa_private_format_types(Format),
        rsa_import_private_key_from_der(DerBytes, DerType)
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

rsa_private_format_types(pkcs8) -> {'PrivateKeyInfo', 'PrivateKeyInfo'};
rsa_private_format_types(pkcs1) -> {'RSAPrivateKey', 'RSAPrivateKey'}.

rsa_import_private_key_from_der(DerBytes, DerType) ->
    RSAPrivKey = public_key:der_decode(DerType, DerBytes),
    RSAPubKey = #'RSAPublicKey'{
        modulus = RSAPrivKey#'RSAPrivateKey'.modulus,
        publicExponent = RSAPrivKey#'RSAPrivateKey'.publicExponent
    },
    {ok, {RSAPrivKey, RSAPubKey}}.

rsa_import_public_key_pem(PemData, Format) ->
    try
        {PemType, _} = rsa_public_format_types(Format),
        case public_key:pem_decode(PemData) of
            [{PemType, DerBytes, not_encrypted}] ->
                rsa_import_public_key_from_der(DerBytes, Format);
            _ ->
                {error, invalid_key_data}
        end
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

rsa_import_public_key_der(DerBytes, Format) ->
    try
        rsa_import_public_key_from_der(DerBytes, Format)
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

rsa_public_format_types(spki) -> {'SubjectPublicKeyInfo', spki};
rsa_public_format_types(rsa_public_key) -> {'RSAPublicKey', rsa_public_key}.

rsa_import_public_key_from_der(DerBytes, spki) ->
    PubKey = public_key:der_decode('SubjectPublicKeyInfo', DerBytes),
    {'SubjectPublicKeyInfo', {'AlgorithmIdentifier', ?'rsaEncryption', _}, PublicKeyDer} = PubKey,
    RSAPubKey = public_key:der_decode('RSAPublicKey', PublicKeyDer),
    {ok, RSAPubKey};
rsa_import_public_key_from_der(DerBytes, rsa_public_key) ->
    RSAPubKey = public_key:der_decode('RSAPublicKey', DerBytes),
    {ok, RSAPubKey}.

rsa_export_private_key_pem(Key, Format) ->
    try
        Der = rsa_private_key_to_der(Key, Format),
        PemType = rsa_private_pem_type(Format),
        PemEntry = {PemType, Der, not_encrypted},
        {ok, public_key:pem_encode([PemEntry])}
    catch
        _:_ ->
            {error, nil}
    end.

rsa_export_private_key_der(Key, Format) ->
    try
        Der = rsa_private_key_to_der(Key, Format),
        {ok, Der}
    catch
        _:_ ->
            {error, nil}
    end.

rsa_private_key_to_der(Key, pkcs8) ->
    {'PrivateKeyInfo', Der, not_encrypted} = public_key:pem_entry_encode('PrivateKeyInfo', Key),
    Der;
rsa_private_key_to_der(Key, pkcs1) ->
    public_key:der_encode('RSAPrivateKey', Key).

rsa_private_pem_type(pkcs8) -> 'PrivateKeyInfo';
rsa_private_pem_type(pkcs1) -> 'RSAPrivateKey'.

rsa_export_public_key_pem(Key, Format) ->
    try
        Der = rsa_public_key_to_der(Key, Format),
        PemType = rsa_public_pem_type(Format),
        PemEntry = {PemType, Der, not_encrypted},
        {ok, public_key:pem_encode([PemEntry])}
    catch
        _:_ ->
            {error, nil}
    end.

rsa_export_public_key_der(Key, Format) ->
    try
        Der = rsa_public_key_to_der(Key, Format),
        {ok, Der}
    catch
        _:_ ->
            {error, nil}
    end.

rsa_public_key_to_der(Key, spki) ->
    {'SubjectPublicKeyInfo', Der, not_encrypted} = public_key:pem_entry_encode(
        'SubjectPublicKeyInfo', Key
    ),
    Der;
rsa_public_key_to_der(Key, rsa_public_key) ->
    public_key:der_encode('RSAPublicKey', Key).

rsa_public_pem_type(spki) -> 'SubjectPublicKeyInfo';
rsa_public_pem_type(rsa_public_key) -> 'RSAPublicKey'.

rsa_public_key_from_private(PrivKey) ->
    #'RSAPublicKey'{
        modulus = PrivKey#'RSAPrivateKey'.modulus,
        publicExponent = PrivKey#'RSAPrivateKey'.publicExponent
    }.

eddsa_generate_key_pair(Curve) ->
    {PubKey, PrivKey} = crypto:generate_key(eddsa, Curve),
    {{PrivKey, Curve}, {PubKey, Curve}}.

eddsa_sign({PrivKey, Curve}, Message) ->
    crypto:sign(eddsa, none, Message, [PrivKey, Curve]).

eddsa_verify({PubKey, Curve}, Message, Signature) ->
    try
        crypto:verify(eddsa, none, Message, Signature, [PubKey, Curve])
    catch
        _:_ ->
            false
    end.

eddsa_private_key_from_bytes(Curve, PrivateBytes) ->
    try
        ExpectedSize = kryptos@eddsa:key_size(Curve),
        case byte_size(PrivateBytes) of
            ExpectedSize ->
                {PubKey, PrivKey} = crypto:generate_key(eddsa, Curve, PrivateBytes),
                {ok, {{PrivKey, Curve}, {PubKey, Curve}}};
            _ ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_public_key_from_bytes(Curve, PublicBytes) ->
    ExpectedSize = kryptos@eddsa:key_size(Curve),
    case byte_size(PublicBytes) of
        ExpectedSize ->
            {ok, {PublicBytes, Curve}};
        _ ->
            {error, nil}
    end.

%% EdDSA Import/Export Functions

eddsa_import_private_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'PrivateKeyInfo', DerBytes, not_encrypted}] ->
                eddsa_import_private_key_from_der(DerBytes);
            _ ->
                {error, invalid_key_data}
        end
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

eddsa_import_private_key_der(DerBytes) ->
    try
        eddsa_import_private_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

eddsa_import_private_key_from_der(DerBytes) ->
    {AlgOID, _} = extract_pkcs8_algorithm(DerBytes),
    case AlgOID of
        {1, 3, 101, 112} ->
            eddsa_import_private_from_pkcs8(DerBytes, ed25519);
        {1, 3, 101, 113} ->
            eddsa_import_private_from_pkcs8(DerBytes, ed448);
        _ ->
            {error, unsupported_curve}
    end.

eddsa_import_private_from_pkcs8(DerBytes, Curve) ->
    PrivateKeyDer = extract_pkcs8_private_key(DerBytes),
    PrivateBytes = decode_octet_string(PrivateKeyDer),
    {PubKey, PrivKey} = crypto:generate_key(eddsa, Curve, PrivateBytes),
    {ok, {{PrivKey, Curve}, {PubKey, Curve}}}.

eddsa_import_public_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'SubjectPublicKeyInfo', DerBytes, not_encrypted}] ->
                eddsa_import_public_key_from_der(DerBytes);
            _ ->
                {error, invalid_key_data}
        end
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

eddsa_import_public_key_der(DerBytes) ->
    try
        eddsa_import_public_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

eddsa_import_public_key_from_der(DerBytes) ->
    {'SubjectPublicKeyInfo', AlgId, PublicKeyBits} =
        public_key:der_decode('SubjectPublicKeyInfo', DerBytes),
    {'AlgorithmIdentifier', AlgOID, _} = AlgId,
    case AlgOID of
        {1, 3, 101, 112} ->
            {ok, {PublicKeyBits, ed25519}};
        {1, 3, 101, 113} ->
            {ok, {PublicKeyBits, ed448}};
        _ ->
            {error, unsupported_curve}
    end.

eddsa_export_private_key_pem({KeyBytes, Curve}) ->
    try
        Der = eddsa_xdh_private_to_pkcs8(KeyBytes, Curve),
        {ok, public_key:pem_encode([{'PrivateKeyInfo', Der, not_encrypted}])}
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_export_private_key_der({KeyBytes, Curve}) ->
    try
        {ok, eddsa_xdh_private_to_pkcs8(KeyBytes, Curve)}
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_export_public_key_pem({PubBytes, Curve}) ->
    try
        Der = eddsa_xdh_public_to_spki(PubBytes, Curve),
        {ok, public_key:pem_encode([{'SubjectPublicKeyInfo', Der, not_encrypted}])}
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_export_public_key_der({PubBytes, Curve}) ->
    try
        {ok, eddsa_xdh_public_to_spki(PubBytes, Curve)}
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_public_key_from_private({_PrivBytes, Curve} = PrivKey) ->
    % Generate public key from private using crypto module
    {PubKey, _} = crypto:generate_key(eddsa, Curve, element(1, PrivKey)),
    {PubKey, Curve}.

%% XDH Import/Export Functions

xdh_import_private_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'PrivateKeyInfo', DerBytes, not_encrypted}] ->
                xdh_import_private_key_from_der(DerBytes);
            _ ->
                {error, invalid_key_data}
        end
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

xdh_import_private_key_der(DerBytes) ->
    try
        xdh_import_private_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

xdh_import_private_key_from_der(DerBytes) ->
    {AlgOID, _} = extract_pkcs8_algorithm(DerBytes),
    case AlgOID of
        {1, 3, 101, 110} ->
            xdh_import_private_from_pkcs8(DerBytes, x25519);
        {1, 3, 101, 111} ->
            xdh_import_private_from_pkcs8(DerBytes, x448);
        _ ->
            {error, unsupported_curve}
    end.

xdh_import_private_from_pkcs8(DerBytes, Curve) ->
    PrivateKeyDer = extract_pkcs8_private_key(DerBytes),
    PrivateBytes = decode_octet_string(PrivateKeyDer),
    {PubKey, PrivKey} = crypto:generate_key(ecdh, Curve, PrivateBytes),
    {ok, {{PrivKey, Curve}, {PubKey, Curve}}}.

xdh_import_public_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'SubjectPublicKeyInfo', DerBytes, not_encrypted}] ->
                xdh_import_public_key_from_der(DerBytes);
            _ ->
                {error, invalid_key_data}
        end
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

xdh_import_public_key_der(DerBytes) ->
    try
        xdh_import_public_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, invalid_key_data}
    end.

xdh_import_public_key_from_der(DerBytes) ->
    {'SubjectPublicKeyInfo', AlgId, PublicKeyBits} =
        public_key:der_decode('SubjectPublicKeyInfo', DerBytes),
    {'AlgorithmIdentifier', AlgOID, _} = AlgId,
    case AlgOID of
        {1, 3, 101, 110} ->
            {ok, {PublicKeyBits, x25519}};
        {1, 3, 101, 111} ->
            {ok, {PublicKeyBits, x448}};
        _ ->
            {error, unsupported_curve}
    end.

xdh_export_private_key_pem({KeyBytes, Curve}) ->
    try
        Der = eddsa_xdh_private_to_pkcs8(KeyBytes, Curve),
        {ok, public_key:pem_encode([{'PrivateKeyInfo', Der, not_encrypted}])}
    catch
        _:_ ->
            {error, nil}
    end.

xdh_export_private_key_der({KeyBytes, Curve}) ->
    try
        {ok, eddsa_xdh_private_to_pkcs8(KeyBytes, Curve)}
    catch
        _:_ ->
            {error, nil}
    end.

xdh_export_public_key_pem({PubBytes, Curve}) ->
    try
        Der = eddsa_xdh_public_to_spki(PubBytes, Curve),
        {ok, public_key:pem_encode([{'SubjectPublicKeyInfo', Der, not_encrypted}])}
    catch
        _:_ ->
            {error, nil}
    end.

xdh_export_public_key_der({PubBytes, Curve}) ->
    try
        {ok, eddsa_xdh_public_to_spki(PubBytes, Curve)}
    catch
        _:_ ->
            {error, nil}
    end.

xdh_public_key_from_private({_PrivBytes, Curve} = PrivKey) ->
    {PubKey, _} = crypto:generate_key(ecdh, Curve, element(1, PrivKey)),
    {PubKey, Curve}.

%% EdDSA/XDH ASN.1 encoding helpers

eddsa_xdh_curve_oid(ed25519) -> {1, 3, 101, 112};
eddsa_xdh_curve_oid(ed448) -> {1, 3, 101, 113};
eddsa_xdh_curve_oid(x25519) -> {1, 3, 101, 110};
eddsa_xdh_curve_oid(x448) -> {1, 3, 101, 111}.

%% Manual DER encoding for EdDSA/XDH PKCS#8
%% Erlang's public_key module doesn't support these key types for der_encode
eddsa_xdh_private_to_pkcs8(KeyBytes, Curve) ->
    OID = encode_oid(eddsa_xdh_curve_oid(Curve)),
    InnerOctet = encode_octet_string(KeyBytes),
    AlgSeq = encode_sequence([OID]),
    encode_sequence([
        encode_integer(0),
        AlgSeq,
        encode_octet_string(InnerOctet)
    ]).

%% Manual DER encoding for EdDSA/XDH SPKI
eddsa_xdh_public_to_spki(PubBytes, Curve) ->
    OID = encode_oid(eddsa_xdh_curve_oid(Curve)),
    AlgSeq = encode_sequence([OID]),
    encode_sequence([
        AlgSeq,
        encode_bit_string(PubBytes)
    ]).

%% ASN.1 DER encoding primitives

encode_integer(0) ->
    <<2, 1, 0>>;
encode_integer(N) when is_integer(N), N > 0 ->
    Bytes = binary:encode_unsigned(N),
    encode_primitive(2, Bytes).

encode_octet_string(Bytes) when is_binary(Bytes) ->
    encode_primitive(4, Bytes).

encode_bit_string(Bytes) when is_binary(Bytes) ->
    % Bit string has leading byte for unused bits (0 for whole bytes)
    encode_primitive(3, <<0, Bytes/binary>>).

encode_oid(OID) ->
    Bytes = oid_to_der_content(OID),
    encode_primitive(6, Bytes).

encode_sequence(Items) ->
    Content = iolist_to_binary(Items),
    encode_constructed(16#30, Content).

encode_primitive(Tag, Content) ->
    Length = encode_length(byte_size(Content)),
    <<Tag, Length/binary, Content/binary>>.

encode_constructed(Tag, Content) ->
    Length = encode_length(byte_size(Content)),
    <<Tag, Length/binary, Content/binary>>.

encode_length(Len) when Len < 128 ->
    <<Len>>;
encode_length(Len) ->
    Bytes = binary:encode_unsigned(Len),
    NumBytes = byte_size(Bytes),
    <<(128 + NumBytes), Bytes/binary>>.

%% OID encoding - handles variable component count
oid_to_der_content(OID) when is_tuple(OID), tuple_size(OID) >= 2 ->
    [A, B | Rest] = tuple_to_list(OID),
    First = A * 40 + B,
    RestEncoded = [encode_oid_component(C) || C <- Rest],
    iolist_to_binary([First | RestEncoded]).

encode_oid_component(N) when N < 128 ->
    <<N>>;
encode_oid_component(N) ->
    encode_oid_component_high(N, <<>>).

encode_oid_component_high(0, Acc) ->
    Acc;
encode_oid_component_high(N, <<>>) ->
    encode_oid_component_high(N bsr 7, <<(N band 127)>>);
encode_oid_component_high(N, Acc) ->
    encode_oid_component_high(N bsr 7, <<((N band 127) bor 128), Acc/binary>>).

%% PKCS#8 DER parsing helpers (used by module-specific import functions)

%% Extract algorithm OID from PKCS#8 DER structure
%% PKCS#8 PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm AlgorithmIdentifier, privateKey OCTET STRING }
extract_pkcs8_algorithm(DerBytes) ->
    % Decode the outer SEQUENCE
    <<16#30, Rest1/binary>> = DerBytes,
    {_, Rest2} = decode_der_length(Rest1),
    % Skip version INTEGER
    <<2, VersionLen, _:VersionLen/binary, Rest3/binary>> = Rest2,
    % Decode AlgorithmIdentifier SEQUENCE
    <<16#30, Rest4/binary>> = Rest3,
    {AlgLen, Rest5} = decode_der_length(Rest4),
    <<AlgContent:AlgLen/binary, _/binary>> = Rest5,
    % Decode OID
    <<6, OidLen, OidBytes:OidLen/binary, ParamsRest/binary>> = AlgContent,
    OID = decode_oid(OidBytes),
    % Extract parameters if present
    Params =
        case ParamsRest of
            <<>> ->
                undefined;
            <<6, ParamOidLen, ParamOidBytes:ParamOidLen/binary, _/binary>> ->
                {namedCurve, decode_oid(ParamOidBytes)};
            _ ->
                undefined
        end,
    {OID, Params}.

decode_der_length(<<Len, Rest/binary>>) when Len < 128 ->
    {Len, Rest};
decode_der_length(<<16#81, Len, Rest/binary>>) ->
    {Len, Rest};
decode_der_length(<<16#82, Len:16, Rest/binary>>) ->
    {Len, Rest}.

decode_oid(Bytes) ->
    [First | Rest] = binary_to_list(Bytes),
    A = First div 40,
    B = First rem 40,
    Components = decode_oid_components(Rest, []),
    list_to_tuple([A, B | Components]).

decode_oid_components([], Acc) ->
    lists:reverse(Acc);
decode_oid_components(Bytes, Acc) ->
    {Value, Rest} = decode_oid_component(Bytes, 0),
    decode_oid_components(Rest, [Value | Acc]).

decode_oid_component([Byte | Rest], Acc) when Byte < 128 ->
    {Acc * 128 + Byte, Rest};
decode_oid_component([Byte | Rest], Acc) ->
    decode_oid_component(Rest, Acc * 128 + (Byte band 127)).

%% Extract the privateKey OCTET STRING from PKCS#8 structure
extract_pkcs8_private_key(DerBytes) ->
    % Decode the outer SEQUENCE
    <<16#30, Rest1/binary>> = DerBytes,
    {_, Rest2} = decode_der_length(Rest1),
    % Skip version INTEGER
    <<2, VersionLen, _:VersionLen/binary, Rest3/binary>> = Rest2,
    % Skip AlgorithmIdentifier SEQUENCE
    <<16#30, Rest4/binary>> = Rest3,
    {AlgLen, Rest5} = decode_der_length(Rest4),
    <<_:AlgLen/binary, Rest6/binary>> = Rest5,
    % The next element is the privateKey OCTET STRING
    <<4, Rest7/binary>> = Rest6,
    {PrivKeyLen, Rest8} = decode_der_length(Rest7),
    <<PrivateKeyDer:PrivKeyLen/binary, _/binary>> = Rest8,
    PrivateKeyDer.

%% Decode ASN.1 OCTET STRING
decode_octet_string(<<4, Len, Rest/binary>>) when Len < 128 ->
    <<Bytes:Len/binary, _/binary>> = Rest,
    Bytes;
decode_octet_string(<<4, 16#81, Len, Rest/binary>>) ->
    <<Bytes:Len/binary, _/binary>> = Rest,
    Bytes;
decode_octet_string(<<4, 16#82, Len:16, Rest/binary>>) ->
    <<Bytes:Len/binary, _/binary>> = Rest,
    Bytes.
