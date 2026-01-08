-module(kryptos_ffi).

-include_lib("public_key/include/public_key.hrl").

-export([
    aead_open/5,
    aead_seal/4,
    cipher_decrypt/2,
    cipher_encrypt/2,
    constant_time_equal/2,
    ec_export_private_key_der/1,
    ec_export_private_key_pem/1,
    ec_export_public_key_der/1,
    ec_export_public_key_pem/1,
    ec_generate_key_pair/1,
    ec_import_private_key_der/1,
    ec_import_private_key_pem/1,
    ec_import_public_key_der/1,
    ec_import_public_key_pem/1,
    ec_private_key_from_bytes/2,
    ec_public_key_from_private/1,
    ec_public_key_from_raw_point/2,
    ec_public_key_from_x509/1,
    ecdh_compute_shared_secret/2,
    ecdsa_sign/3,
    ecdsa_verify/4,
    eddsa_export_private_key_der/1,
    eddsa_export_private_key_pem/1,
    eddsa_export_public_key_der/1,
    eddsa_export_public_key_pem/1,
    eddsa_generate_key_pair/1,
    eddsa_import_private_key_der/1,
    eddsa_import_private_key_pem/1,
    eddsa_import_public_key_der/1,
    eddsa_import_public_key_pem/1,
    eddsa_private_key_from_bytes/2,
    eddsa_public_key_from_bytes/2,
    eddsa_public_key_from_private/1,
    eddsa_sign/2,
    eddsa_verify/3,
    hash_new/1,
    hmac_new/2,
    pbkdf2_derive/5,
    random_bytes/1,
    rsa_decrypt/3,
    rsa_encrypt/3,
    rsa_export_private_key_der/2,
    rsa_export_private_key_pem/2,
    rsa_export_public_key_der/2,
    rsa_export_public_key_pem/2,
    rsa_generate_key_pair/1,
    rsa_import_private_key_der/2,
    rsa_import_private_key_pem/2,
    rsa_import_public_key_der/2,
    rsa_import_public_key_pem/2,
    rsa_private_key_from_pkcs8/1,
    rsa_public_key_from_private/1,
    rsa_public_key_from_x509/1,
    rsa_sign/4,
    rsa_verify/5,
    xdh_compute_shared_secret/2,
    xdh_export_private_key_der/1,
    xdh_export_private_key_pem/1,
    xdh_export_public_key_der/1,
    xdh_export_public_key_pem/1,
    xdh_generate_key_pair/1,
    xdh_import_private_key_der/1,
    xdh_import_private_key_pem/1,
    xdh_import_public_key_der/1,
    xdh_import_public_key_pem/1,
    xdh_private_key_from_bytes/2,
    xdh_public_key_from_bytes/2,
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

aead_cipher_name({gcm, {aes, 128, _}, _}) ->
    aes_128_gcm;
aead_cipher_name({gcm, {aes, 192, _}, _}) ->
    aes_192_gcm;
aead_cipher_name({gcm, {aes, 256, _}, _}) ->
    aes_256_gcm;
aead_cipher_name({ccm, {aes, 128, _}, _, _}) ->
    aes_128_ccm;
aead_cipher_name({ccm, {aes, 192, _}, _, _}) ->
    aes_192_ccm;
aead_cipher_name({ccm, {aes, 256, _}, _, _}) ->
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
cipher_name({ecb, {aes, 128, _}}) ->
    aes_128_ecb;
cipher_name({ecb, {aes, 192, _}}) ->
    aes_192_ecb;
cipher_name({ecb, {aes, 256, _}}) ->
    aes_256_ecb;
cipher_name({cbc, {aes, 128, _}, _}) ->
    aes_128_cbc;
cipher_name({cbc, {aes, 192, _}, _}) ->
    aes_192_cbc;
cipher_name({cbc, {aes, 256, _}, _}) ->
    aes_256_cbc;
cipher_name({ctr, {aes, 128, _}, _}) ->
    aes_128_ctr;
cipher_name({ctr, {aes, 192, _}, _}) ->
    aes_192_ctr;
cipher_name({ctr, {aes, 256, _}, _}) ->
    aes_256_ctr.

cipher_padding({ecb, _}) ->
    pkcs_padding;
cipher_padding({cbc, _, _}) ->
    pkcs_padding;
cipher_padding({ctr, _, _}) ->
    none.

cipher_encrypt(Mode, Plaintext) ->
    Cipher = cipher_name(Mode),
    Key = kryptos@block:cipher_key(Mode),
    Iv = kryptos@block:cipher_iv(Mode),
    Padding = cipher_padding(Mode),
    try
        Ciphertext =
            crypto:crypto_one_time(
                Cipher,
                Key,
                Iv,
                Plaintext,
                [{encrypt, true}, {padding, Padding}]
            ),
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
        Plaintext =
            crypto:crypto_one_time(
                Cipher,
                Key,
                Iv,
                Ciphertext,
                [{encrypt, false}, {padding, Padding}]
            ),
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
    OID = curve_to_oid(CurveName),
    {PubPoint, PrivScalar} = crypto:generate_key(ecdh, CurveName),
    PrivKey =
        {'ECPrivateKey', ecPrivkeyVer1, PrivScalar, {namedCurve, OID}, PubPoint, asn1_NOVALUE},
    PubKey = {{'ECPoint', PubPoint}, {namedCurve, CurveName}},
    {PrivKey, PubKey}.

ec_private_key_from_bytes(Curve, PrivateScalar) ->
    try
        CurveName = ec_curve_name(Curve),
        OID = curve_to_oid(CurveName),
        % Generate a temporary key to get the public point
        % We need to compute the public key from the private scalar
        {PublicPoint, _} = crypto:generate_key(ecdh, CurveName, PrivateScalar),
        PrivKey =
            {'ECPrivateKey', ecPrivkeyVer1, PrivateScalar, {namedCurve, OID}, PublicPoint,
                asn1_NOVALUE},
        PubKey = {{'ECPoint', PublicPoint}, {namedCurve, CurveName}},
        {ok, {PrivKey, PubKey}}
    catch
        _:_ ->
            {error, nil}
    end.

ec_public_key_from_x509(DerBytes) ->
    try
        % Decode the SubjectPublicKeyInfo structure
        {'SubjectPublicKeyInfo', AlgId, PublicKeyBits} =
            public_key:der_decode('SubjectPublicKeyInfo', DerBytes),
        {'AlgorithmIdentifier', _, {namedCurve, OID}} = AlgId,
        CurveName = oid_to_curve(OID),
        % PublicKeyBits is the raw EC point
        {ok, {{'ECPoint', PublicKeyBits}, {namedCurve, CurveName}}}
    catch
        _:_ ->
            {error, nil}
    end.

ec_public_key_from_raw_point(Curve, Point) ->
    try
        CurveName = ec_curve_name(Curve),
        CoordSize = kryptos@ec:coordinate_size(Curve),
        ExpectedSize = 1 + 2 * CoordSize,
        case byte_size(Point) of
            ExpectedSize ->
                case Point of
                    <<16#04, _X:CoordSize/binary, _Y:CoordSize/binary>> ->
                        % Validate point is on curve by attempting ECDH with a test key
                        validate_ec_point(CurveName, Point);
                    _ ->
                        {error, nil}
                end;
            _ ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

validate_ec_point(CurveName, Point) ->
    try
        % Generate a temporary key pair to validate the point
        {_TempPub, TempPriv} = crypto:generate_key(ecdh, CurveName),
        % Try computing shared secret - this validates the point is on the curve
        _ = crypto:compute_key(ecdh, Point, TempPriv, CurveName),
        % Point is valid, construct the public key structure
        {ok, {{'ECPoint', Point}, {namedCurve, CurveName}}}
    catch
        _:_ ->
            {error, nil}
    end.

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
            CurveName = oid_to_curve(CurveOID),
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
            CurveName = oid_to_curve(OID),
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
    {'PrivateKeyInfo', Der, not_encrypted} =
        public_key:pem_entry_encode('PrivateKeyInfo', Key),
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
    CurveOID = curve_to_oid(CurveName),
    Key = {{'ECPoint', Point}, {namedCurve, CurveOID}},
    {'SubjectPublicKeyInfo', Der, not_encrypted} =
        public_key:pem_entry_encode('SubjectPublicKeyInfo', Key),
    Der.

ec_public_key_from_private({'ECPrivateKey', _, _, {namedCurve, CurveOID}, PublicPoint, _}) ->
    CurveName = oid_to_curve(CurveOID),
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

ecdh_compute_shared_secret(PrivateKey, PeerPublicKey) ->
    try
        {{'ECPoint', PeerPoint}, {namedCurve, PeerCurveName}} = PeerPublicKey,
        {namedCurve, PrivateOID} = element(4, PrivateKey),
        ExpectedOID = curve_to_oid(PeerCurveName),
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
    [
        {rsa_padding, rsa_pkcs1_pss_padding},
        {rsa_pss_saltlen, Salt},
        {rsa_mgf1_md, DigestType}
    ].

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
    Opts =
        [
            {rsa_padding, rsa_pkcs1_oaep_padding},
            {rsa_oaep_md, DigestType},
            {rsa_mgf1_md, DigestType}
        ],
    case Label of
        <<>> ->
            Opts;
        _ ->
            [{rsa_oaep_label, Label} | Opts]
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
        PubKey =
            #'RSAPublicKey'{
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
        {'SubjectPublicKeyInfo', {'AlgorithmIdentifier', ?rsaEncryption, _}, PublicKeyDer} =
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

rsa_private_format_types(pkcs8) ->
    {'PrivateKeyInfo', 'PrivateKeyInfo'};
rsa_private_format_types(pkcs1) ->
    {'RSAPrivateKey', 'RSAPrivateKey'}.

rsa_import_private_key_from_der(DerBytes, DerType) ->
    RSAPrivKey = public_key:der_decode(DerType, DerBytes),
    RSAPubKey =
        #'RSAPublicKey'{
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

rsa_public_format_types(spki) ->
    {'SubjectPublicKeyInfo', spki};
rsa_public_format_types(rsa_public_key) ->
    {'RSAPublicKey', rsa_public_key}.

rsa_import_public_key_from_der(DerBytes, spki) ->
    PubKey = public_key:der_decode('SubjectPublicKeyInfo', DerBytes),
    {'SubjectPublicKeyInfo', {'AlgorithmIdentifier', ?rsaEncryption, _}, PublicKeyDer} =
        PubKey,
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
    {'PrivateKeyInfo', Der, not_encrypted} =
        public_key:pem_entry_encode('PrivateKeyInfo', Key),
    Der;
rsa_private_key_to_der(Key, pkcs1) ->
    public_key:der_encode('RSAPrivateKey', Key).

rsa_private_pem_type(pkcs8) ->
    'PrivateKeyInfo';
rsa_private_pem_type(pkcs1) ->
    'RSAPrivateKey'.

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
    {'SubjectPublicKeyInfo', Der, not_encrypted} =
        public_key:pem_entry_encode('SubjectPublicKeyInfo', Key),
    Der;
rsa_public_key_to_der(Key, rsa_public_key) ->
    public_key:der_encode('RSAPublicKey', Key).

rsa_public_pem_type(spki) ->
    'SubjectPublicKeyInfo';
rsa_public_pem_type(rsa_public_key) ->
    'RSAPublicKey'.

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
    case public_key:der_decode('PrivateKeyInfo', DerBytes) of
        #'ECPrivateKey'{privateKey = PrivateBytes, parameters = {namedCurve, OID}} ->
            Curve = oid_to_curve(OID),
            case Curve of
                _ when Curve =:= ed25519; Curve =:= ed448 ->
                    {PubKey, PrivKey} = crypto:generate_key(eddsa, Curve, PrivateBytes),
                    {ok, {{PrivKey, Curve}, {PubKey, Curve}}};
                _ ->
                    {error, unsupported_curve}
            end;
        _ ->
            {error, unsupported_curve}
    end.

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
    case public_key:der_decode('SubjectPublicKeyInfo', DerBytes) of
        #'SubjectPublicKeyInfo'{
            algorithm = #'AlgorithmIdentifier'{algorithm = OID},
            subjectPublicKey = PublicKeyBits
        } ->
            Curve = oid_to_curve(OID),
            case Curve of
                _ when Curve =:= ed25519; Curve =:= ed448 ->
                    {ok, {PublicKeyBits, Curve}};
                _ ->
                    {error, unsupported_curve}
            end;
        _ ->
            {error, unsupported_curve}
    end.

eddsa_export_private_key_pem({KeyBytes, Curve}) ->
    try
        ECPrivKey =
            #'ECPrivateKey'{
                version = 1,
                privateKey = KeyBytes,
                parameters = {namedCurve, curve_to_oid(Curve)}
            },
        Der = public_key:der_encode('PrivateKeyInfo', ECPrivKey),
        {ok, public_key:pem_encode([{'PrivateKeyInfo', Der, not_encrypted}])}
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_export_private_key_der({KeyBytes, Curve}) ->
    try
        ECPrivKey =
            #'ECPrivateKey'{
                version = 1,
                privateKey = KeyBytes,
                parameters = {namedCurve, curve_to_oid(Curve)}
            },
        {ok, public_key:der_encode('PrivateKeyInfo', ECPrivKey)}
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_export_public_key_pem({PubBytes, Curve}) ->
    try
        Spki =
            #'SubjectPublicKeyInfo'{
                algorithm =
                    #'AlgorithmIdentifier'{algorithm = curve_to_oid(Curve)},
                subjectPublicKey = PubBytes
            },
        Der = public_key:der_encode('SubjectPublicKeyInfo', Spki),
        {ok, public_key:pem_encode([{'SubjectPublicKeyInfo', Der, not_encrypted}])}
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_export_public_key_der({PubBytes, Curve}) ->
    try
        Spki =
            #'SubjectPublicKeyInfo'{
                algorithm =
                    #'AlgorithmIdentifier'{algorithm = curve_to_oid(Curve)},
                subjectPublicKey = PubBytes
            },
        {ok, public_key:der_encode('SubjectPublicKeyInfo', Spki)}
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
    case public_key:der_decode('PrivateKeyInfo', DerBytes) of
        {'PrivateKeyInfo', _, {'PrivateKeyAlgorithmIdentifier', OID, _}, WrappedKey, _, _} ->
            Curve = oid_to_curve(OID),
            case Curve of
                _ when Curve =:= x25519; Curve =:= x448 ->
                    KeySize = xdh_key_size(Curve),
                    case WrappedKey of
                        <<4, KeySize, PrivateBytes:KeySize/binary>> ->
                            {PubKey, PrivKey} = crypto:generate_key(ecdh, Curve, PrivateBytes),
                            {ok, {{PrivKey, Curve}, {PubKey, Curve}}};
                        _ ->
                            {error, unsupported_curve}
                    end;
                _ ->
                    {error, unsupported_curve}
            end;
        _ ->
            {error, unsupported_curve}
    end.

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
    case public_key:der_decode('SubjectPublicKeyInfo', DerBytes) of
        #'SubjectPublicKeyInfo'{
            algorithm = #'AlgorithmIdentifier'{algorithm = OID},
            subjectPublicKey = PublicKeyBits
        } ->
            Curve = oid_to_curve(OID),
            case Curve of
                _ when Curve =:= x25519; Curve =:= x448 ->
                    {ok, {PublicKeyBits, Curve}};
                _ ->
                    {error, unsupported_curve}
            end;
        _ ->
            {error, unsupported_curve}
    end.

xdh_export_private_key_pem({KeyBytes, Curve}) ->
    try
        KeySize = xdh_key_size(Curve),
        WrappedKey = <<4, KeySize, KeyBytes/binary>>,
        PrivKeyInfo =
            #'PrivateKeyInfo'{
                version = v1,
                privateKeyAlgorithm =
                    #'PrivateKeyInfo_privateKeyAlgorithm'{
                        algorithm =
                            curve_to_oid(Curve)
                    },
                privateKey = WrappedKey
            },
        Der = public_key:der_encode('PrivateKeyInfo', PrivKeyInfo),
        {ok, public_key:pem_encode([{'PrivateKeyInfo', Der, not_encrypted}])}
    catch
        _:_ ->
            {error, nil}
    end.

xdh_export_private_key_der({KeyBytes, Curve}) ->
    try
        KeySize = xdh_key_size(Curve),
        WrappedKey = <<4, KeySize, KeyBytes/binary>>,
        PrivKeyInfo =
            #'PrivateKeyInfo'{
                version = v1,
                privateKeyAlgorithm =
                    #'PrivateKeyInfo_privateKeyAlgorithm'{
                        algorithm =
                            curve_to_oid(Curve)
                    },
                privateKey = WrappedKey
            },
        {ok, public_key:der_encode('PrivateKeyInfo', PrivKeyInfo)}
    catch
        _:_ ->
            {error, nil}
    end.

xdh_export_public_key_pem({PubBytes, Curve}) ->
    try
        Spki =
            #'SubjectPublicKeyInfo'{
                algorithm =
                    #'AlgorithmIdentifier'{algorithm = curve_to_oid(Curve)},
                subjectPublicKey = PubBytes
            },
        Der = public_key:der_encode('SubjectPublicKeyInfo', Spki),
        {ok, public_key:pem_encode([{'SubjectPublicKeyInfo', Der, not_encrypted}])}
    catch
        _:_ ->
            {error, nil}
    end.

xdh_export_public_key_der({PubBytes, Curve}) ->
    try
        Spki =
            #'SubjectPublicKeyInfo'{
                algorithm =
                    #'AlgorithmIdentifier'{algorithm = curve_to_oid(Curve)},
                subjectPublicKey = PubBytes
            },
        {ok, public_key:der_encode('SubjectPublicKeyInfo', Spki)}
    catch
        _:_ ->
            {error, nil}
    end.

xdh_public_key_from_private({_PrivBytes, Curve} = PrivKey) ->
    {PubKey, _} = crypto:generate_key(ecdh, Curve, element(1, PrivKey)),
    {PubKey, Curve}.

xdh_key_size(x25519) ->
    32;
xdh_key_size(x448) ->
    56.

curve_to_oid(secp256r1) ->
    {1, 2, 840, 10045, 3, 1, 7};
curve_to_oid(secp384r1) ->
    {1, 3, 132, 0, 34};
curve_to_oid(secp521r1) ->
    {1, 3, 132, 0, 35};
curve_to_oid(secp256k1) ->
    {1, 3, 132, 0, 10};
curve_to_oid(ed25519) ->
    {1, 3, 101, 112};
curve_to_oid(ed448) ->
    {1, 3, 101, 113};
curve_to_oid(x25519) ->
    {1, 3, 101, 110};
curve_to_oid(x448) ->
    {1, 3, 101, 111}.

oid_to_curve({1, 2, 840, 10045, 3, 1, 7}) ->
    secp256r1;
oid_to_curve({1, 3, 132, 0, 34}) ->
    secp384r1;
oid_to_curve({1, 3, 132, 0, 35}) ->
    secp521r1;
oid_to_curve({1, 3, 132, 0, 10}) ->
    secp256k1;
oid_to_curve({1, 3, 101, 112}) ->
    ed25519;
oid_to_curve({1, 3, 101, 113}) ->
    ed448;
oid_to_curve({1, 3, 101, 110}) ->
    x25519;
oid_to_curve({1, 3, 101, 111}) ->
    x448.
