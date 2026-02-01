-module(kryptos_ffi).

-include_lib("kryptos/include/kryptos@aead_Ccm.hrl").
-include_lib("kryptos/include/kryptos@aead_ChaCha20Poly1305.hrl").
-include_lib("kryptos/include/kryptos@aead_Gcm.hrl").
-include_lib("kryptos/include/kryptos@block_Aes.hrl").
-include_lib("kryptos/include/kryptos@block_Cbc.hrl").
-include_lib("kryptos/include/kryptos@block_Ctr.hrl").
-include_lib("kryptos/include/kryptos@block_Ecb.hrl").
-include_lib("kryptos/include/kryptos@rsa_Oaep.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    aead_open/5,
    aead_seal/4,
    aes_decrypt_block/2,
    aes_encrypt_block/2,
    block_cipher_decrypt/2,
    block_cipher_encrypt/2,
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
    ec_private_key_to_bytes/1,
    ec_public_key_from_private/1,
    ec_public_key_from_raw_point/2,
    ec_public_key_to_raw_point/1,
    ec_public_key_from_x509/1,
    ec_private_key_curve/1,
    ec_public_key_curve/1,
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
    eddsa_private_key_to_bytes/1,
    eddsa_public_key_from_bytes/2,
    eddsa_public_key_from_private/1,
    eddsa_public_key_to_bytes/1,
    eddsa_private_key_curve/1,
    eddsa_public_key_curve/1,
    eddsa_sign/2,
    eddsa_verify/3,
    hash_new/1,
    hash_update/2,
    hash_final/1,
    hmac_new/2,
    mod_pow/3,
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
    rsa_private_key_modulus_bits/1,
    rsa_public_key_modulus_bits/1,
    rsa_private_key_modulus/1,
    rsa_public_key_modulus/1,
    rsa_private_key_public_exponent/1,
    rsa_public_key_public_exponent/1,
    rsa_private_key_public_exponent_bytes/1,
    rsa_public_key_exponent_bytes/1,
    rsa_private_key_private_exponent_bytes/1,
    rsa_private_key_prime1/1,
    rsa_private_key_prime2/1,
    rsa_private_key_exponent1/1,
    rsa_private_key_exponent2/1,
    rsa_private_key_coefficient/1,
    rsa_public_key_from_components/2,
    rsa_private_key_from_full_components/8,
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
    xdh_private_key_to_bytes/1,
    xdh_public_key_from_bytes/2,
    xdh_public_key_from_private/1,
    xdh_public_key_to_bytes/1,
    xdh_private_key_curve/1,
    xdh_public_key_curve/1
]).

%%------------------------------------------------------------------------------
%% OTP Version Detection
%%------------------------------------------------------------------------------

%% OTP 28 changed PrivateKeyInfo from a 5-tuple to a 6-tuple (OneAsymmetricKey)
%% and renamed the algorithm identifier tuple.
otp_version() ->
    list_to_integer(erlang:system_info(otp_release)).

is_otp_28_or_later() ->
    otp_version() >= 28.

%%------------------------------------------------------------------------------
%% Utilities & Random
%%------------------------------------------------------------------------------

random_bytes(Length) when Length < 0 ->
    crypto:strong_rand_bytes(0);
random_bytes(Length) ->
    crypto:strong_rand_bytes(Length).

constant_time_equal(A, B) when byte_size(A) =:= byte_size(B) ->
    crypto:hash_equals(A, B);
constant_time_equal(_, _) ->
    false.

%%------------------------------------------------------------------------------
%% Hash Functions
%%------------------------------------------------------------------------------

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
hash_algorithm_name({shake128, _OutputLength}) ->
    shake128;
hash_algorithm_name({shake256, _OutputLength}) ->
    shake256;
hash_algorithm_name(Name) ->
    Name.

hash_new({shake128, OutputLength}) ->
    try
        _ = crypto:hash_xof(shake128, <<>>, 8),
        {ok, {xof, shake128, [], OutputLength}}
    catch
        _:_ ->
            {error, nil}
    end;
hash_new({shake256, OutputLength}) ->
    try
        _ = crypto:hash_xof(shake256, <<>>, 8),
        {ok, {xof, shake256, [], OutputLength}}
    catch
        _:_ ->
            {error, nil}
    end;
hash_new(Algorithm) ->
    try
        Name = hash_algorithm_name(Algorithm),
        {ok, crypto:hash_init(Name)}
    catch
        _:_ ->
            {error, nil}
    end.

hash_update({xof, Algorithm, AccData, OutputLength}, Data) ->
    {xof, Algorithm, [Data | AccData], OutputLength};
hash_update(State, Data) ->
    crypto:hash_update(State, Data).

hash_final({xof, Algorithm, AccData, OutputLength}) ->
    AllData = lists:reverse(AccData),
    crypto:hash_xof(Algorithm, AllData, OutputLength * 8);
hash_final(State) ->
    crypto:hash_final(State).

%%------------------------------------------------------------------------------
%% HMAC
%%------------------------------------------------------------------------------

hmac_new(Algorithm, Key) ->
    try
        Name = hash_algorithm_name(Algorithm),
        {ok, crypto:mac_init(hmac, Name, Key)}
    catch
        _:_ ->
            {error, nil}
    end.

%%------------------------------------------------------------------------------
%% Key Derivation Functions (PBKDF2)
%%------------------------------------------------------------------------------

pbkdf2_derive(Algorithm, Password, Salt, Iterations, Length) ->
    Name = hash_algorithm_name(Algorithm),
    try
        Key = crypto:pbkdf2_hmac(Name, Password, Salt, Iterations, Length),
        {ok, Key}
    catch
        _:_ ->
            {error, nil}
    end.

%%------------------------------------------------------------------------------
%% AEAD Ciphers (GCM, CCM, ChaCha20-Poly1305)
%%------------------------------------------------------------------------------

aead_cipher_name(#gcm{cipher = #aes{key_size = 128}}) ->
    aes_128_gcm;
aead_cipher_name(#gcm{cipher = #aes{key_size = 192}}) ->
    aes_192_gcm;
aead_cipher_name(#gcm{cipher = #aes{key_size = 256}}) ->
    aes_256_gcm;
aead_cipher_name(#ccm{cipher = #aes{key_size = 128}}) ->
    aes_128_ccm;
aead_cipher_name(#ccm{cipher = #aes{key_size = 192}}) ->
    aes_192_ccm;
aead_cipher_name(#ccm{cipher = #aes{key_size = 256}}) ->
    aes_256_ccm;
aead_cipher_name(#cha_cha20_poly1305{}) ->
    chacha20_poly1305.

aead_cipher_key(#gcm{cipher = #aes{key = Key}}) ->
    Key;
aead_cipher_key(#ccm{cipher = #aes{key = Key}}) ->
    Key;
aead_cipher_key(#cha_cha20_poly1305{key = Key}) ->
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
    try
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
        end
    catch
        error:_ ->
            {error, nil}
    end.

%%------------------------------------------------------------------------------
%% Block Ciphers (ECB, CBC, CTR)
%%------------------------------------------------------------------------------

block_cipher_name(#ecb{cipher = #aes{key_size = 128}}) ->
    aes_128_ecb;
block_cipher_name(#ecb{cipher = #aes{key_size = 192}}) ->
    aes_192_ecb;
block_cipher_name(#ecb{cipher = #aes{key_size = 256}}) ->
    aes_256_ecb;
block_cipher_name(#cbc{cipher = #aes{key_size = 128}}) ->
    aes_128_cbc;
block_cipher_name(#cbc{cipher = #aes{key_size = 192}}) ->
    aes_192_cbc;
block_cipher_name(#cbc{cipher = #aes{key_size = 256}}) ->
    aes_256_cbc;
block_cipher_name(#ctr{cipher = #aes{key_size = 128}}) ->
    aes_128_ctr;
block_cipher_name(#ctr{cipher = #aes{key_size = 192}}) ->
    aes_192_ctr;
block_cipher_name(#ctr{cipher = #aes{key_size = 256}}) ->
    aes_256_ctr.

block_cipher_padding(#ecb{}) ->
    pkcs_padding;
block_cipher_padding(#cbc{}) ->
    pkcs_padding;
block_cipher_padding(#ctr{}) ->
    none.

block_cipher_encrypt(Mode, Plaintext) ->
    Cipher = block_cipher_name(Mode),
    Key = kryptos@block:cipher_key(Mode),
    Iv = kryptos@block:cipher_iv(Mode),
    Padding = block_cipher_padding(Mode),
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

block_cipher_decrypt(Mode, Ciphertext) ->
    Cipher = block_cipher_name(Mode),
    Key = kryptos@block:cipher_key(Mode),
    Iv = kryptos@block:cipher_iv(Mode),
    Padding = block_cipher_padding(Mode),
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

%% Raw AES block encryption/decryption (no padding, for key wrap)

aes_cipher_name(#aes{key_size = 128}) ->
    aes_128_ecb;
aes_cipher_name(#aes{key_size = 192}) ->
    aes_192_ecb;
aes_cipher_name(#aes{key_size = 256}) ->
    aes_256_ecb.

aes_encrypt_block(Cipher, Block) ->
    CipherName = aes_cipher_name(Cipher),
    Key = Cipher#aes.key,
    crypto:crypto_one_time(CipherName, Key, Block, [{encrypt, true}, {padding, none}]).

aes_decrypt_block(Cipher, Block) ->
    CipherName = aes_cipher_name(Cipher),
    Key = Cipher#aes.key,
    crypto:crypto_one_time(CipherName, Key, Block, [{encrypt, false}, {padding, none}]).

%%------------------------------------------------------------------------------
%% Curve/OID Mapping (shared by EC, EdDSA, XDH)
%%------------------------------------------------------------------------------

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

%%------------------------------------------------------------------------------
%% Elliptic Curve (EC/ECDSA/ECDH)
%%------------------------------------------------------------------------------

%% Return the appropriate ECPrivateKey version value for the current OTP version
%% OTP 27: integer 1
%% OTP 28: atom ecPrivkeyVer1
ec_private_key_version() ->
    case is_otp_28_or_later() of
        true ->
            ecPrivkeyVer1;
        false ->
            1
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
    PrivKey = make_ec_private_key(PrivScalar, OID, PubPoint),
    PubKey = {{'ECPoint', PubPoint}, {namedCurve, CurveName}},
    {PrivKey, PubKey}.

%% Construct ECPrivateKey tuple compatible with both OTP 27 and OTP 28
make_ec_private_key(PrivScalar, OID, PubPoint) ->
    {'ECPrivateKey', ec_private_key_version(), PrivScalar, {namedCurve, OID}, PubPoint,
        asn1_NOVALUE}.

ec_coordinate_size(Curve) ->
    case Curve of
        p256 ->
            32;
        p384 ->
            48;
        p521 ->
            66;
        secp256k1 ->
            32
    end.

ec_private_key_from_bytes(Curve, PrivateScalar) ->
    ExpectedSize = ec_coordinate_size(Curve),
    case normalize_ec_scalar(PrivateScalar, ExpectedSize) of
        {ok, NormalizedScalar} ->
            try
                CurveName = ec_curve_name(Curve),
                OID = curve_to_oid(CurveName),
                {PublicPoint, _} = crypto:generate_key(ecdh, CurveName, NormalizedScalar),
                PrivKey = make_ec_private_key(NormalizedScalar, OID, PublicPoint),
                PubKey = {{'ECPoint', PublicPoint}, {namedCurve, CurveName}},
                {ok, {PrivKey, PubKey}}
            catch
                _:_ ->
                    {error, nil}
            end;
        error ->
            {error, nil}
    end.

%% Normalize EC scalar to expected size, handling DER integer encoding
normalize_ec_scalar(Scalar, ExpectedSize) ->
    ActualSize = byte_size(Scalar),
    if
        ActualSize =:= 0 ->
            %% Empty scalar is invalid
            error;
        ActualSize =:= ExpectedSize ->
            {ok, Scalar};
        ActualSize =:= ExpectedSize + 1 ->
            %% May have leading 0x00 for DER sign byte
            case Scalar of
                <<0, Rest/binary>> ->
                    {ok, Rest};
                _ ->
                    error
            end;
        ActualSize < ExpectedSize ->
            %% Pad with leading zeros
            PadSize = ExpectedSize - ActualSize,
            {ok, <<0:PadSize/unit:8, Scalar/binary>>};
        true ->
            error
    end.

ec_private_key_to_bytes(#'ECPrivateKey'{privateKey = PrivateScalar}) ->
    PrivateScalar.

ec_public_key_from_x509(DerBytes) ->
    try
        #'SubjectPublicKeyInfo'{algorithm = AlgId, subjectPublicKey = PublicKeyBits} =
            public_key:der_decode('SubjectPublicKeyInfo', DerBytes),
        #'AlgorithmIdentifier'{parameters = {namedCurve, OID}} = AlgId,
        CurveName = oid_to_curve(OID),
        {ok, {{'ECPoint', PublicKeyBits}, {namedCurve, CurveName}}}
    catch
        _:_ ->
            {error, nil}
    end.

ec_public_key_from_raw_point(Curve, Point) ->
    try
        CurveName = ec_curve_name(Curve),
        CoordSize = kryptos@ec:coordinate_size(Curve),
        case Point of
            <<16#04, _X:CoordSize/binary, _Y:CoordSize/binary>> ->
                validate_ec_point(CurveName, Point);
            _ ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

validate_ec_point(CurveName, Point) ->
    try
        {_TempPub, TempPriv} = crypto:generate_key(ecdh, CurveName),
        _ = crypto:compute_key(ecdh, Point, TempPriv, CurveName),
        {ok, {{'ECPoint', Point}, {namedCurve, CurveName}}}
    catch
        _:_ ->
            {error, nil}
    end.

ec_public_key_to_raw_point({{'ECPoint', <<4, _/binary>> = Point}, {namedCurve, _CurveName}}) ->
    Point;
ec_public_key_to_raw_point({{'ECPoint', <<Prefix, _/binary>> = Point}, {namedCurve, CurveName}}) when
    Prefix == 2; Prefix == 3
->
    ec_decompress_point(Point, CurveName).

ec_decompress_point(<<Prefix, XBin/binary>>, CurveName) ->
    {{prime_field, PBin}, {ABin, BBin, _}, _, _, _} = crypto:ec_curve(CurveName),
    X = binary:decode_unsigned(XBin),
    P = binary:decode_unsigned(PBin),
    A = binary:decode_unsigned(ABin),
    B = binary:decode_unsigned(BBin),
    X3 = binary:decode_unsigned(
        crypto:mod_pow(X, 3, P)
    ),
    % y² = x³ + ax + b (mod p)
    Y2 = (X3 + A * X + B) rem P,
    % For p ≡ 3 (mod 4), sqrt(a) = a^((p+1)/4) mod p
    Y = binary:decode_unsigned(
        crypto:mod_pow(Y2, (P + 1) div 4, P)
    ),
    YFinal =
        case (Y rem 2 == 0) == (Prefix == 2) of
            true ->
                Y;
            false ->
                P - Y
        end,
    CoordSize = byte_size(XBin),
    YBin = pad_to_size(binary:encode_unsigned(YFinal), CoordSize),
    <<4, XBin/binary, YBin/binary>>.

pad_to_size(Bin, Size) when byte_size(Bin) >= Size ->
    Bin;
pad_to_size(Bin, Size) ->
    PadSize = Size - byte_size(Bin),
    <<0:(PadSize * 8), Bin/binary>>.

ec_public_key_from_private(#'ECPrivateKey'{
    parameters = {namedCurve, CurveOID},
    publicKey = PublicPoint
}) ->
    CurveName = oid_to_curve(CurveOID),
    {{'ECPoint', PublicPoint}, {namedCurve, CurveName}}.

ec_private_key_curve(#'ECPrivateKey'{parameters = {namedCurve, CurveOID}}) ->
    erlang_ec_curve_to_gleam(oid_to_curve(CurveOID)).

ec_public_key_curve({{'ECPoint', _}, {namedCurve, CurveName}}) ->
    erlang_ec_curve_to_gleam(CurveName).

erlang_ec_curve_to_gleam(secp256r1) ->
    p256;
erlang_ec_curve_to_gleam(secp384r1) ->
    p384;
erlang_ec_curve_to_gleam(secp521r1) ->
    p521;
erlang_ec_curve_to_gleam(secp256k1) ->
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

ecdh_compute_shared_secret(PrivateKey, PeerPublicKey) ->
    try
        {{'ECPoint', PeerPoint}, {namedCurve, PeerCurveName}} = PeerPublicKey,
        #'ECPrivateKey'{privateKey = PrivateScalar, parameters = {namedCurve, PrivateOID}} =
            PrivateKey,
        ExpectedOID = curve_to_oid(PeerCurveName),
        case PrivateOID =:= ExpectedOID of
            false ->
                {error, nil};
            true ->
                SharedSecret = crypto:compute_key(ecdh, PeerPoint, PrivateScalar, PeerCurveName),
                {ok, SharedSecret}
        end
    catch
        _:_ ->
            {error, nil}
    end.

%% EC Import Functions

ec_import_private_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'PrivateKeyInfo', DerBytes, not_encrypted}] ->
                ec_import_private_key_from_der(DerBytes);
            _ ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

ec_import_private_key_der(DerBytes) ->
    try
        ec_import_private_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, nil}
    end.

ec_import_private_key_from_der(DerBytes) ->
    %% der_decode returns ECPrivateKey tuple
    %% OTP 27/28: {'ECPrivateKey', Version, PrivScalar, {namedCurve, OID}, PubPoint, asn1_NOVALUE}
    case public_key:der_decode('PrivateKeyInfo', DerBytes) of
        {'ECPrivateKey', _, PrivateScalar, {namedCurve, CurveOID}, PublicPoint, _} ->
            CurveName = oid_to_curve(CurveOID),
            PrivKey = make_ec_private_key(PrivateScalar, CurveOID, PublicPoint),
            PubKey = {{'ECPoint', PublicPoint}, {namedCurve, CurveName}},
            {ok, {PrivKey, PubKey}};
        _ ->
            {error, nil}
    end.

ec_import_public_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'SubjectPublicKeyInfo', DerBytes, not_encrypted}] ->
                ec_import_public_key_from_der(DerBytes);
            _ ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

ec_import_public_key_der(DerBytes) ->
    try
        ec_import_public_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, nil}
    end.

ec_import_public_key_from_der(DerBytes) ->
    %% SubjectPublicKeyInfo structure:
    %% {'SubjectPublicKeyInfo', {'AlgorithmIdentifier', Algorithm, Parameters}, PublicKeyBits}
    %% Parameters format differs between OTP versions:
    %%   OTP 27: raw DER bytes
    %%   OTP 28: {namedCurve, OID} tuple
    case public_key:der_decode('SubjectPublicKeyInfo', DerBytes) of
        {'SubjectPublicKeyInfo', {'AlgorithmIdentifier', ?'id-ecPublicKey', Params}, PublicKeyBits} ->
            case extract_ec_curve_oid(Params) of
                {ok, OID} ->
                    CurveName = oid_to_curve(OID),
                    {ok, {{'ECPoint', PublicKeyBits}, {namedCurve, CurveName}}};
                error ->
                    {error, nil}
            end;
        _ ->
            {error, nil}
    end.

%% Extract curve OID from AlgorithmIdentifier parameters
%% OTP 27: raw DER-encoded OID bytes
%% OTP 28: {namedCurve, OID} tuple
extract_ec_curve_oid({namedCurve, OID}) ->
    {ok, OID};
extract_ec_curve_oid(DerBytes) when is_binary(DerBytes) ->
    %% OTP 27 returns raw DER bytes, decode the OID
    try
        OID = public_key:der_decode('EcpkParameters', DerBytes),
        case OID of
            {namedCurve, ActualOID} ->
                {ok, ActualOID};
            _ ->
                error
        end
    catch
        _:_ ->
            error
    end;
extract_ec_curve_oid(_) ->
    error.

%% EC Export Functions

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

%%------------------------------------------------------------------------------
%% X25519/X448 Key Exchange (XDH)
%%------------------------------------------------------------------------------

xdh_generate_key_pair(Curve) ->
    {PubKey, PrivKey} = crypto:generate_key(ecdh, Curve),
    {{PrivKey, Curve}, {PubKey, Curve}}.

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

xdh_private_key_to_bytes({PrivBytes, _Curve}) ->
    PrivBytes.

xdh_public_key_to_bytes({PubBytes, _Curve}) ->
    PubBytes.

xdh_public_key_from_private({PrivBytes, Curve}) ->
    {PubKey, _} = crypto:generate_key(ecdh, Curve, PrivBytes),
    {PubKey, Curve}.

xdh_private_key_curve({_PrivBytes, Curve}) ->
    Curve.

xdh_public_key_curve({_PubBytes, Curve}) ->
    Curve.

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

%% XDH Import Functions

xdh_import_private_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'PrivateKeyInfo', DerBytes, not_encrypted}] ->
                xdh_import_private_key_from_der(DerBytes);
            _ ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

xdh_import_private_key_der(DerBytes) ->
    try
        xdh_import_private_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, nil}
    end.

xdh_import_private_key_from_der(DerBytes) ->
    %% der_decode returns tuples, not records
    %% OTP 27: 5-tuple with 'PrivateKeyInfo_privateKeyAlgorithm'
    %% OTP 28: 6-tuple with 'PrivateKeyAlgorithmIdentifier'
    case public_key:der_decode('PrivateKeyInfo', DerBytes) of
        {'PrivateKeyInfo', _, {_, OID, _}, WrappedKey, _} ->
            %% OTP 27 format (5-tuple)
            xdh_import_from_decoded(OID, WrappedKey);
        {'PrivateKeyInfo', _, {_, OID, _}, WrappedKey, _, _} ->
            %% OTP 28 format (6-tuple)
            xdh_import_from_decoded(OID, WrappedKey);
        _ ->
            {error, nil}
    end.

xdh_import_from_decoded(OID, WrappedKey) ->
    Curve = oid_to_curve(OID),
    case Curve of
        _ when Curve =:= x25519; Curve =:= x448 ->
            KeySize = kryptos@xdh:key_size(Curve),
            case WrappedKey of
                <<4, KeySize, PrivateBytes:KeySize/binary>> ->
                    {PubKey, PrivKey} = crypto:generate_key(ecdh, Curve, PrivateBytes),
                    {ok, {{PrivKey, Curve}, {PubKey, Curve}}};
                _ ->
                    {error, nil}
            end;
        _ ->
            {error, nil}
    end.

xdh_import_public_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'SubjectPublicKeyInfo', DerBytes, not_encrypted}] ->
                xdh_import_public_key_from_der(DerBytes);
            _ ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

xdh_import_public_key_der(DerBytes) ->
    try
        xdh_import_public_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, nil}
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
                    {error, nil}
            end;
        _ ->
            {error, nil}
    end.

%% XDH Export Functions

xdh_export_private_key_pem({KeyBytes, Curve}) ->
    try
        Der = xdh_private_key_to_der(KeyBytes, Curve),
        {ok, public_key:pem_encode([{'PrivateKeyInfo', Der, not_encrypted}])}
    catch
        _:_ ->
            {error, nil}
    end.

xdh_export_private_key_der({KeyBytes, Curve}) ->
    try
        {ok, xdh_private_key_to_der(KeyBytes, Curve)}
    catch
        _:_ ->
            {error, nil}
    end.

xdh_private_key_to_der(KeyBytes, Curve) ->
    KeySize = kryptos@xdh:key_size(Curve),
    WrappedKey = <<4, KeySize, KeyBytes/binary>>,
    OID = curve_to_oid(Curve),
    AlgId = {'AlgorithmIdentifier', OID, asn1_NOVALUE},
    PrivKeyInfo =
        case is_otp_28_or_later() of
            true ->
                %% OTP 28+: 6-tuple OneAsymmetricKey format
                {'OneAsymmetricKey', 0, AlgId, WrappedKey, asn1_NOVALUE, asn1_NOVALUE};
            false ->
                %% OTP 27: 5-tuple PrivateKeyInfo format
                {'PrivateKeyInfo', v1, AlgId, WrappedKey, asn1_NOVALUE}
        end,
    public_key:der_encode('PrivateKeyInfo', PrivKeyInfo).

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

%%------------------------------------------------------------------------------
%% RSA
%%------------------------------------------------------------------------------

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

rsa_generate_key_pair(Bits) ->
    {PubKey, PrivKey} = crypto:generate_key(rsa, {Bits, 65537}),
    {rsa_build_private_key(PrivKey), rsa_build_public_key(PubKey)}.

rsa_public_key_from_private(PrivKey) ->
    #'RSAPublicKey'{
        modulus = PrivKey#'RSAPrivateKey'.modulus,
        publicExponent = PrivKey#'RSAPrivateKey'.publicExponent
    }.

rsa_private_key_modulus_bits(#'RSAPrivateKey'{modulus = N}) ->
    bit_size(binary:encode_unsigned(N)).

rsa_public_key_modulus_bits(#'RSAPublicKey'{modulus = N}) ->
    bit_size(binary:encode_unsigned(N)).

rsa_private_key_public_exponent(#'RSAPrivateKey'{publicExponent = E}) ->
    E.

rsa_public_key_public_exponent(#'RSAPublicKey'{publicExponent = E}) ->
    E.

rsa_private_key_modulus(#'RSAPrivateKey'{modulus = N}) ->
    binary:encode_unsigned(N).

rsa_public_key_modulus(#'RSAPublicKey'{modulus = N}) ->
    binary:encode_unsigned(N).

rsa_private_key_public_exponent_bytes(#'RSAPrivateKey'{publicExponent = E}) ->
    binary:encode_unsigned(E).

rsa_public_key_exponent_bytes(#'RSAPublicKey'{publicExponent = E}) ->
    binary:encode_unsigned(E).

rsa_private_key_private_exponent_bytes(#'RSAPrivateKey'{privateExponent = D}) ->
    binary:encode_unsigned(D).

rsa_private_key_prime1(#'RSAPrivateKey'{prime1 = P}) ->
    binary:encode_unsigned(P).

rsa_private_key_prime2(#'RSAPrivateKey'{prime2 = Q}) ->
    binary:encode_unsigned(Q).

rsa_private_key_exponent1(#'RSAPrivateKey'{exponent1 = DP}) ->
    binary:encode_unsigned(DP).

rsa_private_key_exponent2(#'RSAPrivateKey'{exponent2 = DQ}) ->
    binary:encode_unsigned(DQ).

rsa_private_key_coefficient(#'RSAPrivateKey'{coefficient = QI}) ->
    binary:encode_unsigned(QI).

rsa_public_key_from_components(N, E) ->
    try
        NInt = bin_to_int(N),
        EInt = bin_to_int(E),
        case NInt > 1 andalso EInt > 1 andalso EInt < NInt of
            true ->
                {ok, #'RSAPublicKey'{modulus = NInt, publicExponent = EInt}};
            false ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

mod_pow(Base, Exp, Mod) ->
    crypto:mod_pow(bin_to_int(Base), bin_to_int(Exp), bin_to_int(Mod)).

rsa_private_key_from_full_components(N, E, D, P, Q, DP, DQ, QI) ->
    try
        NInt = bin_to_int(N),
        EInt = bin_to_int(E),
        DInt = bin_to_int(D),
        PInt = bin_to_int(P),
        QInt = bin_to_int(Q),
        DPInt = bin_to_int(DP),
        DQInt = bin_to_int(DQ),
        QIInt = bin_to_int(QI),
        case NInt > 1 andalso EInt > 1 andalso EInt < NInt andalso PInt * QInt =:= NInt of
            true ->
                PrivKey =
                    #'RSAPrivateKey'{
                        version = 'two-prime',
                        modulus = NInt,
                        publicExponent = EInt,
                        privateExponent = DInt,
                        prime1 = PInt,
                        prime2 = QInt,
                        exponent1 = DPInt,
                        exponent2 = DQInt,
                        coefficient = QIInt
                    },
                PubKey = #'RSAPublicKey'{modulus = NInt, publicExponent = EInt},
                {ok, {PrivKey, PubKey}};
            false ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

%% RSA Signing

rsa_pss_salt_length(salt_length_hash_len) ->
    -1;
rsa_pss_salt_length(salt_length_max) ->
    -2;
rsa_pss_salt_length({salt_length_explicit, Length}) ->
    Length.

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

%% RSA Encryption

rsa_encrypt_padding_opts(encrypt_pkcs1v15) ->
    [{rsa_padding, rsa_pkcs1_padding}];
rsa_encrypt_padding_opts(#oaep{hash = Hash, label = Label}) ->
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

%% RSA Import Functions

rsa_private_format_types(pkcs8) ->
    {'PrivateKeyInfo', 'PrivateKeyInfo'};
rsa_private_format_types(pkcs1) ->
    {'RSAPrivateKey', 'RSAPrivateKey'}.

rsa_public_format_types(spki) ->
    {'SubjectPublicKeyInfo', spki};
rsa_public_format_types(rsa_public_key) ->
    {'RSAPublicKey', rsa_public_key}.

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
        #'SubjectPublicKeyInfo'{
            algorithm = #'AlgorithmIdentifier'{algorithm = ?rsaEncryption},
            subjectPublicKey = PublicKeyDer
        } =
            public_key:der_decode('SubjectPublicKeyInfo', DerBytes),
        RSAPubKey = public_key:der_decode('RSAPublicKey', PublicKeyDer),
        {ok, RSAPubKey}
    catch
        _:_ ->
            {error, nil}
    end.

rsa_import_private_key_pem(PemData, Format) ->
    try
        {PemType, DerType} = rsa_private_format_types(Format),
        case public_key:pem_decode(PemData) of
            [{PemType, DerBytes, not_encrypted}] ->
                rsa_import_private_key_from_der(DerBytes, DerType);
            _ ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

rsa_import_private_key_der(DerBytes, Format) ->
    try
        {_, DerType} = rsa_private_format_types(Format),
        rsa_import_private_key_from_der(DerBytes, DerType)
    catch
        _:_ ->
            {error, nil}
    end.

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
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

rsa_import_public_key_der(DerBytes, Format) ->
    try
        rsa_import_public_key_from_der(DerBytes, Format)
    catch
        _:_ ->
            {error, nil}
    end.

rsa_import_public_key_from_der(DerBytes, spki) ->
    #'SubjectPublicKeyInfo'{
        algorithm = #'AlgorithmIdentifier'{algorithm = ?rsaEncryption},
        subjectPublicKey = PublicKeyDer
    } =
        public_key:der_decode('SubjectPublicKeyInfo', DerBytes),
    RSAPubKey = public_key:der_decode('RSAPublicKey', PublicKeyDer),
    {ok, RSAPubKey};
rsa_import_public_key_from_der(DerBytes, rsa_public_key) ->
    RSAPubKey = public_key:der_decode('RSAPublicKey', DerBytes),
    {ok, RSAPubKey}.

%% RSA Export Functions

rsa_private_pem_type(pkcs8) ->
    'PrivateKeyInfo';
rsa_private_pem_type(pkcs1) ->
    'RSAPrivateKey'.

rsa_public_pem_type(spki) ->
    'SubjectPublicKeyInfo';
rsa_public_pem_type(rsa_public_key) ->
    'RSAPublicKey'.

rsa_private_key_to_der(Key, pkcs8) ->
    {'PrivateKeyInfo', Der, not_encrypted} =
        public_key:pem_entry_encode('PrivateKeyInfo', Key),
    Der;
rsa_private_key_to_der(Key, pkcs1) ->
    public_key:der_encode('RSAPrivateKey', Key).

rsa_public_key_to_der(Key, spki) ->
    {'SubjectPublicKeyInfo', Der, not_encrypted} =
        public_key:pem_entry_encode('SubjectPublicKeyInfo', Key),
    Der;
rsa_public_key_to_der(Key, rsa_public_key) ->
    public_key:der_encode('RSAPublicKey', Key).

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

%%------------------------------------------------------------------------------
%% EdDSA (Ed25519/Ed448)
%%------------------------------------------------------------------------------

eddsa_generate_key_pair(Curve) ->
    {PubKey, PrivKey} = crypto:generate_key(eddsa, Curve),
    {{PrivKey, Curve}, {PubKey, Curve}}.

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

eddsa_private_key_to_bytes({PrivBytes, _Curve}) ->
    PrivBytes.

eddsa_public_key_to_bytes({PubBytes, _Curve}) ->
    PubBytes.

eddsa_public_key_from_private({PrivBytes, Curve}) ->
    {PubKey, _} = crypto:generate_key(eddsa, Curve, PrivBytes),
    {PubKey, Curve}.

eddsa_private_key_curve({_PrivBytes, Curve}) ->
    Curve.

eddsa_public_key_curve({_PubBytes, Curve}) ->
    Curve.

eddsa_sign({PrivKey, Curve}, Message) ->
    crypto:sign(eddsa, none, Message, [PrivKey, Curve]).

eddsa_verify({PubKey, Curve}, Message, Signature) ->
    try
        crypto:verify(eddsa, none, Message, Signature, [PubKey, Curve])
    catch
        _:_ ->
            false
    end.

%% EdDSA Import Functions

eddsa_import_private_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'PrivateKeyInfo', DerBytes, not_encrypted}] ->
                eddsa_import_private_key_from_der(DerBytes);
            _ ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_import_private_key_der(DerBytes) ->
    try
        eddsa_import_private_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_import_private_key_from_der(DerBytes) ->
    case public_key:der_decode('PrivateKeyInfo', DerBytes) of
        {'PrivateKeyInfo', _, {_, OID, _}, WrappedKey, _} ->
            eddsa_import_from_decoded(OID, WrappedKey);
        {'PrivateKeyInfo', _, {_, OID, _}, WrappedKey, _, _} ->
            eddsa_import_from_decoded(OID, WrappedKey);
        #'ECPrivateKey'{privateKey = PrivateBytes, parameters = {namedCurve, OID}} ->
            Curve = oid_to_curve(OID),
            case Curve of
                _ when Curve =:= ed25519; Curve =:= ed448 ->
                    {PubKey, PrivKey} = crypto:generate_key(eddsa, Curve, PrivateBytes),
                    {ok, {{PrivKey, Curve}, {PubKey, Curve}}};
                _ ->
                    {error, nil}
            end;
        _ ->
            {error, nil}
    end.

eddsa_import_from_decoded(OID, WrappedKey) ->
    Curve = oid_to_curve(OID),
    case Curve of
        _ when Curve =:= ed25519; Curve =:= ed448 ->
            KeySize = kryptos@eddsa:key_size(Curve),
            case WrappedKey of
                <<4, KeySize, PrivateBytes:KeySize/binary>> ->
                    {PubKey, PrivKey} = crypto:generate_key(eddsa, Curve, PrivateBytes),
                    {ok, {{PrivKey, Curve}, {PubKey, Curve}}};
                _ ->
                    {error, nil}
            end;
        _ ->
            {error, nil}
    end.

eddsa_import_public_key_pem(PemData) ->
    try
        case public_key:pem_decode(PemData) of
            [{'SubjectPublicKeyInfo', DerBytes, not_encrypted}] ->
                eddsa_import_public_key_from_der(DerBytes);
            _ ->
                {error, nil}
        end
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_import_public_key_der(DerBytes) ->
    try
        eddsa_import_public_key_from_der(DerBytes)
    catch
        _:_ ->
            {error, nil}
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
                    {error, nil}
            end;
        _ ->
            {error, nil}
    end.

%% EdDSA Export Functions

eddsa_export_private_key_pem({KeyBytes, Curve}) ->
    try
        Der = eddsa_private_key_to_der(KeyBytes, Curve),
        {ok, public_key:pem_encode([{'PrivateKeyInfo', Der, not_encrypted}])}
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_export_private_key_der({KeyBytes, Curve}) ->
    try
        {ok, eddsa_private_key_to_der(KeyBytes, Curve)}
    catch
        _:_ ->
            {error, nil}
    end.

eddsa_private_key_to_der(KeyBytes, Curve) ->
    KeySize = kryptos@eddsa:key_size(Curve),
    WrappedKey = <<4, KeySize, KeyBytes/binary>>,
    OID = curve_to_oid(Curve),
    AlgId = {'AlgorithmIdentifier', OID, asn1_NOVALUE},
    PrivKeyInfo =
        case is_otp_28_or_later() of
            true ->
                {'OneAsymmetricKey', 0, AlgId, WrappedKey, asn1_NOVALUE, asn1_NOVALUE};
            false ->
                {'PrivateKeyInfo', v1, AlgId, WrappedKey, asn1_NOVALUE}
        end,
    public_key:der_encode('PrivateKeyInfo', PrivKeyInfo).

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
