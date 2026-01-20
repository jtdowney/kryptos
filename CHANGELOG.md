# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-01-19

### Added

#### Key Derivation

- Concat KDF (NIST SP 800-56A) for key derivation

#### Digital Signatures

- ECDSA R||S format support with DER conversion utilities

### Changed

- Made `BlockCipher`, `CipherContext`, and `AeadContext` opaque types for better encapsulation

## [1.1.0] - 2026-01-16

### Added

#### Authenticated Encryption

- XChaCha20-Poly1305 with extended 192-bit nonces

#### Key Management

- AES Key Wrap (RFC 3394) for secure key encapsulation
- Key introspection methods for all key types
- RSA CRT parameter computation for private keys
- EC key introspection (curve parameters, public point coordinates)

### Changed

- Migrated tests to qcheck property-based testing
- Wycheproof tests now tagged and excluded from default test runs
- Erlang FFI refactored to use Gleam-generated .hrl records

## [1.0.0] - 2026-01-09

### Added

#### Hash Functions

- SHA-1, SHA-256, SHA-384, SHA-512
- SHA-512/224, SHA-512/256
- SHA3-224, SHA3-256, SHA3-384, SHA3-512
- BLAKE2b, BLAKE2s
- Streaming API with `new`/`update`/`final`

#### Message Authentication

- HMAC with all supported hash algorithms
- Incremental and one-shot APIs
- Constant-time verification with `verify`

#### Key Derivation

- HKDF (RFC 5869) with extract-expand pattern
- PBKDF2 (RFC 8018) with configurable iterations

#### Authenticated Encryption (AEAD)

- AES-GCM (128, 192, 256-bit keys)
- AES-CCM (RFC 3610) with configurable nonce and tag sizes
- ChaCha20-Poly1305 (RFC 8439)

#### Block Ciphers

- AES in ECB, CBC, and CTR modes
- PKCS7 padding support for CBC mode

#### Elliptic Curve Cryptography

- ECDSA signing and verification (P-256, P-384, P-521, secp256k1)
- ECDH key agreement
- EC point import/export (compressed and uncompressed SEC1 format)
- Multiple hash algorithm support for signatures

#### Edwards Curve Cryptography

- EdDSA signing and verification (Ed25519, Ed448)
- Deterministic signatures (no nonce required)
- Key import/export in raw bytes and PEM formats

#### Montgomery Curve Cryptography

- XDH key agreement (X25519, X448)
- Key import/export in ASN.1/DER/PEM formats
- Low-order point validation

#### RSA Cryptography

- RSA-PSS signing with configurable salt length
- RSA PKCS#1 v1.5 signing (legacy support)
- RSA-OAEP encryption with configurable hash and MGF
- RSA PKCS#1 v1.5 encryption (legacy support)
- Key generation and PEM import/export

#### Utilities

- Cryptographically secure random byte generation
- Constant-time byte comparison
- UUID v4 generation

#### Platform Support

- Dual runtime support (Erlang and JavaScript)
- Erlang target wraps OTP `:crypto` and `:public_key` modules
- JavaScript target wraps Node.js `crypto` module

#### Testing

- Wycheproof test vector validation for ECDSA, AES-GCM, AES-CBC, ChaCha20-Poly1305, XDH, and ECDH

[1.2.0]: https://github.com/jtdowney/kryptos/releases/tag/v1.2.0
[1.1.0]: https://github.com/jtdowney/kryptos/releases/tag/v1.1.0
[1.0.0]: https://github.com/jtdowney/kryptos/releases/tag/v1.0.0
