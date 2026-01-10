# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.y   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

To report a security vulnerability, please use [GitHub Security Advisories](https://github.com/jtdowney/kryptos/security/advisories/new).

**Please do not report security vulnerabilities through public GitHub issues.**

When reporting, include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

You can expect an initial response within 48 hours. We will work with you to understand the issue and coordinate disclosure.

## Security Model

Kryptos is a **wrapper library** that delegates all cryptographic operations to platform-native implementations:

- **Erlang target**: OTP `:crypto` and `:public_key` modules (OpenSSL/LibreSSL)
- **JavaScript target**: Node.js `crypto` module (OpenSSL)

This library does not implement any cryptographic primitives itself. Security depends on the underlying platform implementations being correct and up to date.

## Algorithm Guidance

### Recommended Algorithms

| Use Case             | Recommended                              |
| -------------------- | ---------------------------------------- |
| Hashing              | SHA-256, SHA-384, SHA-512, SHA3-256      |
| HMAC                 | HMAC-SHA-256 or stronger                 |
| Key Derivation       | HKDF                                     |
| Symmetric Encryption | AES-GCM, ChaCha20-Poly1305               |
| Signing              | EdDSA (Ed25519), ECDSA (P-256+), RSA-PSS |
| Encryption           | RSA-OAEP                                 |
| Key Agreement        | X25519, ECDH (P-256+)                    |

### Legacy Algorithms (Use with Caution)

The following are included for compatibility with existing systems but are not recommended for new applications:

- **MD5, SHA-1**: Cryptographically broken for collision resistance
- **AES-ECB**: Leaks patterns in plaintext
- **AES-CBC, AES-CTR**: No authentication; use AEAD modes instead
- **RSA PKCS#1 v1.5 encryption**: Vulnerable to padding oracle attacks
- **RSA PKCS#1 v1.5 signing**: Less robust than PSS

## Runtime Requirements

### Node.js

**Recommended: Node.js 22 or later**

Node.js 20.x has a known vulnerability ([CVE-2023-46809](https://nvd.nist.gov/vuln/detail/CVE-2023-46809)) affecting RSA PKCS#1 v1.5 decryption (Marvin attack). This library disables PKCS#1 v1.5 decryption on affected versions.

### Erlang/OTP

Use a currently supported OTP version with up-to-date OpenSSL/LibreSSL.
