# kryptos

[![Package Version](https://img.shields.io/hexpm/v/kryptos)](https://hex.pm/packages/kryptos)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/kryptos/)

<p align="right">
  <img src="assets/kryptos.png" alt="kryptos logo" width="200">
</p>

A cryptography library for Gleam targeting both Erlang and JavaScript runtimes.

## Why kryptos?

- **Dual-runtime support** — Works on both Erlang and JavaScript (Node.js),
  wrapping each platform's native crypto APIs for consistent behavior.
- **No custom cryptography** — All cryptographic operations delegate to the
  runtime's battle-tested implementations (Erlang's `crypto` module,
  Node.js `crypto` module). This library is a wrapper, not a reimplementation.
- **Misuse-resistant API** — Inspired by Go's crypto library, the API guides
  you toward safe defaults and makes dangerous operations explicit.
- **Tested against Wycheproof** — Validated against Google's
  [Wycheproof](https://github.com/C2SP/wycheproof) test vectors to catch
  edge-case vulnerabilities.

## Installation

```sh
gleam add kryptos
```

## Features

| Module                                                   | Algorithms                                     |
| -------------------------------------------------------- | ---------------------------------------------- |
| [hash](https://hexdocs.pm/kryptos/kryptos/hash.html)     | SHA-1, SHA-2, SHA-3, BLAKE2                    |
| [hmac](https://hexdocs.pm/kryptos/kryptos/hmac.html)     | All hash algorithms                            |
| [aead](https://hexdocs.pm/kryptos/kryptos/aead.html)     | AES-GCM, AES-CCM, ChaCha20-Poly1305            |
| [block](https://hexdocs.pm/kryptos/kryptos/block.html)   | AES-128, AES-192, AES-256                      |
| [ecdsa](https://hexdocs.pm/kryptos/kryptos/ecdsa.html)   | P-256, P-384, P-521                            |
| [eddsa](https://hexdocs.pm/kryptos/kryptos/eddsa.html)   | Ed25519, Ed448                                 |
| [ecdh](https://hexdocs.pm/kryptos/kryptos/ecdh.html)     | P-256, P-384, P-521                            |
| [xdh](https://hexdocs.pm/kryptos/kryptos/xdh.html)       | X25519, X448                                   |
| [rsa](https://hexdocs.pm/kryptos/kryptos/rsa.html)       | OAEP, PKCS#1 v1.5, PSS, PKCS#1 v1.5 signatures |
| [crypto](https://hexdocs.pm/kryptos/kryptos/crypto.html) | HKDF, PBKDF2, random bytes                     |

## Getting Started

Encrypt and decrypt data using AES-GCM:

```gleam
import kryptos/aead
import kryptos/block
import kryptos/crypto

pub fn main() {
  // Generate a random 256-bit key
  let assert Ok(cipher) = block.aes_256(crypto.random_bytes(32))
  let ctx = aead.gcm(cipher)

  // Generate a random nonce (never reuse with the same key!)
  let nonce = crypto.random_bytes(aead.nonce_size(ctx))

  // Encrypt
  let plaintext = <<"hello, world!":utf8>>
  let assert Ok(#(ciphertext, tag)) = aead.seal(ctx, nonce:, plaintext:)

  // Decrypt
  let assert Ok(decrypted) = aead.open(ctx, nonce:, ciphertext:, tag:)
  // decrypted == plaintext
}
```

## Security

For guidance on choosing cryptographic primitives, see
[Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html).
