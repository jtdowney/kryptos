# kryptos

[![Package Version](https://img.shields.io/hexpm/v/kryptos)](https://hex.pm/packages/kryptos)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/kryptos/)

Kyrptos is a library for cryptography in Gleam that wraps the Erlang and Node.js cryptography APIs. The goal is to provide a complete basic cryptography library in Gleam, while being able to still target as many platforms as possible. The API is loosely inspired by the Go cryptography library.

## Project Goals

1. Target both Erlang and Node.js
2. Provide a clear API with misuse resistance where possible
3. Pass [wycheproof](https://github.com/C2SP/wycheproof) test vectors for supported APIs
