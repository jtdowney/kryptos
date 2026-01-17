test-erlang:
    gleam test --target erlang

test-javascript:
    gleam test --target javascript

test: test-erlang test-javascript

test-erlang-wycheproof:
    gleam test --target erlang -- --tag wycheproof

test-javascript-wycheproof:
    gleam test --target javascript -- --tag wycheproof

test-wycheproof: test-erlang-wycheproof test-javascript-wycheproof

test-all: test test-wycheproof
