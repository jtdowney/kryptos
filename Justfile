test-erlang:
    gleam test --target erlang

test-javascript:
    gleam test --target javascript

test: test-erlang test-javascript
