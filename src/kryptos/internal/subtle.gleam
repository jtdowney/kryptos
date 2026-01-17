//// Internal constant-time utilities.
////
//// Provides timing-safe operations to prevent side-channel attacks when
//// comparing sensitive data like authentication tags and MACs.

@external(erlang, "kryptos_ffi", "constant_time_equal")
@external(javascript, "../../kryptos_ffi.mjs", "constantTimeEqual")
pub fn constant_time_equal(a: BitArray, b: BitArray) -> Bool
