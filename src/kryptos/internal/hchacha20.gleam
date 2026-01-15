//// Internal HChaCha20 implementation for XChaCha20-Poly1305.
////
//// HChaCha20 derives a 256-bit subkey from a 256-bit key and 128-bit input.
//// It uses the ChaCha20 quarter-round function but outputs different words.

import gleam/int

/// HChaCha20 key derivation function.
/// Takes a 32-byte key and 16-byte input, returns 32-byte subkey.
pub fn subkey(key: BitArray, input: BitArray) -> BitArray {
  // Parse key as 8 little-endian 32-bit words
  let assert <<
    k0:32-little-unsigned,
    k1:32-little-unsigned,
    k2:32-little-unsigned,
    k3:32-little-unsigned,
    k4:32-little-unsigned,
    k5:32-little-unsigned,
    k6:32-little-unsigned,
    k7:32-little-unsigned,
  >> = key

  // Parse input as 4 little-endian 32-bit words
  let assert <<
    n0:32-little-unsigned,
    n1:32-little-unsigned,
    n2:32-little-unsigned,
    n3:32-little-unsigned,
  >> = input

  // Initialize state with ChaCha20 constants, key, and input
  // Constants: "expand 32-byte k" in little-endian
  let state =
    State(
      s0: 0x61707865,
      s1: 0x3320646E,
      s2: 0x79622D32,
      s3: 0x6B206574,
      s4: k0,
      s5: k1,
      s6: k2,
      s7: k3,
      s8: k4,
      s9: k5,
      s10: k6,
      s11: k7,
      s12: n0,
      s13: n1,
      s14: n2,
      s15: n3,
    )

  // Perform 20 rounds (10 double-rounds)
  let state = perform_rounds(state, 10)

  // Return words 0-3 and 12-15 as the 32-byte subkey
  <<
    state.s0:32-little,
    state.s1:32-little,
    state.s2:32-little,
    state.s3:32-little,
    state.s12:32-little,
    state.s13:32-little,
    state.s14:32-little,
    state.s15:32-little,
  >>
}

type State {
  State(
    s0: Int,
    s1: Int,
    s2: Int,
    s3: Int,
    s4: Int,
    s5: Int,
    s6: Int,
    s7: Int,
    s8: Int,
    s9: Int,
    s10: Int,
    s11: Int,
    s12: Int,
    s13: Int,
    s14: Int,
    s15: Int,
  )
}

fn perform_rounds(state: State, remaining: Int) -> State {
  case remaining <= 0 {
    True -> state
    False -> {
      // Column round: QR(0,4,8,12), QR(1,5,9,13), QR(2,6,10,14), QR(3,7,11,15)
      let #(s0, s4, s8, s12) =
        quarter_round(state.s0, state.s4, state.s8, state.s12)
      let #(s1, s5, s9, s13) =
        quarter_round(state.s1, state.s5, state.s9, state.s13)
      let #(s2, s6, s10, s14) =
        quarter_round(state.s2, state.s6, state.s10, state.s14)
      let #(s3, s7, s11, s15) =
        quarter_round(state.s3, state.s7, state.s11, state.s15)

      // Diagonal round: QR(0,5,10,15), QR(1,6,11,12), QR(2,7,8,13), QR(3,4,9,14)
      let #(s0, s5, s10, s15) = quarter_round(s0, s5, s10, s15)
      let #(s1, s6, s11, s12) = quarter_round(s1, s6, s11, s12)
      let #(s2, s7, s8, s13) = quarter_round(s2, s7, s8, s13)
      let #(s3, s4, s9, s14) = quarter_round(s3, s4, s9, s14)

      let state =
        State(
          s0:,
          s1:,
          s2:,
          s3:,
          s4:,
          s5:,
          s6:,
          s7:,
          s8:,
          s9:,
          s10:,
          s11:,
          s12:,
          s13:,
          s14:,
          s15:,
        )
      perform_rounds(state, remaining - 1)
    }
  }
}

/// The ChaCha20 quarter-round function.
/// Operates on 4 32-bit words in the state.
fn quarter_round(a: Int, b: Int, c: Int, d: Int) -> #(Int, Int, Int, Int) {
  // a += b; d ^= a; d <<<= 16;
  let a = add32(a, b)
  let d = rotl32(int.bitwise_exclusive_or(d, a), 16)

  // c += d; b ^= c; b <<<= 12;
  let c = add32(c, d)
  let b = rotl32(int.bitwise_exclusive_or(b, c), 12)

  // a += b; d ^= a; d <<<= 8;
  let a = add32(a, b)
  let d = rotl32(int.bitwise_exclusive_or(d, a), 8)

  // c += d; b ^= c; b <<<= 7;
  let c = add32(c, d)
  let b = rotl32(int.bitwise_exclusive_or(b, c), 7)

  #(a, b, c, d)
}

fn add32(a: Int, b: Int) -> Int {
  int.bitwise_and(a + b, 0xFFFFFFFF)
}

fn rotl32(x: Int, n: Int) -> Int {
  let shifted_left = int.bitwise_shift_left(x, n)
  let shifted_right = int.bitwise_shift_right(x, 32 - n)
  int.bitwise_and(int.bitwise_or(shifted_left, shifted_right), 0xFFFFFFFF)
}
