# How the Keccak Function Works Internally

## Table of Contents

- [Introduction](#introduction)
  - [XOF Mode](#xof-mode)
  - [Indexing Convention within the Internal State Matrix](#indexing-convention-within-the-internal-state-matrix)
- [Internal Step Functions](#internal-step-functions)
  - [θ Theta](#θ-theta)
  - [ρ Rho](#ρ-rho)
  - [π Pi](#π-pi)
  - [χ Chi](#χ-chi)
  - [ι Iota](#ι-iota)

---

# Introduction

For this example, we will use SHA3 in drop-in replacement mode for SHA2.
This means that the internal state is always 1600 bits long and the required digest output size `d` may only be one of `224`, `256`, `384` or `512` bits.

This example will use `d = 256`; therefore, the rate will be:

```
rate = 1600 - 2 * d
     = 1600 - 2 * 256
     = 1088 bits
```

Steps 2 to 5 below describe the SHA3 absorb phase, and step 6 describes the squeeze phase.

1. To start with, the Keccak function's internal state is initialised to 200 bytes of `0x00`.

2. Consume `rate` bits from the input file/stream.
   If the input supplies less than `rate` bits, then pad the input data such that it fills a complete rate block as previously described.

3. XOR the input data with the data already present in the rate region of the internal state.

4. Perform 24 rounds of the Keccak function against the data in the internal state.

5. Did step 2 hit end of file?

   Nope - Goto step 2<br>Yup&nbsp; - Goto step 6

6. We're done - the required digest is the first `d` bits in the rate region of the internal state.

## XOF Mode

If we are running SHA3 in XOF mode, then once the absorb phase in steps 2-5 has completed, we need to output the requested number of bytes from the rate part of the internal state.

It is quite possible that we need to output more bytes than are contained in the rate, so in this case, we first output the entire rate, then rerun the Keccak function against the internal state to generate more data in the rate.

We keep running the Keccak function against the internal state until the required number of output bytes have been generated.

## Indexing Convention within the Internal State Matrix

This module follows the state array indexing convention described in section 3.1.4 of the NIST document.

![Indexing convention of internal state matrix](./indexing_convention.png)

The linear order of the data in expected test results starts in the bottom left corner `(3,3)` of the above matrix.

The array data then follows the order `(3,3), (4,3), (0,3), (1,3), (2,3)` followed by `(3,4), (4,4), (0,4), (1,4), (2,4)`, then `(3,0), (4,0), (0,0), (1,0), (2,0)` etc.

# Internal Step Functions

Internally, the Keccak function invokes a sequence of five step functions, each of which is identified with a Greek letter.
These functions are always executed in the following order:

* &theta; Theta
* &rho; Rho
* &pi; Pi
* &chi; Chi
* &iota; Iota

![Keccak Internals](./keccak_internals.png)

A sequence of calls to the Theta, Rho, Pi, Chi and Iota functions constitutes one round of the Keccak function.
24 Keccak rounds are always performed per block of data read into the internal state.

## &theta; Theta

Theta mixes each column of the state into every other column, ensuring that a change in any single lane eventually propagates to the entire state.
It is performed in three sub-steps:

1. **Theta-C**<br>For each column `x`, XOR all five lanes in that column down to a single `u64` parity value.

   ```rust
   fn theta_c(state: &[[u64; 5]; 5]) -> [u64; 5] {
       let mut c = [0u64; 5];
       for x in 0..5 {
           c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
       }
       c
   }
   ```

2. **Theta-D**<br>For each column `x`, XOR the parity of the column to the left `(x-1) mod 5` with the parity of the column to the right `(x+1) mod 5` rotated left by one bit.

   ```rust
   fn theta_d(c: &[u64; 5]) -> [u64; 5] {
       let mut d = [0u64; 5];
       for x in 0..5 {
           d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
       }
       d
   }
   ```

3. **Theta XOR**<br>XOR every lane `A[x,y]` with `D[x]` — the mixing value derived from column `x`.

   ```rust
   fn theta(state: &mut [[u64; 5]; 5]) {
       let c = theta_c(state);
       let d = theta_d(&c);
       for x in 0..5 {
           for y in 0..5 {
               state[x][y] ^= d[x];
           }
       }
   }
   ```

## &rho; Rho

Rho rotates each lane left by a fixed, position-dependent number of bits defined by FIPS 202 Table 2.
Lane `A[0,0]` is not rotated.
This step introduces diffusion in the bit-position dimension (`z`) of the state.

```rust
const RHO_OFFSETS: [[u32; 5]; 5] = [
//   y=0  y=1  y=2  y=3  y=4
    [  0,  36,   3,  41,  18 ],  // x=0
    [  1,  44,  10,  45,   2 ],  // x=1
    [ 62,   6,  43,  15,  61 ],  // x=2
    [ 28,  55,  25,  21,  56 ],  // x=3
    [ 27,  20,  39,   8,  14 ],  // x=4
];

fn rho(state: &mut [[u64; 5]; 5]) {
    for x in 0..5 {
        for y in 0..5 {
            state[x][y] = state[x][y].rotate_left(RHO_OFFSETS[x][y]);
        }
    }
}
```

## &pi; Pi

Pi rearranges the lanes according to a fixed permutation.
Each lane at position `(x, y)` is moved to position `(y, (2x + 3y) mod 5)`, or equivalently, the new lane at `(x, y)` is taken from the old lane at `((x + 3y) mod 5, x)`.
This step provides long-range diffusion across the rows and columns of the state.

```rust
fn pi(state: &[[u64; 5]; 5]) -> [[u64; 5]; 5] {
    let mut result = [[0u64; 5]; 5];
    for x in 0..5 {
        for y in 0..5 {
            result[x][y] = state[(x + 3 * y) % 5][x];
        }
    }
    result
}
```

## &chi; Chi

Chi is the only **non-linear** step in the Keccak round.
For each lane, it XORs in a value derived from the bitwise complement of the next lane in the same row AND'ed with the lane after that.
Because it operates across five lanes simultaneously and introduces non-linearity, it is the primary source of the cryptographic strength of SHA3.

```rust
fn chi(state: &mut [[u64; 5]; 5]) {
    for y in 0..5 {
        // Take a snapshot of the row before modifying it
        let row = [state[0][y], state[1][y], state[2][y], state[3][y], state[4][y]];
        for x in 0..5 {
            state[x][y] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
        }
    }
}
```

## &iota; Iota

Iota breaks the symmetry that would otherwise exist between rounds by XOR'ing a round-specific constant into lane `A[0,0]`.
Without this step, every round would be identical and the entire 24-round permutation could be collapsed to a single round, drastically weakening the function.

```rust
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

fn iota(state: &mut [[u64; 5]; 5], round: usize) {
    state[0][0] ^= ROUND_CONSTANTS[round];
}
```
