
# The Keccak Function

## Table of Contents

- [Introduction](#introduction)
- [Input Block Padding](#input-block-padding)
- [Keccak Function Input Processing](#keccak-function-input-processing)

# Introduction

SHA3 manipulates the input data using a function that has been given the made up name of "Keccak" (pronounced "ket chak").

# Domain Suffix and Block Padding

The input data is divided into some number `t` of blocks, where `t` is the file size in bits divided by the rate.
If this number is not an integer, then it is rounded up to the next whole number.

More formally, this is given by:

```javascript
let t = Math.floor(file_size_in_bits / rate) + (file_size_in_bits mod rate < 4 ? 1 : 0)
```

The last block always has a "domain suffix" appended, followed by some number of padding bits so that the last block is entirely filled:

  1. Append the domain suffix to the message:
     - SHA3: append `01` (2 bits)
     - SHAKE: append `1111` (4 bits)
  2. Apply the `pad10*1` function (see NIST FIPS 202 §5.1) to fill the remaining space in the last block

The data is always suffixed with the domain suffix bits (being either `01` or `1111`) followed by however many padding bits the `pad10*1` function generates.

The `pad10*1` function will always generate a bit string that:
* Starts and ends with bit `1`
* Between which are zero or more bit `0`s

Note that if the data is an exact integer multiple of the block size `r`, then an entire extra block containing only the domain suffix and the padding bit string is always added.

# Keccak Function Input Processing

Now that the input data `X` has been organised into some integer number `t` of blocks of size `r` (the last of which has been appropriately padded), the "absorb" phase performs the following loop:

```rust
// Internal state starts as 200 initialised u64s
let mut state[u64; 200] = [0; 200];
// The rate size in bits is given by 1600 - (2 * digest_size)
// Assuming a digest size of 256 bits the rate size = 1600 - (2 * 256) = 1088
let rate_size = 1088 >>> 6;  // As u64 words

for idx in X.size {
    state = keccak_f([state[0..rate_size] XOR X[idx], ...state[rate_size..]])
}
```

Each time a new block is read from the input data, it is `XOR`ed with the current rate and the resulting internal state passed to the Keccak function.
This process is performed as many times as needed to fully "absorb" the input data.

![Sponge function](./sponge.png)

When SHA3 is being used in SHA2 replacement mode, after the absorb phase has completed, the required hash value is obtained simply by taking the required number of bits from the rate at `Y(0)`.

However, when SHA3 is being used in XOF mode, the squeeze phase will be performed as many times as needed to generate the required number of output bytes.
Hence, states `Y(1)`, `Y(2)` or `Y(3)` may need to be created in order to generate the required length of output data.

This process is entirely deterministic.
For the same input followed by the same number of squeeze rounds, the same output data will always be generated.

[This page](./keccak_internals.md) provides a description of how the Keccak function works internally.
