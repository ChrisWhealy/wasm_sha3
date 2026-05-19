
# The Keccak Function

SHA3 manipulates the input data using a function that has been given the made up name of "Keccak" (pronounced "ket chak").

## Input Block Padding

The input data is divided into some number (`t`) of blocks of the same size as the rate where `t` is given by:

```javascript
let t = Math.floor(file_size_in_bits / rate) + (file_size_in_bits mod rate < 4 ? 1 : 0)
```

The last block must be padded so that the data being processed fills an integer number of blocks.

The padding rules depend on whether SHA3 is being used in SHA2-replacement mode, or XOF mode.
In our case, we are only concerned with SHA2-replacement mode, so the padding rules are as follows:

* The data must be suffixed with the two padding marker bits `01`
* The padding marker must be followed by a variable length bit sequence that:
   * Starts and ends with bit `1`
   * Between the start and end `1`s there must be zero or more bit `0`s

Thus, if the size of data `n` in the last block is 4 or more bits smaller than the rate `r`, the last block will be padded as follows:

| Size of data<br> in last block | Padding<br>marker | Padding<br>bit sequence | Complete<br>bit string
|---|---|---|---
| `r-4` | `01` | `11` | `0111`
| `r-5` | `01` | `101` | `01101`
| `r-6` | `01` | `1001` | `011001`
| `r-7` | `01` | `10001` | `0110001`
| `r-n` | `01` | `1[n-4 * 0]1` | `0110...01`

In the event that the block size is 3 or fewer bits smaller than the rate `r`, then the remaining bits are padded using the same scheme as above, but the padding string spills over into a new block:

| Size of data<br>in last block | Padding bit<br>sequence in<br>last block | Padding bits<br>in extra block
|---|---|---
| `r-3` | `011` | `[r-1 * 0]1`
| `r-2` | `01` | `1[r-2 * 0]1`
| `r-1` | `0` | `11[r-3 * 0]1`
| `r` | | `011[r-4 * 0]1`

Note that if the data is an exact integer multiple of the block size `r`, then an extra block containing only the padding string is always added.

## Keccak-f Input Processing

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
However, when SHA3 is being used in XOF mode, at least one further round of the squeeze phase is performed, yielding `Y(1)`.
At this point you may take as output any number of bits from the rate (up to the full size of the rate), and then perform any number of further squeeze rounds to continue generating psuedo-random data.

This process is entirely deterministic.
For the same input followed by the same number of squeeze rounds, the same output data will always be generated.

[This page](./keccak_internals.md) provides a description of how the Keccak function works internally.
