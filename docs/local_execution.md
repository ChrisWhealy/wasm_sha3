# Local Execution

# Table of Contents

- [Host Environment Prerequisites](#host-environment-prerequisites)
- [Building Locally](#building-locally)
- [WASM File System Access](#wasm-file-system-access)
- [Using NodeJS](#using-nodejs)
- [Using `wasmer`](#using-wasmer-v71)
- [Using `wasmtime`](#using-wasmtime-v4400)
- [Using `wazero`](#using-wazero-v1110)


# Host Environment Prerequisites

[Install NodeJS](https://nodejs.org/en/download) plus one or more of these WebAssembly Host environments:

* Wasmer: <https://docs.wasmer.io/runtime>
* Wasmtime: <https://wasmtime.dev/>
* Wazero: <https://wazero.io/>

# Building Locally

If you wish to run this app locally, clone the repo into some local directory, change into that directory, then:

```bash
$ npm run build:prod

> wasm_sha3@0.1.0 build:prod
> npm run compile_sha3:prod && npm run compile_tests && npm run opt_sha3:prod && npm run opt_tests


> wasm_sha3@0.1.0 compile_sha3:prod
> ./utils/strip_debug.mjs && wat2wasm --enable-multi-memory ./src/sha3.prod.wat -o ./bin/sha3.prod.wasm


> wasm_sha3@0.1.0 compile_tests
> wat2wasm --debug-names --enable-multi-memory ./src/tests.wat -o ./bin/tests.wasm


> wasm_sha3@0.1.0 opt_sha3:prod
> wasm-opt ./bin/sha3.prod.wasm --enable-simd --enable-multimemory --enable-multivalue --enable-bulk-memory -O4 -o ./bin/sha3.prod.opt.wasm


> wasm_sha3@0.1.0 opt_tests
> wasm-opt ./bin/tests.wasm --enable-simd --enable-multimemory --enable-multivalue -O4 -o ./bin/tests.opt.wasm
```

# WASM File System Access

A WASM module only has access to the files or directories preopened for it by the host environment.
This means that when invoking the WASM module, we must instruct the host environment to open the files or directories to which the WASM module needs access.

The syntax for specifying such preopened resources varies between the different runtimes.

---

# Using NodeJS

The `sha3` WebAssembly module is instantiated and managed by creating an instance of the `SHA3Sponge` class.

To see the usage of this class, take a look at the coding in `sha3sponge_demo.mjs`.

The JavaScript module invoked by NodeJS does not use very sophisticated logic for determining the location of the target file.
Instead, it assumes the current working directory is the one containing `sha3sum.mjs` and the `WASI` instance then preopens `process.cwd()`.
This means the target file ***must*** live in (or beneath) that directory.

By default, `./sha3sum.mjs` runs the `prod` version of the WebAssembly module.

## Drop-In Mode

In drop-in mode, `./sha3sum.mjs` copies the output format of the OS command `sha3sum`.

```bash
$ ./sha3sum.mjs <digest-len> <filename>
```

Where `<digest-len>` is one of `224`, `256`, `384` or `512`

For example:

```bash
$ ./sha3sum.mjs 384 ./tests/war_and_peace.txt
9baecef1c5bd0d3358483274277d06e74598dcbfad6f837c8898fe790a5d0d17e9a6f04a50bf5b05bbe1f34ffe45d7f4  ./test_data/war_and_peace.txt
```

## XOF Mode

In XOF mode, `<output_bytes>` are written to `stdout` without the filename.

```bash
$ ./sha3sum.mjs <digest_len> <output_bytes> <filename>
```

Where `<digest-len>` is one of `shake128` or `shake256`

For example

```bash
$ ./sha3sum.mjs shake128 32 ./test_data/war_and_peace.txt
203c8a358de1abc98d809cb6d5920dad444afa03d95814c9a9ceef79acf9e475
```

---

# Using `wasmer v7.1`

Wasmer can run the SHA3 algorithm in both drop-in and XOF mode.

If present in the CWD, `wasmer` will read `wasmer.toml` to discover which WASM module is to be run.
In such cases, you need only specify `wasmer run .` where the meaning of `.` will be derived from the contents of `wasmer.toml`.

The `--volume` argument preopens the first named directory and mounts it as the second named directory.
So in this case, `wamer` preopens the contents of `./test_data` and mounts it as WebAssembly's root directory `/.`

## Drop-In Mode

`wasmer.toml` contains definitions for the drop-in mode commands `224`, `256`, `384` and `512`.

```bash
$ wasmer run . --volume ./test_data:/. --command-name=224 -- war_and_peace.txt
1b74a9be309c26072ad2903b3ab16eda117414736d32df43df562bb1  war_and_peace.txt
```

## XOF Mode

`wasmer.toml` also contains definitions for the XOF mode commands `shake128` and `shake256`.

The following command runs SHA3 in XOF mode and generates 64 bytes of output data.

```bash
$ wasmer run . --volume ./test_data:/. --command-name=shake128 -- 64 war_and_peace.txt
203c8a358de1abc98d809cb6d5920dad444afa03d95814c9a9ceef79acf9e475498015ad958d4217f5235df6f651697b32ff56fa5c3dc259dab97fd8084b829c
```

# Using `wasmtime v44.0.0`

Wasmtime can run the SHA3 algorithm in both drop-in and XOF mode.

In this example, the `--dir <host_dir>` argument uses `./test_data` as the virtual root and from within WASM, `/` is implied.

## Drop-In Mode

```bash
$ wasmtime --dir ./test_data ./bin/sha3.prod.opt.wasm -- 256 war_and_peace.txt
11a5e2565ce9b182b980aff48ed1bb33d1278bbd77ee4f506729d0272cc7c6f7  war_and_peace.txt
```

## XOF Mode

```bash
$ wasmtime --dir ./test_data ./bin/sha3.prod.opt.wasm -- shake256 32 war_and_peace.txt
0874ad7b6e05764fa19318c85cac7ae7b8fd64473f1df23f002c9a4a18e3c223  war_and_peace.txt
```

# Using `wazero v1.11.0`

Wazero can run the SHA3 algorithm in both drop-in and XOF mode.

When using `wazero`, the `--mount` argument uses a syntax similar to `wasmer`'s `--volume` argument.

## Drop-In Mode

```bash
$ wazero run -mount=./test_data:. ./bin/sha3.prod.opt.wasm 224 war_and_peace.txt
1b74a9be309c26072ad2903b3ab16eda117414736d32df43df562bb1  ./test_data/war_and_peace.txt
```

## XOF Mode

```bash
$ wazero run -mount=./test_data:. ./bin/sha3.prod.opt.wasm shale256 28 war_and_peace.txt
0874ad7b6e05764fa19318c85cac7ae7b8fd64473f1df23f002c9a4a
```
