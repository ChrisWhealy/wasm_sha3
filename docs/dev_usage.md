# Development Usage

## Overview

***IMPORTANT***<br>The development version of the WASM binary can only be run through NodeJS, ***not*** CLI runtimes such as `wasmer` or `wasmtime`.
This is because although the CLI invokes `sha3.wasm` from within an instance of the `WASI` runtime, it cannot additionally bind the extra instances of the `debug` and `log` modules that are needed for the debug/trace functionality to work.

This means that if you try to invoke the `dev` version of the WASM module from say `wasmtime`, it will fail with a link error.

Also, by default, CLI runtimes such as `wasmer` and `wasmtime` invoke the `_start()` function.
This means that once this function terminates, the entire WASM module is torn down and its internal state is lost.

The NodeJS version however creates a persistent instance of `sha3.wasm` via the `SHA3Sponge` class, and then interacts with it by calling the `absorb()`, `finalize()` and `squeeze()` functions.

## Development Mode

If you wish to run this program with the trace functionality switched on, then you will need to build the WASM module in debug and/or test mode.

The `./utils/prepare_src.mjs` program scans the `sha3.wat` source code, stripping out all statements between the special comment markers `;;@debug-start` and `;;@debug-end`, and/or `;;@test-start` and `;;@test-end`.
These special comment markers are also stripped out.

Calling `./prepare_src debug` strips out the special comment markers `;;@debug-start` and `;;@debug-end` and all the coding between them.

Calling `./prepare_src test` strips out the special comment markers `;;@test-start` and `;;@test-end` and all the coding between them.

In both of the above cases, because either the debug or test coding will be left in the source code, `prepare_src.mjs` will output a new WAT source file called `sha3.dev.wat` that is then compiled and can be optionally passed through the `wasm-opt` optimizer.

## Switching On Trace Functionality

If you wish to run this program with the debug trace statements switched on, then do the following:

1. In `sha3.wat`, set the global flag `$DEBUG_ACTIVE` to `1`.<br>This means nothing more than the fact that printing debug trace statements is now permissible.
2. If you wish to trace the internal data as it is processed, then within the appropriate function, set its local `$debug_active` flag to `1`.<br>But be careful - switching this flag on for the Keccak step functions might produce a huge quantity of trace output!
3. Build the module using the command `npm run build:dev`.
4. Run `sha3sum.mjs` passing the additional `--dev` argument.
   If you wish to run the version of the WASM binary that has not been passed through `wasm-opt`, use the `--no-opt` argument.

## Production Mode

Calling `./prepare_src debug test` strips out both sets of special comment markers and all the coding between them.
It then produces a new WAT source file called `sha3.prod.wat` that is then compiled and passed through the `wasm-opt` optimizer.
