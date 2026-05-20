# Development Usage

## Overview

***IMPORTANT***<br>Development version of the WASM binary can only be run through NodeJS and not CLI runtimes such as `wasmer` or `wasmtime`.
This is because although the CLI invokes `sha3.wasm` from within an instance of the `WASI` runtime, it cannot provide instances of the extra `debug` and `log` modules that are also needed during development.
This means if you try to invoke the `dev` version of the WASM module from say `wasmtime`, it will fail with a link error.

Also, CLI runtimes such as `wasmer` and `wasmtime` only ever invoke the `_start()` function.
This means that once this function terminates, the entire WASM module is torn down and its internal state is lost.

The NodeJS version however creates a persistent instance of `sha3.wasm` via the `SHA3Sponge` class, and then interacts with it by calling the `absorb()`, `finalize()` and `squeeze()` functions.

## Seeing Trace Statements

If you wish to run this program with the debug trace statements switched on, then do the following:

1. In `sha3.wat`, set the global flag `$DEBUG_ACTIVE` to `1`.<br>This means nothing more than the fact that printing debug trace statements is now permissible.
2. If you wish to trace the internal data as it is processed, then within the appropriate function, set its local `$debug_active` flag to `1`.<br>But be careful - switching this flag on for the Keccak step functions might produce a huge quantity of trace output!
3. Build the module using the command `npm run build:dev`.
4. Run `sha3sum.mjs` passing the additional `--dev` argument.
   If you wish to run the version of the WASM binary that has not been passed through `wasm-opt`, use the `--no-opt` argument.

## Stripping Out Debug Coding

Any statements used only for debug tracing (such as calls to functions `$hexdump`, `$write_msg` or `$write_args` etc) are enclosed between the preprocessor markers `;;@debug-start` and `;;@debug-end`.

When compiling for production, such function calls are removed from the source code by running `./utils/strip-debug.mjs`.

This then produces a `.prod` version of the WAT source code (`./src/sha256.prod.wat`) from which these delimiters and all the enclosed code has been removed.
