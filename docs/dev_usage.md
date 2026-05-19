# Development Usage

If you wish to run this program with the debug trace statements switched on, then do the following:

1. In `sha3.wat`, set the global flag `$DEBUG_ACTIVE` to `1`.
   This will cause nothing more than the execution step numbers and their return codes to be printed.
2. If you wish to see a trace of the internal data processed by the Keccak step functions, then within the appropriate function, set its local `$debug_active` flag to `1`.<br>
   Be careful - this might produce a huge quantity of trace output!
3. Build the module using the command `npm run build:dev`.
4. In `sha3sum.mjs`, set the Boolean flag `isProd` to `false`
5. Run the WASM module using NodeJS

## Stripping Out Debug Coding

Any statements used only for debug tracing (such as calls to functions `$hexdump`, `$write_msg` or `$write_step` etc) are delimited by preprocessor markers `;;@debug-start` and `;;@debug-end`.

To compile for production, such function calls can be removed from the source code by first running `./utils/strip-debug.mjs`.

This then produces a "production" version of the WAT source code (`./src/sha256.prod.wat`) from which these delimiters and all the coding between them have been removed.

