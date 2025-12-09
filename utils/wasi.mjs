import { readFileSync } from "fs"
import { WASI } from "wasi"
import * as log from "./logging.mjs"

// Use non-optimized binaries during testing
const sha3WasmBinPath = "./bin/sha3.wasm"
const debugWasmBinPath = "./bin/debug.wasm"

const readWasmBinary = pathToWasmBin => new Uint8Array(readFileSync(pathToWasmBin))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Instantiate the WASM module
const startWasm =
  async () => {
    // Start debug module using WASI
    const wasi = new WASI({
      args: process.argv,
      version: "unstable",
      preopens: { ".": process.cwd() },
    })
    const debugImportObj = {
      wasi_snapshot_preview2: wasi.wasiImport,
    }

    let debugModule = await WebAssembly.instantiate(
      new Uint8Array(readFileSync(debugWasmBinPath)),
      debugImportObj,
    )

    wasi.start(debugModule.instance)

    // Create the SHA3 module
    let debugEnv = {
      env: {
        debug: debugModule.instance.exports.memory,
        hexdump: debugModule.instance.exports.hexdump
      },
      log: {
        fnEnter: log.doFnEnter,
        fnExit: log.doFnExit,
        fnEnterNth: log.doFnEnterNth,
        fnExitNth: log.doFnExitNth,
        singleI64: log.singleI64,
        singleI32: log.singleI32,
        singleDec: log.singleDec,
        mappedPair: log.mappedPair,
        coordinatePair: log.coordPair,
        singleBigInt: log.singleBigInt,
        label: log.label,
      }
    }

    return await WebAssembly.instantiate(readWasmBinary(sha3WasmBinPath), debugEnv)
  }

export {
  startWasm
}
