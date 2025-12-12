import { readFileSync } from "fs"
import { WASI } from "wasi"
import * as log from "./logging.mjs"

// Use non-optimized binaries during testing
const sha3WasmBinPath = "./bin/sha3.wasm"
const debugWasmBinPath = "./bin/debug.wasm"
const testWasmBinPath = "./bin/tests.wasm"

const readWasmBinary = pathToWasmBin => new Uint8Array(readFileSync(pathToWasmBin))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Instantiate the SHA3 WASM module
const startSha3Wasm =
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
        fnEnter: log.fnEnter,
        fnExit: log.fnExit,
        fnEnterNth: log.fnEnterNth,
        fnExitNth: log.fnExitNth,
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

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Instantiate the test WASM module as a wrapper around the SHA3 module
const startTestWasm =
  async sha3WasmMod => {
    let testEnv = {
      sha3: {
        prepareState: sha3WasmMod.instance.exports.prepare_state,
        thetaC: sha3WasmMod.instance.exports.theta_c,
        thetaD: sha3WasmMod.instance.exports.theta_d,
        thetaXorLoop: sha3WasmMod.instance.exports.theta_xor_loop,
        theta: sha3WasmMod.instance.exports.theta,
        rho: sha3WasmMod.instance.exports.rho,
        pi: sha3WasmMod.instance.exports.pi,
        chi: sha3WasmMod.instance.exports.chi,
        iota: sha3WasmMod.instance.exports.iota,
        keccak: sha3WasmMod.instance.exports.keccak,
        sponge: sha3WasmMod.instance.exports.sponge,
      },
    }

    return await WebAssembly.instantiate(readWasmBinary(testWasmBinPath), testEnv)
  }

export {
  startSha3Wasm,
  startTestWasm,
}
