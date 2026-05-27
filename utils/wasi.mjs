import { readFileSync } from "fs"
import { WASI } from "wasi"
import * as log from "./logging.mjs"

const debugWasmBinPath = "./bin/debug.wasm"
const testWasmBinPath = "./bin/tests.wasm"

const readWasmBinary = pathToWasmBin => new Uint8Array(readFileSync(pathToWasmBin))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Instantiate the debug WASM module
const startDebugWasm = async pathToWasmBin => {
  const debugWasi = new WASI({
    version: "unstable",
  })
  const debugWasiImportObj = { wasi_snapshot_preview1: debugWasi.wasiImport }

  let debugModule = await WebAssembly.instantiate(
    new Uint8Array(readFileSync(pathToWasmBin)),
    debugWasiImportObj,
  )

  debugWasi.start(debugModule.instance)

  return debugModule
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Instantiate the SHA3 WASM module
const startSha3Wasm =
  async (pathToWasmBin, isProd) => {
    const sha3Wasi = new WASI({
      args: process.argv,
      version: "unstable",
      preopens: { ".": process.cwd() }, // Available as fd 3
    })

    let envObj = {
      wasi_snapshot_preview1: sha3Wasi.wasiImport,
    }

    if (!isProd) {
      const debugModule = await startDebugWasm(debugWasmBinPath)

      envObj["debug"] = {
        memory: debugModule.instance.exports.memory,
        hexdump: debugModule.instance.exports.hexdump
      },
      envObj["log"] = log
    }

    let sha3Module = await WebAssembly.instantiate(
      new Uint8Array(readFileSync(pathToWasmBin)),
      envObj,
    )

    sha3Wasi.start(sha3Module.instance)

    return sha3Module
  }

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Instantiate the test WASM module as a wrapper around the SHA3 module
const startTestWasm =
  async sha3WasmMod => {
    let testEnv = {
      sha3: {
        prepare_state: sha3WasmMod.instance.exports.prepare_state,
        theta: sha3WasmMod.instance.exports.theta,
        rho_pi: sha3WasmMod.instance.exports.rho_pi,
        chi: sha3WasmMod.instance.exports.chi,
        iota: sha3WasmMod.instance.exports.iota,
        keccak: sha3WasmMod.instance.exports.keccak,
        keccak24: sha3WasmMod.instance.exports.keccak24,
        sponge: sha3WasmMod.instance.exports.sponge,
      },
    }

    return await WebAssembly.instantiate(readWasmBinary(testWasmBinPath), testEnv)
  }

export {
  startSha3Wasm,
  startTestWasm,
}
