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
    const debugWasiImportObj = { wasi_snapshot_preview2: debugWasi.wasiImport }

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
  async (pathToWasmBin, devMode) => {
    // Start SHA3 module using WASI passing in debguWasi instance
    const sha3Wasi = new WASI({
      args: process.argv,
      version: "unstable",
      preopens: { ".": process.cwd() }, // Available as fd 3
    })

    let envObj = {
      wasi_snapshot_preview2: sha3Wasi.wasiImport,
    }

    if (devMode) {
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
