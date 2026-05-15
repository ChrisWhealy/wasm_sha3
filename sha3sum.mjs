#!/usr/bin/env node

// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

import { readFileSync } from "fs"
import { WASI } from "wasi"
import * as log from "./utils/logging.mjs"

const IsProd = true

const wasmBinPath = IsProd ? "./bin/sha3.prod.opt.wasm" : "./bin/sha3.dev.opt.wasm"
const wasmDebugPath = "./bin/debug.opt.wasm"

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Instantiate the debug WASM module
const startDebugWasm =
  async () => {
    const debugWasi = new WASI({ version: "unstable" })
    const debugWasiImportObj = { wasi_snapshot_preview1: debugWasi.wasiImport }

    let debugModule = await WebAssembly.instantiate(
      new Uint8Array(readFileSync(wasmDebugPath)),
      debugWasiImportObj,
    )

    debugWasi.start(debugModule.instance)

    return debugModule
  }

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Instantiate and then start the WASM module
const startWasm =
  async (pathToWasmBin, isProd) => {
    //  Define WASI environment
    const wasi = new WASI({
      args: process.argv,
      version: "unstable",
      preopens: { ".": process.cwd() }, // Available as fd 3
    })
    const envObj = {
      wasi_snapshot_preview1: wasi.wasiImport,
    }

    if (!isProd) {
      const debugModule = await startDebugWasm()

      envObj["debug"] = {
        memory: debugModule.instance.exports.memory,
        hexdump: debugModule.instance.exports.hexdump
      }

      envObj["log"] = log
    }

    let sha3Module = await WebAssembly.instantiate(
      new Uint8Array(readFileSync(pathToWasmBin)),
      envObj,
    )

    wasi.start(sha3Module.instance)
  }

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
await startWasm(wasmBinPath, IsProd)
