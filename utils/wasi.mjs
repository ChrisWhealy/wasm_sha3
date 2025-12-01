import { readFileSync } from "fs"
import { u64AsHexStr, u32AsHexStr } from "./binary_utils.mjs"
import { debugLabels, debugMsgs } from "./debug_msgs.mjs"
import { WASI } from "wasi"

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
        fnEnter: (debugActive, fnId) => debugActive ? console.log(`===> ${debugMsgs[fnId].fnName}`) : {},
        fnExit: (debugActive, fnId) => debugActive ? console.log(`<=== ${debugMsgs[fnId].fnName}`) : {},
        fnEnterNth: (debugActive, fnId, n) => debugActive ? console.log(`===> ${debugMsgs[fnId].fnName} ${n}`) : {},
        fnExitNth: (debugActive, fnId, n) => debugActive ? console.log(`<=== ${debugMsgs[fnId].fnName} ${n}`) : {},
        singleI64: (debugActive, fnId, msgId, i64) => debugActive
          ? console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = ${u64AsHexStr(i64)}`)
          : {},
        singleI32: (debugActive, fnId, msgId, i32) => debugActive
          ? console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = ${u32AsHexStr(i32)}`)
          : {},
        singleDec: (debugActive, fnId, msgId, i32) => debugActive
          ? console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = ${i32}`)
          : {},
        mappedPair: (debugActive, fnId, msgId, v1, v2) => debugActive
          ? console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]}: ${v1} -> ${v2}`)
          : {},
        coordinatePair: (debugActive, fnId, msgId, v1, v2) => debugActive
          ? console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = (${v1},${v2})`)
          : {},
        singleBigInt: (debugActive, fnId, msgId, i64) => debugActive
          ? console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = ${i64}`)
          : {},
        label: (debugActive, labelId) => debugActive ? console.log(debugLabels[labelId]) : {},
      }
    }

    return await WebAssembly.instantiate(readWasmBinary(sha3WasmBinPath), debugEnv)
  }

export {
  startWasm
}
