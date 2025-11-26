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
        fnEnter: fnId => console.log(`===> ${debugMsgs[fnId].fnName}`),
        fnExit: fnId => console.log(`<=== ${debugMsgs[fnId].fnName}`),
        fnEnterNth: (fnId, n) => console.log(`===> ${debugMsgs[fnId].fnName} ${n}`),
        fnExitNth: (fnId, n) => console.log(`<=== ${debugMsgs[fnId].fnName} ${n}`),
        singleI64: (fnId, msgId, i64) => {
          console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = ${u64AsHexStr(i64)}`)
        },
        singleI32: (fnId, msgId, i32) => {
          console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = ${u32AsHexStr(i32)}`)
        },
        singleDec: (fnId, msgId, i32) => {
          console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = ${i32}`)
        },
        mappedPair: (fnId, msgId, v1, v2) => {
          console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]}: ${v1} -> ${v2}`)
        },
        coordinatePair: (fnId, msgId, v1, v2) => {
          console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = (${v1},${v2})`)
        },
        singleBigInt: (fnId, msgId, i64) => {
          console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = ${i64}`)
        },
        label: labelId => console.log(debugLabels[labelId]),
      }
    }

    return await WebAssembly.instantiate(readWasmBinary(sha3WasmBinPath), debugEnv)
  }

  export {
    startWasm
  }
