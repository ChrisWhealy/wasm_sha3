import { readFileSync } from "fs"
import { u64AsHexStr, u32AsHexStr } from "./binary_utils.mjs"
import { debugLabels, debugMsgs } from "./debug_msgs.mjs"
import { WASI } from "wasi"

// Use non-optimized binaries during testing
const sha3WasmBinPath = "./bin/sha3.wasm"
const debugWasmBinPath = "./bin/debug.wasm"

const readWasmBinary = pathToWasmBin => new Uint8Array(readFileSync(pathToWasmBin))

const logMsgHdr = (fnId, msgId) => `${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]}`
const logSingleI64 = (isDebug, fnId, msgId, i64) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)} = ${u64AsHexStr(i64)}`) : {}
const logSingleI32 = (isDebug, fnId, msgId, i32) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)} = ${u32AsHexStr(i32)}`) : {}
const logSingleDec = (isDebug, fnId, msgId, dec) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)} = ${dec}`) : {}
const logMappedPair = (isDebug, fnId, msgId, v1, v2) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)}: ${v1} -> ${v2}`) : {}
const logCoordPair = (isDebug, fnId, msgId, v1, v2) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)} = (${v1},${v2})`) : {}
const logSingleBigInt = (isDebug, fnId, msgId, i64) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)} = ${i64}`) : {}
const logLabel = (isDebug, labelId) => isDebug ? console.log(debugLabels[labelId]) : {}

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
        fnEnter: (isDebug, fnId) => isDebug ? console.log(`===> ${debugMsgs[fnId].fnName}`) : {},
        fnExit: (isDebug, fnId) => isDebug ? console.log(`<=== ${debugMsgs[fnId].fnName}`) : {},
        fnEnterNth: (isDebug, fnId, n) => isDebug ? console.log(`===> ${debugMsgs[fnId].fnName} ${n}`) : {},
        fnExitNth: (isDebug, fnId, n) => isDebug ? console.log(`<=== ${debugMsgs[fnId].fnName} ${n}`) : {},
        singleI64: logSingleI64,
        singleI32: logSingleI32,
        singleDec: logSingleDec,
        mappedPair: logMappedPair,
        coordinatePair: logCoordPair,
        singleBigInt: logSingleBigInt,
        label: logLabel,
      }
    }

    return await WebAssembly.instantiate(readWasmBinary(sha3WasmBinPath), debugEnv)
  }

export {
  startWasm
}
