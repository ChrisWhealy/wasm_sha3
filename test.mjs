#!/usr/bin/env node

// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on(
  'warning',
  w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message)
)

import { readFileSync } from "fs"
import { u64AsHexStr, u32AsHexStr, u8AsHexStr } from "./utils/binary_utils.mjs"
import { runTest } from "./utils/test_utils.mjs"
import { testData } from "./utils/test_data.mjs"
import { debugLabels, debugMsgs } from "./utils/debug_msgs.mjs"
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

    let sha3Module = await WebAssembly.instantiate(readWasmBinary(sha3WasmBinPath), debugEnv)

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    runTest(sha3Module, testData.xorDataWithRate)
    runTest(sha3Module, testData.thetaC1)
    runTest(sha3Module, testData.thetaC2)
    runTest(sha3Module, testData.thetaC3)
    runTest(sha3Module, testData.thetaC4)
    runTest(sha3Module, testData.thetaC)
    runTest(sha3Module, testData.thetaD)
    runTest(sha3Module, testData.thetaXorLoop)
    runTest(sha3Module, testData.testTheta)
    runTest(sha3Module, testData.testRho)
    runTest(sha3Module, testData.testPi)
    runTest(sha3Module, testData.testChi)
    runTest(sha3Module, testData.testIota)
    runTest(sha3Module, testData.testThetaRho)
    runTest(sha3Module, testData.testThetaRhoPi)
    runTest(sha3Module, testData.testThetaRhoPiChi)
    runTest(sha3Module, testData.testThetaRhoPiChiIota)
    runTest(sha3Module, testData.testKeccak1)
    runTest(sha3Module, testData.testKeccak2)
    runTest(sha3Module, testData.testKeccak24)
  }

await startWasm()
