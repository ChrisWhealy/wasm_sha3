#!/usr/bin/env node

// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on(
  'warning',
  w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message)
)

import { readFileSync } from "fs"
import { u64AsHexStr, u32AsHexStr, u8AsHexStr } from "./utils/binary_utils.mjs"
import { testData } from "./utils/test_data.mjs"
import { debugMsgs } from "./utils/debug_msgs.mjs"
import { WASI } from "wasi"

// Use non-optimized binaries during testing
const sha3WasmBinPath = "./bin/sha3.wasm"
const debugWasmBinPath = "./bin/debug.wasm"

const readWasmBinary = pathToWasmBin => new Uint8Array(readFileSync(pathToWasmBin))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const runTest = (wasmMod, testName) => {
  let thisTest = testData[testName]
  let wasmMem8 = new Uint8Array(wasmMod.instance.exports.memory.buffer)

  // Write test data to the locations in the pointer list
  for (let idx = 0; idx < thisTest.wasmGlobalExportPtrIn.length; idx++) {
    let toPtr = wasmMod.instance.exports[thisTest.wasmGlobalExportPtrIn[idx]].value
    wasmMem8.set(thisTest.testData[idx], toPtr)
  }

  // Call test function
  wasmMod.instance.exports[thisTest.wasmTestFnName]()

  // Compare expected results with the data found at outputPtr
  let outputPtr = wasmMod.instance.exports[thisTest.wasmGlobalExportPtrOut].value
  let success = true

  for (let idx = 0; idx < thisTest.expected.length; idx++) {
    let resultByte = wasmMem8[outputPtr + idx]
    let expectedByte = thisTest.expected[idx]

    if (resultByte != expectedByte) {
      success = false
      console.log(`${testName} error at byte ${idx}: expected ${u8AsHexStr(expectedByte)}, got ${u8AsHexStr(resultByte)}`)
    }
  }

  console.log(`${success ? "✅" : "❌"} Test ${testName}`)
}

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
        singleI64: (fnId, msgId, i64) => {
          console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = ${u64AsHexStr(i64)}`)
        },
        singleI32: (fnId, msgId, i32) => {
          console.log(`${debugMsgs[fnId].fnName} ${debugMsgs[fnId].msgId[msgId]} = ${u32AsHexStr(i32)}`)
        }
      }
    }

    let sha3Module = await WebAssembly.instantiate(readWasmBinary(sha3WasmBinPath), debugEnv)

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    runTest(sha3Module, "thetaC")
    runTest(sha3Module, "thetaD")
    runTest(sha3Module, "thetaXorLoop")
    runTest(sha3Module, "theta")
    runTest(sha3Module, "rho")
    runTest(sha3Module, "pi")
    runTest(sha3Module, "chi")
    runTest(sha3Module, "iota")
    runTest(sha3Module, "keccak0")
  }

await startWasm()
