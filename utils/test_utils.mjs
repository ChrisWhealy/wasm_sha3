import { test } from 'node:test'
import assert from 'node:assert/strict'
import { u8AsHexStr } from "./binary_utils.mjs"
import { startTestWasm, startSha3Wasm } from "./wasi.mjs"

export const PAD_MARKER = 0x61
export const PAD_MARKER_START = 0x06
export const PAD_MARKER_END = 0x80

// Use non-optimized binary for testing dev
const sha3WasmBinPathDev = "./bin/sha3.dev.wasm"
const sha3WasmBinPathProd = "./bin/sha3.prod.opt.wasm"

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// For a given digest length, define the dimensions of the SHA3 internal state
export const defineInternalState = digestLen => {
  if (digestLen !== 224 && digestLen !== 256 && digestLen !== 384 && digestLen !== 512) {
    console.error(`Invalid digest length ${digestLen} supplied.  Defaulting to 256 bits`)
    digestLen = 256
  }

  const LENGTH = 6
  const WORD_LENGTH = 2 ** LENGTH
  const STATE_SIZE = 5 * 5 * WORD_LENGTH
  const CAPACITY = 2 * digestLen
  const RATE = STATE_SIZE - CAPACITY

  return {
    getWordLength: () => WORD_LENGTH,

    getStateSize: () => STATE_SIZE,
    getStateSizeBytes: () => STATE_SIZE >>> 3,
    getStateSizeWords: () => STATE_SIZE >>> 6,

    getCapacity: () => CAPACITY,
    getCapacityBytes: () => CAPACITY >>> 3,
    getCapacityWords: () => CAPACITY >>> 6,

    getRate: () => RATE,
    getRateBytes: () => RATE >>> 3,
    getRateWords: () => RATE >>> 6,
  }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Build a rate-sized Uint8Array containing testData followed by SHA3 pad10*1 padding (domain 0x06)
export const sha3PaddingForDigest = (digestLen, testData) => {
  const state = defineInternalState(digestLen)
  let arr = new Uint8Array(state.getRateBytes())
  const encoded = new TextEncoder().encode(testData)

  arr.set(encoded)

  if (state.getRateBytes() - encoded.length === 1) {
    arr[encoded.length - 1] = PAD_MARKER
  } else {
    arr[encoded.length] = PAD_MARKER_START
    arr[arr.length - 1] = PAD_MARKER_END
  }

  return arr
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const uInt8ArrayDiff = (thisTest, wasmMod) => {
  const wasmMem8 = new Uint8Array(wasmMod.instance.exports.memory.buffer)
  const outputPtr = wasmMod.instance.exports[thisTest.wasmGlobalExportPtrOut].value
  const diffs = []

  for (let idx = 0; idx < thisTest.expected.length; idx++) {
    let resultByte = wasmMem8[outputPtr + idx]
    let expectedByte = thisTest.expected[idx]

    if (resultByte != expectedByte) {
      diffs.push({
        idx: idx,
        expected: expectedByte,
        got: resultByte
      })
    }
  }

  return diffs
}

const formatUInt8ArrayDiff = d =>
  `    at index ${d.idx}: expected ${u8AsHexStr(d.expected)}, got ${u8AsHexStr(d.got)}`

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Each test must run against its own isolated WASM instance
export const testWasmFn = (thisTest, isProd) => {
  let testName = `${thisTest.wasmTestFnName}(${thisTest.wasmTestFnArgs ? thisTest.wasmTestFnArgs.join(',') : ''})`
  let wasmBinPath = isProd ? sha3WasmBinPathProd : sha3WasmBinPathDev

  test(testName,
    async () => {
      let wasmMod = await startSha3Wasm(wasmBinPath, isProd)
      let testMod = await startTestWasm(wasmMod)
      let wasmMem8 = new Uint8Array(wasmMod.instance.exports.memory.buffer)

      for (let idx = 0; idx < thisTest.wasmInputData.length; idx++) {
        const wasmIn = thisTest.wasmInputData[idx]
        const writeToPtr = wasmMod.instance.exports[wasmIn.writeToPtr].value

        if (!wasmIn.inputData || wasmIn.inputData.length === 0) {
          throw new Error(`No test input data for ${testName} index ${idx}`)
        }

        wasmMem8.set(wasmIn.inputData, writeToPtr)
      }

      let testFn = testMod.instance.exports[thisTest.wasmTestFnName]

      if (thisTest.wasmTestFnArgs && thisTest.wasmTestFnArgs.length > 0) {
        testFn(...thisTest.wasmTestFnArgs)
      } else {
        testFn()
      }

      let diffs = uInt8ArrayDiff(thisTest, wasmMod)

      assert.equal(diffs.length, 0, `❌ UInt8Arrays differ\n${diffs.map(formatUInt8ArrayDiff).join('\n')}`)
    }
  )
}
