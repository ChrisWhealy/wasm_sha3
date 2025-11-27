import { test } from 'node:test'
import assert from 'node:assert/strict'
import { u8AsHexStr } from "./binary_utils.mjs"

const PAD_MARKER = 0x61
const PAD_MARKER_START = 0x60
const PAD_MARKER_END = 0x01

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const defineState = digestLen => {
  // Required SHA3 output digest length may only be one of 224, 256, 384 or 512
  if (digestLen !== 224 && digestLen !== 256 && digestLen !== 384 && digestLen !== 512) {
    console.error(`Invalid digest length ${digestLen} supplied.  Defaulting to 256 bits`)
    digestLen = 256
  }

  // Define dimnensions of the SHA3 internal state
  const LENGTH = 6  // Can be 0..6, but here is hard-coded since this is a drop-in replacement for SHA2
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
// Take a single block of input data (that must be at least 8 bits smaller than the rate size) and return it as a
// UInt8Array followed by the correct padding bit sequence
const sha3PaddingForDigest = digestLen => {
  const state = defineState(digestLen)

  let arr = new Uint8Array(state.getRateBytes())

  return testData => {
    let encoded = new TextEncoder().encode(testData)
    arr.set(encoded)

    // Insert padding
    let bytesRem = state.getRateBytes() - encoded.length

    if (bytesRem === 1) {
      arr.set(PAD_MARKER, encoded.length - 1)
    } else {
      arr[encoded.length] = PAD_MARKER_START
      arr[arr.length - 1] = PAD_MARKER_END
    }

    return arr
  }
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
      diffs.push(`    at index ${idx}: expected ${u8AsHexStr(expectedByte)}, got ${u8AsHexStr(resultByte)}`)
    }
  }

  return diffs
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testWasmFn = (wasmMod, thisTest) => {
  let testName = `${thisTest.wasmTestFnName}(${thisTest.wasmTestFnArgs ? thisTest.wasmTestFnArgs.join(',') : ''})`
  let wasmMem8 = new Uint8Array(wasmMod.instance.exports.memory.buffer)

  // Write test data to the locations in the pointer list
  for (let idx = 0; idx < thisTest.wasmGlobalExportPtrIn.length; idx++) {
    let toPtr = wasmMod.instance.exports[thisTest.wasmGlobalExportPtrIn[idx]].value
    wasmMem8.set(thisTest.testData[idx], toPtr)
  }

  // Test WASM function
  test(testName,
    () => {
      if (thisTest.wasmTestFnArgs && thisTest.wasmTestFnArgs.length > 0) {
        wasmMod.instance.exports[thisTest.wasmTestFnName](...thisTest.wasmTestFnArgs)
      } else {
        wasmMod.instance.exports[thisTest.wasmTestFnName]()
      }

      let diffs = uInt8ArrayDiff(thisTest, wasmMod)

      assert.equal(diffs.length, 0, `❌ UInt8Arrays differ\n${diffs.join('\n')}`)
    }
  )
}

const sha3Padding224 = sha3PaddingForDigest(224)
const sha3Padding256 = sha3PaddingForDigest(256)
const sha3Padding384 = sha3PaddingForDigest(384)
const sha3Padding512 = sha3PaddingForDigest(512)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
export {
  PAD_MARKER,
  PAD_MARKER_START,
  PAD_MARKER_END,
  sha3Padding224,
  sha3Padding256,
  sha3Padding384,
  sha3Padding512,
  testWasmFn,
  defineState,
}
