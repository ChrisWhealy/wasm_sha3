import { test } from 'node:test'
import assert from 'node:assert/strict'
import { u8AsHexStr } from "./binary_utils.mjs"
import { startWasm } from "./wasi.mjs"

const PAD_MARKER = 0x61
const PAD_MARKER_START = 0x60
const PAD_MARKER_END = 0x01

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// For a given digest length, define the dimensions of the SHA3 internal state
// Since this is a drop-in replacement for SHA2, not only must the digest length be one of 224, 256, 384 or 512 bits,
// but the exponent of the word length is fixed at 6 (i.e. 64-bit words)
const defineInternalState = digestLen => {
  if (digestLen !== '224' && digestLen !== '256' && digestLen !== '384' && digestLen !== '512') {
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
// Take a single block of input data (that must be at least 8 bits smaller than the rate size) and return it as a
// UInt8Array followed by the correct sequence of padding bits 011[*0]1
const sha3PaddingForDigest = (digestLen, testData) => {
  const state = defineInternalState(digestLen)
  let arr = new Uint8Array(state.getRateBytes())
  const encoded = new TextEncoder().encode(testData)

  arr.set(encoded)

  // Insert padding
  if (state.getRateBytes() - encoded.length === 1) {
    arr.set(PAD_MARKER, encoded.length - 1)
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
const testWasmFn = thisTest => {
  let testName = `${thisTest.wasmTestFnName}(${thisTest.wasmTestFnArgs ? thisTest.wasmTestFnArgs.join(',') : ''})`

  // Test WASM function
  test(testName,
    async () => {
      let wasmMod = await startWasm()
      let wasmMem8 = new Uint8Array(wasmMod.instance.exports.memory.buffer)

      // Write test data to the locations in WASM memory given in the input data list
      for (let idx = 0; idx < thisTest.wasmInputData.length; idx++) {
        const wasmIn = thisTest.wasmInputData[idx]
        const writeToPtr = wasmMod.instance.exports[wasmIn.writeToPtr].value
        let src = wasmIn.inputData

        // // If src points to the INPUT_DATA wrapper, use its .value
        // if (src && src.value) {
        //   src = src.value

          // Sanity check that we actually have some test data
          if (src == null) {
            throw new Error(`No test input data for ${testName} index ${idx} - got ${src}`)
          }
        // }

        wasmMem8.set(src, writeToPtr)
      }

      let wasmFn = wasmMod.instance.exports[thisTest.wasmTestFnName]

      if (thisTest.wasmTestFnArgs && thisTest.wasmTestFnArgs.length > 0) {
        wasmFn(...thisTest.wasmTestFnArgs)
      } else {
        wasmFn()
      }

      // The WASM functions being tested never return any values; instead, they mutate shared memory
      let diffs = uInt8ArrayDiff(thisTest, wasmMod)

      assert.equal(diffs.length, 0, `❌ UInt8Arrays differ\n${diffs.map(formatUInt8ArrayDiff).join('\n')}`)
    }
  )
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
export {
  PAD_MARKER,
  PAD_MARKER_START,
  PAD_MARKER_END,
  sha3PaddingForDigest,
  testWasmFn,
}
