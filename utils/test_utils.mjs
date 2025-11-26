import { u8AsHexStr } from "./binary_utils.mjs"

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const defineState = digestLen => {
  // Required SHA3 output digest length may only be one of 224, 256, 384 or 512
  if (digestLen !== 224 && digestLen !== 256 && digestLen !== 384 && digestLen !== 256) {
    console.error(`Invalid digest length ${digestLen} supplied.  Defaulting to 256 bits`)
    digestLen = 256
  }

  // Define SHA3 internal state dimensions
  const LENGTH = 6  // Hard-coded since this is a drop-in replacement for SHA2
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
// Take a single block of input data (that must be smaller than the rate size) and return it as a UInt8Array padded with
// the correct bit sequence
const sha3PaddingForRate = digestLen => {
  const state = defineState(digestLen)
  const pad1Byte = 0x61
  const padFirstByte = 0x60
  const padLastByte = 0x01

  let arr = new Uint8Array(state.getRateBytes())

  return testData => {
    let encoded = new TextEncoder().encode(testData)
    arr.set(encoded)

    // Insert padding
    let bytesRem = state.getRateBytes() - encoded.length

    if (bytesRem === 1) {
      arr.set(pad1Byte, encoded.length - 1)
    } else {
      arr[encoded.length] = padFirstByte
      arr[arr.length - 1] = padLastByte
    }

    return arr
  }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const runTest = (wasmMod, thisTest) => {
  let wasmMem8 = new Uint8Array(wasmMod.instance.exports.memory.buffer)

  // Write test data to the locations in the pointer list
  for (let idx = 0; idx < thisTest.wasmGlobalExportPtrIn.length; idx++) {
    let toPtr = wasmMod.instance.exports[thisTest.wasmGlobalExportPtrIn[idx]].value
    wasmMem8.set(thisTest.testData[idx], toPtr)
  }

  // Call test function
  if (thisTest.wasmTestFnArgs && thisTest.wasmTestFnArgs.length > 0) {
    wasmMod.instance.exports[thisTest.wasmTestFnName](...thisTest.wasmTestFnArgs)
  } else {
    wasmMod.instance.exports[thisTest.wasmTestFnName]()
  }

  // Compare expected results with the data found at outputPtr
  let outputPtr = wasmMod.instance.exports[thisTest.wasmGlobalExportPtrOut].value
  let success = true
  let testName = `${thisTest.wasmTestFnName}(`

  if (thisTest.wasmTestFnArgs) {
    testName += thisTest.wasmTestFnArgs.join(',')
  }
  testName += ')'

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

const sha3Padding256 = sha3PaddingForRate(256)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
export {
  sha3Padding256,
  runTest,
  defineState,
}
