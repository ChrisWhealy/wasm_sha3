// Required SHA3 output digest length
// May only be one of 224, 256, 384 or 512
const DIGEST_LENGTH = 256

// Define SHA3 internal state dimensions
const LENGTH = 6
const WORD_LENGTH = 2 ** LENGTH
const STATE_SIZE = 5 * 5 * WORD_LENGTH
const RATE = STATE_SIZE - (2 * DIGEST_LENGTH)
const CAPACITY = STATE_SIZE - RATE

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const toHexFormat = byteArray => {
  const hex = Array.from(byteArray, b => '0x' + b.toString(16).padStart(2, '0'))
  let output = '[\n'

  for (let i = 0; i < hex.length; i += 8) {
    output += '  ' + hex.slice(i, i + 8).join(', ') + ',\n'
  }

  output += ']'
  return output
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Take a single block of input data (that must be smaller than the rate size) and return it as a UInt8Array padded with
// the correct bit sequence
const sha3Padding = testData => {
  const rateLenAsBytes = RATE >>> 3
  const pad1Byte = 0x61
  const padFirstByte = 0x60
  const padLastByte = 0x01

  let arr = new Uint8Array(rateLenAsBytes)
  let encoded = new TextEncoder().encode(testData)

  arr.set(encoded)

  // Insert padding
  let bytesRem = rateLenAsBytes - encoded.length

  if (bytesRem === 1) {
    arr.set(pad1Byte, encoded.length - 1)
  } else if (bytesRem === 2) {
    arr.set([padFirstByte, padLastByte], encoded.length - 2)
  } else {
    let zeroes = new Uint8Array(bytesRem - 2)
    arr.set([padFirstByte, ...zeroes, padLastByte], encoded.length)
  }

  return arr
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

  for (let idx = 0; idx < thisTest.expected.length; idx++) {
    let resultByte = wasmMem8[outputPtr + idx]
    let expectedByte = thisTest.expected[idx]

    if (resultByte != expectedByte) {
      success = false
      console.log(`${testName} error at byte ${idx}: expected ${u8AsHexStr(expectedByte)}, got ${u8AsHexStr(resultByte)}`)
    }
  }

  console.log(`${success ? "✅" : "❌"} Test ${thisTest.wasmTestFnName}`)
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
export {
  sha3Padding,
  toHexFormat,
  DIGEST_LENGTH,
  STATE_SIZE,
  RATE,
  CAPACITY,
  runTest,
}
