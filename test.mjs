#!/usr/bin/env node

// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { startWasm } from "./utils/wasi.mjs"
import { testWasmFn, PAD_MARKER_START, PAD_MARKER_END } from "./utils/test_utils.mjs"
import { INPUT_STR, DATA_BLKS, testData } from "./utils/test_data.mjs"

let sha3Module = await startWasm()

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Test that the generated rate blocks have been padded correctly
test('Rate block padding', () => {
  let dataLen = INPUT_STR.length

  for (let idx=0; idx < DATA_BLKS.length; idx++) {
    let dataBlk = DATA_BLKS[idx]

    assert.equal(dataBlk[dataLen], PAD_MARKER_START, `Pad marker start byte should be 0x${PAD_MARKER_START.toString(16)}`)
    assert.equal(dataBlk[dataBlk.length-1], PAD_MARKER_END, `Pad marker end byte should be 0x${PAD_MARKER_END.toString(16)}`)
  }
})

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Test SHA3 WASM functions
testWasmFn(sha3Module, testData.xorDataWithRate)
testWasmFn(sha3Module, testData.thetaC1)
testWasmFn(sha3Module, testData.thetaC2)
testWasmFn(sha3Module, testData.thetaC3)
testWasmFn(sha3Module, testData.thetaC4)
testWasmFn(sha3Module, testData.thetaC)
testWasmFn(sha3Module, testData.thetaD)
// testWasmFn(sha3Module, testData.thetaXorLoop)
testWasmFn(sha3Module, testData.testTheta)
testWasmFn(sha3Module, testData.testRho)
testWasmFn(sha3Module, testData.testPi)
testWasmFn(sha3Module, testData.testChi)
testWasmFn(sha3Module, testData.testIota)
testWasmFn(sha3Module, testData.testThetaRho)
testWasmFn(sha3Module, testData.testThetaRhoPi)
testWasmFn(sha3Module, testData.testThetaRhoPiChi)
testWasmFn(sha3Module, testData.testThetaRhoPiChiIota)
testWasmFn(sha3Module, testData.testKeccak1)
testWasmFn(sha3Module, testData.testKeccak2)
testWasmFn(sha3Module, testData.testKeccak24)
