#!/usr/bin/env node

// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { testWasmFn, PAD_MARKER_START, PAD_MARKER_END } from "./utils/test_utils.mjs"
import { INPUT_STR, DATA_BLKS, testData } from "./utils/test_data.mjs"

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
testWasmFn(testData.xorDataWithRate)
testWasmFn(testData.thetaC1)
testWasmFn(testData.thetaC2)
testWasmFn(testData.thetaC3)
testWasmFn(testData.thetaC4)
testWasmFn(testData.thetaC)
testWasmFn(testData.thetaD)
testWasmFn(testData.thetaXorLoop)
testWasmFn(testData.testTheta)
testWasmFn(testData.testRho)
testWasmFn(testData.testPi)
testWasmFn(testData.testChi)
testWasmFn(testData.testIota)
testWasmFn(testData.testThetaRho)
testWasmFn(testData.testThetaRhoPi)
testWasmFn(testData.testThetaRhoPiChi)
testWasmFn(testData.testThetaRhoPiChiIota)
testWasmFn(testData.testKeccak1)
testWasmFn(testData.testKeccak2)
testWasmFn(testData.testKeccak24)
