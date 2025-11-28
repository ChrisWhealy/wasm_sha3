#!/usr/bin/env node

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const DIGEST_LENGTH = '256'
const INPUT_STR = "The quick brown fox jumps over the lazy dog"

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { testWasmFn, PAD_MARKER_START, PAD_MARKER_END, sha3PaddingForDigest } from "./utils/test_utils.mjs"

const TEST_MOD = await (d => import(`./test_data/digest_${d}.mjs`))(DIGEST_LENGTH)
TEST_MOD.INPUT_DATA.value = sha3PaddingForDigest(DIGEST_LENGTH, INPUT_STR)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Test that the generated rate block has been padded correctly
test('Rate block padding', () => {
  assert.equal(
    TEST_MOD.INPUT_DATA.value[INPUT_STR.length],
    PAD_MARKER_START,
    `Pad marker start byte should be 0x${PAD_MARKER_START.toString(16)}`
  )
  assert.equal(
    TEST_MOD.INPUT_DATA.value[TEST_MOD.INPUT_DATA.value.length - 1],
    PAD_MARKER_END,
    `Pad marker end byte should be 0x${PAD_MARKER_END.toString(16)}`
  )
})

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Test SHA3 WASM functions
testWasmFn(TEST_MOD.testXorDataWithRate)
testWasmFn(TEST_MOD.testThetaC1)
testWasmFn(TEST_MOD.testThetaC2)
testWasmFn(TEST_MOD.testThetaC3)
testWasmFn(TEST_MOD.testThetaC4)
testWasmFn(TEST_MOD.testThetaC)
testWasmFn(TEST_MOD.testThetaD)
testWasmFn(TEST_MOD.testThetaXorLoop)
testWasmFn(TEST_MOD.testTheta)
testWasmFn(TEST_MOD.testRho)
testWasmFn(TEST_MOD.testPi)
testWasmFn(TEST_MOD.testChi)
testWasmFn(TEST_MOD.testIota)
testWasmFn(TEST_MOD.testThetaRho)
testWasmFn(TEST_MOD.testThetaRhoPi)
testWasmFn(TEST_MOD.testThetaRhoPiChi)
testWasmFn(TEST_MOD.testThetaRhoPiChiIota)
testWasmFn(TEST_MOD.testKeccak1)
testWasmFn(TEST_MOD.testKeccak2)
testWasmFn(TEST_MOD.testKeccak24)
