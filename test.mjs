#!/usr/bin/env node

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { testWasmFn, PAD_MARKER_START, PAD_MARKER_END, sha3PaddingForDigest } from "./utils/test_utils.mjs"

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const digestLength = 224
const inputStr = "The quick brown fox jumps over the lazy dog"
const paddedInputBlk = sha3PaddingForDigest(digestLength, inputStr)
const testData = await import(`./test_data/digest_${digestLength}.mjs`)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testXorDataWithRate = {
  wasmTestFnName: "test_xor_data_with_rate",
  wasmTestFnArgs: [digestLength],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "RATE_PTR",
  expected: testData.XOR_DATA_WITH_RATE_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testThetaC1 = {
  wasmTestFnName: "test_theta_c",
  wasmTestFnArgs: [digestLength, 1],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "THETA_C_OUT_PTR",
  expected: testData.THETA_C_1_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testThetaC2 = {
  wasmTestFnName: "test_theta_c",
  wasmTestFnArgs: [digestLength, 2],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "THETA_C_OUT_PTR",
  expected: testData.THETA_C_2_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testThetaC3 = {
  wasmTestFnName: "test_theta_c",
  wasmTestFnArgs: [digestLength, 3],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "THETA_C_OUT_PTR",
  expected: testData.THETA_C_3_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testThetaC4 = {
  wasmTestFnName: "test_theta_c",
  wasmTestFnArgs: [digestLength, 4],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "THETA_C_OUT_PTR",
  expected: testData.THETA_C_4_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testThetaC = {
  wasmTestFnName: "test_theta_c",
  wasmTestFnArgs: [digestLength, 5],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "THETA_C_OUT_PTR",
  expected: testData.THETA_C_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testThetaD = {
  wasmTestFnName: "test_theta_d",
  wasmTestFnArgs: [digestLength],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "THETA_D_OUT_PTR",
  expected: testData.THETA_D_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testThetaXorLoop = {
  wasmTestFnName: "test_theta_xor_loop",
  wasmTestFnArgs: [digestLength],
  wasmInputData: [
    { writeToPtr: "THETA_D_OUT_PTR", inputData: testData.THETA_D_OUT_FOR_XOR_LOOP },
    { writeToPtr: "THETA_A_BLK_PTR", inputData: testData.THETA_A_BLK_FOR_XOR_LOOP },
  ],
  wasmGlobalExportPtrOut: "THETA_RESULT_PTR",
  expected: testData.THETA_XOR_LOOP_RESULT,
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testTheta = {
  wasmTestFnName: "test_theta",
  wasmTestFnArgs: [digestLength],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "THETA_RESULT_PTR",
  expected: testData.THETA_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testRho = {
  wasmTestFnName: "rho",
  wasmInputData: [
    { writeToPtr: "THETA_RESULT_PTR", inputData: testData.THETA_RESULT },
  ],
  wasmGlobalExportPtrOut: "RHO_RESULT_PTR",
  expected: testData.RHO_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testPi = {
  wasmTestFnName: "pi",
  wasmInputData: [
    { writeToPtr: "RHO_RESULT_PTR", inputData: testData.RHO_RESULT },
  ],
  wasmGlobalExportPtrOut: "PI_RESULT_PTR",
  expected: testData.PI_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testChi = {
  wasmTestFnName: "chi",
  wasmInputData: [
    { writeToPtr: "PI_RESULT_PTR", inputData: testData.PI_RESULT },
  ],
  wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
  expected: testData.CHI_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testIota = {
  wasmTestFnName: "test_iota",
  wasmInputData: [
    { writeToPtr: "CHI_RESULT_PTR", inputData: testData.CHI_RESULT },
  ],
  wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
  expected: testData.IOTA_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testThetaRho = {
  wasmTestFnName: "test_theta_rho",
  wasmTestFnArgs: [digestLength],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "RHO_RESULT_PTR",
  expected: testData.RHO_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testThetaRhoPi = {
  wasmTestFnName: "test_theta_rho_pi",
  wasmTestFnArgs: [digestLength],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "PI_RESULT_PTR",
  expected: testData.PI_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testThetaRhoPiChi = {
  wasmTestFnName: "test_theta_rho_pi_chi",
  wasmTestFnArgs: [digestLength],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
  expected: testData.CHI_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testThetaRhoPiChiIota = {
  wasmTestFnName: "test_theta_rho_pi_chi_iota",
  wasmTestFnArgs: [digestLength],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
  expected: testData.IOTA_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testKeccak1 = {
  wasmTestFnName: "test_keccak",
  wasmTestFnArgs: [digestLength],
  wasmTestFnArgs: [1],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
  expected: testData.IOTA_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testKeccak2 = {
  wasmTestFnName: "test_keccak",
  wasmTestFnArgs: [digestLength],
  wasmTestFnArgs: [2],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
  expected: testData.KECCAK_2_RESULT
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testKeccak24 = {
  wasmTestFnName: "test_keccak",
  wasmTestFnArgs: [digestLength],
  wasmTestFnArgs: [24],
  wasmInputData: [
    { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
  ],
  wasmGlobalExportPtrOut: "STATE_PTR",
  expected: [
    ...testData.KECCAK_24_RATE,
    ...testData.KECCAK_24_CAPACITY,
  ]
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Test that the generated rate block has been padded correctly
test('Rate block padding', () => {
  assert.equal(
    paddedInputBlk[inputStr.length],
    PAD_MARKER_START,
    `Pad marker start byte should be 0x${PAD_MARKER_START.toString(16)}`
  )
  assert.equal(
    paddedInputBlk[paddedInputBlk.length - 1],
    PAD_MARKER_END,
    `Pad marker end byte should be 0x${PAD_MARKER_END.toString(16)}`
  )
})

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Test SHA3 WASM functions
// testWasmFn(testXorDataWithRate)
testWasmFn(testThetaC1)
testWasmFn(testThetaC2)
testWasmFn(testThetaC3)
testWasmFn(testThetaC4)
testWasmFn(testThetaC)
testWasmFn(testThetaD)
testWasmFn(testThetaXorLoop)
testWasmFn(testTheta)
testWasmFn(testRho)
// testWasmFn(testPi)
// testWasmFn(testChi)
// testWasmFn(testIota)
// testWasmFn(testThetaRho)
// testWasmFn(testThetaRhoPi)
// testWasmFn(testThetaRhoPiChi)
// testWasmFn(testThetaRhoPiChiIota)
// testWasmFn(testKeccak1)
// testWasmFn(testKeccak2)
// testWasmFn(testKeccak24)
