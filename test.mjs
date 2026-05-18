#!/usr/bin/env node

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { testWasmFn, PAD_MARKER_START, PAD_MARKER_END, sha3PaddingForDigest } from "./utils/test_utils.mjs"

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const isProd = process.argv[2] === 'prod'

const inputStr = "The quick brown fox jumps over the lazy dog"
const digestLengths = [224, 256, 384, 512]

for (const digestLength of digestLengths) {
  const paddedInputBlk = sha3PaddingForDigest(digestLength, inputStr)
  const testData = await import(`./test_data/digest_${digestLength}.mjs`)

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testXorDataWithRate = {
    wasmTestFnName: "test_xor_data_with_rate",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "RATE_PTR",
    expected: testData.XOR_DATA_WITH_RATE_RESULT
  }
  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testTheta = {
    wasmTestFnName: "test_theta",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "THETA_RESULT_PTR",
    expected: testData.THETA_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testRho = {
    wasmTestFnName: "test_rho",
    wasmInputData: [
      { writeToPtr: "THETA_RESULT_PTR", inputData: testData.THETA_RESULT },
    ],
    wasmGlobalExportPtrOut: "RHO_RESULT_PTR",
    expected: testData.RHO_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testPi = {
    wasmTestFnName: "test_pi",
    wasmInputData: [
      { writeToPtr: "RHO_RESULT_PTR", inputData: testData.RHO_RESULT },
    ],
    wasmGlobalExportPtrOut: "PI_RESULT_PTR",
    expected: testData.PI_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testChi = {
    wasmTestFnName: "test_chi",
    wasmInputData: [
      { writeToPtr: "PI_RESULT_PTR", inputData: testData.PI_RESULT },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.CHI_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testIota = {
    wasmTestFnName: "test_iota",
    wasmInputData: [
      { writeToPtr: "CHI_RESULT_PTR", inputData: testData.CHI_RESULT },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.IOTA_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testThetaRho = {
    wasmTestFnName: "test_theta_rho",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "RHO_RESULT_PTR",
    expected: testData.RHO_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testThetaRhoPi = {
    wasmTestFnName: "test_theta_rho_pi",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "PI_RESULT_PTR",
    expected: testData.PI_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testThetaRhoPiChi = {
    wasmTestFnName: "test_theta_rho_pi_chi",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.CHI_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testThetaRhoPiChiIota = {
    wasmTestFnName: "test_theta_rho_pi_chi_iota",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.IOTA_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testKeccak1 = {
    wasmTestFnName: "test_keccak",
    wasmTestFnArgs: [digestLength, 1],
    wasmInputData: [
      { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.IOTA_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testKeccak2 = {
    wasmTestFnName: "test_keccak",
    wasmTestFnArgs: [digestLength, 2],
    wasmInputData: [
      { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.KECCAK_2_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testSponge = {
    wasmTestFnName: "test_sponge",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "DATA_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "STATE_PTR",
    expected: [
      ...testData.KECCAK_24_RATE,
      ...testData.KECCAK_24_CAPACITY,
    ]
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  const testGetCmdLineArgs = {
    wasmTestFnName: "test_get_command_line_args",
    wasmInputData: [],
    wasmGlobalExportPtrOut: "CMD_LINE_ARGS_PTR",
    expected: []
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Test that the generated rate block has been padded correctly
  // test(`\n---- Rate block padding for digest length ${digestLength} ----`, () => {
  //   assert.equal(
  //     paddedInputBlk[inputStr.length],
  //     PAD_MARKER_START,
  //     `Pad marker start byte should be 0x${PAD_MARKER_START.toString(16)}`
  //   )
  //   assert.equal(
  //     paddedInputBlk[paddedInputBlk.length - 1],
  //     PAD_MARKER_END,
  //     `Pad marker end byte should be 0x${PAD_MARKER_END.toString(16)}`
  //   )
  // })

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Test SHA3 WASM functions
  testWasmFn(testXorDataWithRate, isProd)
  testWasmFn(testTheta, isProd)
  testWasmFn(testRho, isProd)
  testWasmFn(testPi, isProd)
  testWasmFn(testChi, isProd)
  testWasmFn(testIota, isProd)
  testWasmFn(testThetaRho, isProd)
  testWasmFn(testThetaRhoPi, isProd)
  testWasmFn(testThetaRhoPiChi, isProd)
  testWasmFn(testThetaRhoPiChiIota, isProd)
  testWasmFn(testKeccak1, isProd)
  testWasmFn(testKeccak2, isProd)
  testWasmFn(testSponge, isProd)
}
