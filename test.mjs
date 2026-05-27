#!/usr/bin/env node

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'fs'
import { testWasmFn, PAD_MARKER_START, PAD_MARKER_END, sha3PaddingForDigest } from "./utils/test_utils.mjs"

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const isProd = process.argv[2] === 'prod'

const inputStr = readFileSync('./test_data/qbf.txt', 'utf-8').trim()
const digestLengths = [224, 256, 384, 512]

for (const digestLength of digestLengths) {
  const paddedInputBlk = sha3PaddingForDigest(digestLength, inputStr)
  const testData = await import(`./test_data/digest_${digestLength}.mjs`)

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // XOR padded block into zeroed state — result lives at RATE_PTR (= STATE_PTR)
  const testXorDataWithRate = {
    wasmTestFnName: "test_xor_data_with_rate",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "PAD_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "RATE_PTR",
    expected: testData.XOR_DATA_WITH_RATE_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Theta result lives at THETA_RESULT_PTR (= WORK_PTR)
  const testTheta = {
    wasmTestFnName: "test_theta",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "PAD_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "THETA_RESULT_PTR",
    expected: testData.THETA_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Rho+pi fused — write theta result to WORK (THETA_RESULT_PTR), result lives at RHO_PI_RESULT_PTR (= STATE_PTR)
  // v2 rho_pi = v1 rho followed by pi, so expected output equals v1's PI_RESULT
  const testRhoPi = {
    wasmTestFnName: "test_rho_pi",
    wasmInputData: [
      { writeToPtr: "THETA_RESULT_PTR", inputData: testData.THETA_RESULT },
    ],
    wasmGlobalExportPtrOut: "RHO_PI_RESULT_PTR",
    expected: testData.PI_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Chi in-place — write rho_pi result to STATE_PTR, result stays at CHI_RESULT_PTR (= STATE_PTR)
  const testChi = {
    wasmTestFnName: "test_chi",
    wasmInputData: [
      { writeToPtr: "RHO_PI_RESULT_PTR", inputData: testData.PI_RESULT },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.CHI_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Iota round 0 in-place — result stays at CHI_RESULT_PTR (= STATE_PTR)
  const testIota = {
    wasmTestFnName: "test_iota",
    wasmInputData: [
      { writeToPtr: "CHI_RESULT_PTR", inputData: testData.CHI_RESULT },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.IOTA_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Theta → rho_pi pipeline — result at RHO_PI_RESULT_PTR
  const testThetaRhoPi = {
    wasmTestFnName: "test_theta_rho_pi",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "PAD_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "RHO_PI_RESULT_PTR",
    expected: testData.PI_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Theta → rho_pi → chi — result at CHI_RESULT_PTR
  const testThetaRhoPiChi = {
    wasmTestFnName: "test_theta_rho_pi_chi",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "PAD_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.CHI_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Theta → rho_pi → chi → iota(0) — one complete Keccak round — result at CHI_RESULT_PTR
  const testThetaRhoPiChiIota = {
    wasmTestFnName: "test_theta_rho_pi_chi_iota",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "PAD_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.IOTA_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // 1 round via sponge()
  const testKeccak1 = {
    wasmTestFnName: "test_keccak",
    wasmTestFnArgs: [digestLength, 1],
    wasmInputData: [
      { writeToPtr: "PAD_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.IOTA_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // 2 rounds via sponge()
  const testKeccak2 = {
    wasmTestFnName: "test_keccak",
    wasmTestFnArgs: [digestLength, 2],
    wasmInputData: [
      { writeToPtr: "PAD_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "CHI_RESULT_PTR",
    expected: testData.KECCAK_2_RESULT
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Full 24-round sponge — result covers the entire STATE (rate + capacity)
  const testSponge = {
    wasmTestFnName: "test_sponge",
    wasmTestFnArgs: [digestLength],
    wasmInputData: [
      { writeToPtr: "PAD_PTR", inputData: paddedInputBlk },
    ],
    wasmGlobalExportPtrOut: "STATE_PTR",
    expected: [
      ...testData.KECCAK_24_RATE,
      ...testData.KECCAK_24_CAPACITY,
    ]
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  testWasmFn(testXorDataWithRate, isProd)
  testWasmFn(testTheta, isProd)
  testWasmFn(testRhoPi, isProd)
  testWasmFn(testChi, isProd)
  testWasmFn(testIota, isProd)
  testWasmFn(testThetaRhoPi, isProd)
  testWasmFn(testThetaRhoPiChi, isProd)
  testWasmFn(testThetaRhoPiChiIota, isProd)
  testWasmFn(testKeccak1, isProd)
  testWasmFn(testKeccak2, isProd)
  testWasmFn(testSponge, isProd)
}
