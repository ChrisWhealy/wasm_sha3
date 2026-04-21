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
const inputStr = "The quick brown fox jumps over the lazy dog"


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const testGetCmdLineArgs = {
  wasmTestFnName: "test_get_command_line_args",
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
// Test SHA3 WASM functions
testWasmFn(testXorDataWithRate)
