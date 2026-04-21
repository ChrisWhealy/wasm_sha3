#!/usr/bin/env node

process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

import { writeFileSync } from 'node:fs'
import { startSha3Wasm, startTestWasm } from './utils/wasi.mjs'

const inputStr = "The quick brown fox jumps over the lazy dog"
const input = new TextEncoder().encode(inputStr)

// Build padded input for a given digest length
const makePadded = digestLen => {
  const rateBytes = (1600 - digestLen * 2) / 8
  const block = new Uint8Array(rateBytes)
  block.set(input)
  block[input.length] = 0x06
  block[rateBytes - 1] = 0x80
  return block
}

// Format a Uint8Array as a JS array literal with 8 bytes per line
const fmtBytes = (arr, indent = '  ') => {
  const lines = []
  for (let i = 0; i < arr.length; i += 8) {
    const row = Array.from(arr.slice(i, i + 8)).map(b => '0x' + b.toString(16).padStart(2, '0'))
    lines.push(indent + row.join(', ') + ',')
  }
  return lines.join('\n')
}

// Capture output of a test function from a fresh WASM instance
const run = async (testFnName, testFnArgs, inputData, outPtrName, outBytes) => {
  const wasmMod = await startSha3Wasm('./bin/sha3.wasm', true)
  const testMod = await startTestWasm(wasmMod)
  const exports = wasmMod.instance.exports
  const mem = new Uint8Array(exports.memory.buffer)

  for (const { writeToPtr, inputData: data } of inputData) {
    const ptr = exports[writeToPtr].value
    mem.set(data, ptr)
  }

  const fn = testMod.instance.exports[testFnName]
  if (testFnArgs && testFnArgs.length > 0) fn(...testFnArgs)
  else fn()

  const outPtr = exports[outPtrName].value
  return new Uint8Array(mem.slice(outPtr, outPtr + outBytes))
}

for (const digestLen of [224, 256, 384, 512]) {
  console.log(`Generating digest_${digestLen}.mjs ...`)

  const padded = makePadded(digestLen)
  const rateWords = (1600 - digestLen * 2) / 64
  const rateBytes = rateWords * 8
  const capacityBytes = 200 - rateBytes

  // Helper: run with padded input written to DATA_PTR
  const runPadded = (fnName, args, outPtr, outBytes) =>
    run(fnName, args, [{ writeToPtr: 'DATA_PTR', inputData: padded }], outPtr, outBytes)

  // 1. XOR_DATA_WITH_RATE_RESULT — 200 bytes from RATE_PTR (= STATE_PTR)
  const XOR_DATA_WITH_RATE_RESULT = await runPadded('test_xor_data_with_rate', [digestLen], 'RATE_PTR', 200)

  // 2. THETA_C_N_RESULT — 40 bytes from THETA_C_OUT_PTR (n=1..5)
  const THETA_C_1_RESULT = await runPadded('test_theta_c', [digestLen, 1], 'THETA_C_OUT_PTR', 40)
  const THETA_C_2_RESULT = await runPadded('test_theta_c', [digestLen, 2], 'THETA_C_OUT_PTR', 40)
  const THETA_C_3_RESULT = await runPadded('test_theta_c', [digestLen, 3], 'THETA_C_OUT_PTR', 40)
  const THETA_C_4_RESULT = await runPadded('test_theta_c', [digestLen, 4], 'THETA_C_OUT_PTR', 40)
  const THETA_C_RESULT   = await runPadded('test_theta_c', [digestLen, 5], 'THETA_C_OUT_PTR', 40)

  // 3. THETA_D_RESULT — 40 bytes from THETA_D_OUT_PTR
  const THETA_D_RESULT = await runPadded('test_theta_d', [digestLen], 'THETA_D_OUT_PTR', 40)

  // 4. THETA_XOR_LOOP_RESULT — uses artificial inputs; keep THETA_D_OUT_FOR_XOR_LOOP and
  //    THETA_A_BLK_FOR_XOR_LOOP from the existing file as the designed inputs
  const { THETA_D_OUT_FOR_XOR_LOOP, THETA_A_BLK_FOR_XOR_LOOP } =
    await import(`./test_data/digest_${digestLen}.mjs`)

  const THETA_XOR_LOOP_RESULT = await run(
    'test_theta_xor_loop', [digestLen],
    [
      { writeToPtr: 'THETA_D_OUT_PTR',  inputData: new Uint8Array(THETA_D_OUT_FOR_XOR_LOOP) },
      { writeToPtr: 'THETA_A_BLK_PTR',  inputData: new Uint8Array(THETA_A_BLK_FOR_XOR_LOOP) },
    ],
    'THETA_RESULT_PTR', 200
  )

  // 5. THETA_RESULT — 200 bytes from THETA_RESULT_PTR
  const THETA_RESULT = await runPadded('test_theta', [digestLen], 'THETA_RESULT_PTR', 200)

  // 6. RHO_RESULT — write THETA_RESULT to THETA_RESULT_PTR, call test_rho, read RHO_RESULT_PTR
  const RHO_RESULT = await run(
    'test_rho', [],
    [{ writeToPtr: 'THETA_RESULT_PTR', inputData: THETA_RESULT }],
    'RHO_RESULT_PTR', 200
  )

  // 7. PI_RESULT — write RHO_RESULT to RHO_RESULT_PTR, call test_pi, read PI_RESULT_PTR
  const PI_RESULT = await run(
    'test_pi', [],
    [{ writeToPtr: 'RHO_RESULT_PTR', inputData: RHO_RESULT }],
    'PI_RESULT_PTR', 200
  )

  // 8. CHI_RESULT — write PI_RESULT to PI_RESULT_PTR, call test_chi, read CHI_RESULT_PTR
  const CHI_RESULT = await run(
    'test_chi', [],
    [{ writeToPtr: 'PI_RESULT_PTR', inputData: PI_RESULT }],
    'CHI_RESULT_PTR', 200
  )

  // 9. IOTA_RESULT — write CHI_RESULT to CHI_RESULT_PTR, call test_iota, read CHI_RESULT_PTR
  const IOTA_RESULT = await run(
    'test_iota', [],
    [{ writeToPtr: 'CHI_RESULT_PTR', inputData: CHI_RESULT }],
    'CHI_RESULT_PTR', 200
  )

  // 10. KECCAK_2_RESULT — 200 bytes from CHI_RESULT_PTR after test_keccak(digestLen, 2)
  const KECCAK_2_RESULT = await runPadded('test_keccak', [digestLen, 2], 'CHI_RESULT_PTR', 200)

  // 11. KECCAK_24 full sponge — 200 bytes from STATE_PTR after test_sponge(digestLen)
  const full = await runPadded('test_sponge', [digestLen], 'STATE_PTR', 200)
  const KECCAK_24_RATE     = full.slice(0, rateBytes)
  const KECCAK_24_CAPACITY = full.slice(rateBytes)

  const out = `\
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Expected test results for digest length of ${digestLen} bits
// Rate = ${rateWords} words
// Capacity = ${25 - rateWords} words
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
export const XOR_DATA_WITH_RATE_RESULT = [
${fmtBytes(XOR_DATA_WITH_RATE_RESULT)}
]

export const THETA_C_1_RESULT = [
${fmtBytes(THETA_C_1_RESULT)}
]

export const THETA_C_2_RESULT = [
${fmtBytes(THETA_C_2_RESULT)}
]

export const THETA_C_3_RESULT = [
${fmtBytes(THETA_C_3_RESULT)}
]

export const THETA_C_4_RESULT = [
${fmtBytes(THETA_C_4_RESULT)}
]

export const THETA_C_RESULT = [
${fmtBytes(THETA_C_RESULT)}
]

export const THETA_D_RESULT = [
${fmtBytes(THETA_D_RESULT)}
]

export const THETA_D_OUT_FOR_XOR_LOOP = [
${fmtBytes(new Uint8Array(THETA_D_OUT_FOR_XOR_LOOP))}
]

export const THETA_A_BLK_FOR_XOR_LOOP = [
${fmtBytes(new Uint8Array(THETA_A_BLK_FOR_XOR_LOOP))}
]

export const THETA_XOR_LOOP_RESULT = [
${fmtBytes(THETA_XOR_LOOP_RESULT)}
]

export const THETA_RESULT = [
${fmtBytes(THETA_RESULT)}
]

export const RHO_RESULT = [
${fmtBytes(RHO_RESULT)}
]

export const PI_RESULT = [
${fmtBytes(PI_RESULT)}
]

export const CHI_RESULT = [
${fmtBytes(CHI_RESULT)}
]

export const IOTA_RESULT = [
${fmtBytes(IOTA_RESULT)}
]

export const KECCAK_2_RESULT = [
${fmtBytes(KECCAK_2_RESULT)}
]

// Rate size = ${rateBytes * 8} for w=64
export const KECCAK_24_RATE = [
${fmtBytes(KECCAK_24_RATE)}
]

export const KECCAK_24_CAPACITY = [
${fmtBytes(KECCAK_24_CAPACITY)}
]
`

  writeFileSync(`./test_data/digest_${digestLen}.mjs`, out)
}

console.log('Done.')
