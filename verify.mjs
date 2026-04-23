#!/usr/bin/env node

// End-to-end verification: SHA3-256("The quick brown fox jumps over the lazy dog")
// Expected: 69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04

process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

import { createHash } from 'node:crypto'
import { startSha3Wasm } from './utils/wasi.mjs'

const inputStr = "The quick brown fox jumps over the lazy dog"
const DIGEST_LEN = 256
const RATE_BYTES = (1600 - DIGEST_LEN * 2) / 8  // 136 bytes for SHA3-256

// Build padded input block (SHA3 domain separator 0x06, end pad 0x80)
const input = new TextEncoder().encode(inputStr)
const paddedBlock = new Uint8Array(RATE_BYTES)
paddedBlock.set(input)
paddedBlock[input.length] = 0x06
paddedBlock[RATE_BYTES - 1] = 0x80

const wasmMod = await startSha3Wasm('./bin/sha3.prod.opt.wasm', true)
const exports = wasmMod.instance.exports
const mem = new Uint8Array(exports.memory.buffer)

// Write padded block to DATA_PTR
const dataPtr = exports.DATA_PTR.value
mem.set(paddedBlock, dataPtr)

// Run full 24-round sponge
exports.sponge(DIGEST_LEN, 24)

// Read rate portion (first 32 bytes = SHA3-256 digest) from STATE_PTR
const statePtr = exports.STATE_PTR.value
const digest = mem.slice(statePtr, statePtr + 32)
const got = Buffer.from(digest).toString('hex')

// Reference via Node.js built-in
const expected = createHash('sha3-256').update(inputStr).digest('hex')

console.log('Expected:', expected)
console.log('Got:     ', got)
console.log(got === expected ? '✓ PASS' : '✗ FAIL')
