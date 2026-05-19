#!/usr/bin/env node

import { readFileSync } from 'fs'
import { createSponge } from './SHA3Sponge.mjs'

const PATH_TO_WASM_BIN  = './bin/sha3.prod.opt.wasm'
const PATH_TO_TEST_FILE = './test_data/war_and_peace.txt'
const DOMAIN_SUFFIX_SHAKE = 0x1f
const DOMAIN_SUFFIX_SHA3  = 0x06

const makeSponge = async (digestLen, suffixByte) => {
  const sponge = await createSponge(PATH_TO_WASM_BIN)
  sponge.init(digestLen, suffixByte).absorb(readFileSync(PATH_TO_TEST_FILE)).finalize()
  return sponge
}

const input = readFileSync(PATH_TO_TEST_FILE)

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// SHAKE128: squeeze 200 bytes in three separate calls
let s1 = await makeSponge(128, DOMAIN_SUFFIX_SHAKE)

const part1 = s1.squeeze(32)
const part2 = s1.squeeze(32)
const part3 = s1.squeeze(136)  // 32+32+136 = 200 bytes total

const combined = Buffer.concat([part1, part2, part3]).toString('hex')
console.log('SHAKE128 (200 bytes, 3 calls):')
console.log(combined)

// Compare: same 200 bytes in a single call using a fresh sponge
const s2 = await makeSponge(128, DOMAIN_SUFFIX_SHAKE)
console.log('\nSHAKE128 (200 bytes, 1 call):')
console.log(Buffer.from(s2.squeeze(200)).toString('hex'))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// SHA3: 224-bit hash
const s3 = await makeSponge(224, DOMAIN_SUFFIX_SHA3)
console.log(`\nSHA3 224-bit digest: ${Buffer.from(s3.squeeze(224 >> 3)).toString('hex')}  ${PATH_TO_TEST_FILE}`)

// SHA3: 256-bit hash
const s4 = await makeSponge(256, DOMAIN_SUFFIX_SHA3)
console.log(`SHA3 256-bit digest: ${Buffer.from(s4.squeeze(256 >> 3)).toString('hex')}  ${PATH_TO_TEST_FILE}`)

// SHA3: 384-bit hash
const s5 = await makeSponge(384, DOMAIN_SUFFIX_SHA3)
console.log(`SHA3 384-bit digest: ${Buffer.from(s5.squeeze(384 >> 3)).toString('hex')}  ${PATH_TO_TEST_FILE}`)

// SHA3: 512-bit hash
const s6 = await makeSponge(512, DOMAIN_SUFFIX_SHA3)
console.log(`SHA3 512-bit digest: ${Buffer.from(s6.squeeze(512 >> 3)).toString('hex')}  ${PATH_TO_TEST_FILE}`)
