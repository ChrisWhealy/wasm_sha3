#!/usr/bin/env node

import { readFileSync } from 'fs'
import { SHA3Sponge } from './SHA3Sponge.mjs'

const PATH_TO_TEST_FILE = './test_data/war_and_peace.txt'
const input = readFileSync(PATH_TO_TEST_FILE)

// Read domain constants once; makeSponge creates its own instance per call
const probe        = await SHA3Sponge.create()
const DOMAIN_SHA3  = probe.DOMAIN_SHA3
const DOMAIN_SHAKE = probe.DOMAIN_SHAKE

const makeSponge = async (digestLen, domainByte = DOMAIN_SHA3) => {
  const sponge = await SHA3Sponge.create()
  sponge.init(digestLen, domainByte).absorb(input).finalize()
  return sponge
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// SHAKE128: squeeze 200 bytes in three separate calls
const s1 = await makeSponge(128, DOMAIN_SHAKE)

const part1 = s1.squeeze(32)
const part2 = s1.squeeze(32)
const part3 = s1.squeeze(136)  // 32+32+136 = 200 bytes total

console.log('SHAKE128 (200 bytes, 3 calls):')
console.log(Buffer.concat([part1, part2, part3]).toString('hex'))

// Compare: same 200 bytes in a single call using a fresh sponge
const s2 = await makeSponge(128, DOMAIN_SHAKE)
console.log('\nSHAKE128 (200 bytes, 1 call):')
console.log(Buffer.from(s2.squeeze(200)).toString('hex'))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// SHA3 fixed-length digests
const s3 = await makeSponge(224)
console.log(`\nSHA3 224-bit digest: ${Buffer.from(s3.squeeze(224 >> 3)).toString('hex')}  ${PATH_TO_TEST_FILE}`)

const s4 = await makeSponge(256)
console.log(`SHA3 256-bit digest: ${Buffer.from(s4.squeeze(256 >> 3)).toString('hex')}  ${PATH_TO_TEST_FILE}`)

const s5 = await makeSponge(384)
console.log(`SHA3 384-bit digest: ${Buffer.from(s5.squeeze(384 >> 3)).toString('hex')}  ${PATH_TO_TEST_FILE}`)

const s6 = await makeSponge(512)
console.log(`SHA3 512-bit digest: ${Buffer.from(s6.squeeze(512 >> 3)).toString('hex')}  ${PATH_TO_TEST_FILE}`)
