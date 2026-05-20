#!/usr/bin/env node

// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

import { readFileSync } from 'fs'
import { SHA3Sponge } from './SHA3Sponge.mjs'

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
let digestLen, domainByte, outputBytes, filePath

const USAGE = 'Usage: sha3sum.mjs <224|256|384|512> <file>\n'
            + '   or: sha3sum.mjs <shake128|shake256> <bytes> <file>\n'

const argv = process.argv.slice(2)
const dev = argv.includes('--dev')
const args = argv.filter(a => a !== '--dev')
const [algo, ...rest] = args

if (!algo) {
  process.stderr.write(USAGE)
  process.exit(1)
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
const sponge = await SHA3Sponge.create(!dev)

// Parse and then validate the arguments
if (algo === 'shake128' || algo === 'shake256') {
  digestLen = algo === 'shake128' ? 128 : 256
  domainByte = sponge.DOMAIN_SHAKE
  outputBytes = parseInt(rest[0], 10)
  filePath = rest[1]
} else {
  digestLen = parseInt(algo, 10)
  domainByte = sponge.DOMAIN_SHA3
  outputBytes = digestLen / 8
  filePath = rest[0]
}

if (!filePath || isNaN(outputBytes)) {
  process.stderr.write(USAGE)
  process.exit(1)
}

// sponge.init() validates the digestLen/domainByte combination and throws RangeError if invalid
const data = readFileSync(filePath)
const digest = sponge.init(digestLen, domainByte).absorb(data).finalize().squeeze(outputBytes)
const hex = Buffer.from(digest).toString('hex')

if (domainByte === sponge.DOMAIN_SHA3) {
  process.stdout.write(`${hex}  ${filePath}\n`)
} else {
  process.stdout.write(`${hex}\n`)
}
