#!/usr/bin/env node

import { readFileSync, writeFileSync } from 'node:fs'

const src = readFileSync('./src/sha3.wat', 'utf8')
const stripped = src.replace(/;;@debug-start[\s\S]*?;;@debug-end?/g, '')

writeFileSync('./src/sha3.prod.wat', stripped)
