#!/usr/bin/env node

// Strip out the debug code occurring between the markers ;;@debug-start and ;;@debug-end in a .wat file
// Write the result to a corresponding .prod.wat file.
import { readFileSync, writeFileSync } from 'node:fs'

const src = readFileSync('./src/sha3.wat', 'utf8')
const stripped = src
  .replace(/[ \t]*;;@debug-start[\s\S]*?;;@debug-end[^\n]*\n(\n)?/g, '')
  .replace(/\n{3,}/g, '\n\n')

writeFileSync('./src/sha3.prod.wat', stripped)
