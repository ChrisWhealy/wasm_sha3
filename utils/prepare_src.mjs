#!/usr/bin/env node

// Strip comment-delimited blocks from sha3.wat and write the result to an intermediate .wat file.
//
// Usage: prepare_src.mjs <debug|test|debug test>
//
//   debug       removes ;;@debug-start … ;;@debug-end blocks  → sha3.dev.wat
//   test        removes ;;@test-start  … ;;@test-end  blocks  → sha3.dev.wat
//   debug test  removes both (pipelined: debug first, then test) → sha3.prod.wat
import { readFileSync, writeFileSync } from 'node:fs'

const modes = process.argv.slice(2)

if (modes.length === 0 || modes.some(m => m !== 'debug' && m !== 'test')) {
  console.error(`Usage: prepare_src.mjs <debug|test|debug test>`)
  process.exit(1)
}

const markerRe = mode => {
  const prefix = mode === 'debug' ? ';;@debug' : ';;@test'
  return new RegExp(`[ \\t]*${prefix}-start[\\s\\S]*?${prefix}-end[^\\n]*\\n(\\n)?`, 'g')
}

const stripped = modes.reduce(
  (src, mode) => src.replace(markerRe(mode), ''),
  readFileSync('./src/sha3.wat', 'utf8')
).replace(/\n{3,}/g, '\n\n')

const outFile = (modes.includes('debug') && modes.includes('test'))
  ? './src/sha3.prod.wat'
  : './src/sha3.dev.wat'

writeFileSync(outFile, stripped)
