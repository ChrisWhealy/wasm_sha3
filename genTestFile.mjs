#! /usr/bin/env node

import { writeFileSync } from 'fs'
import { DATA_BLK_1, DATA_BLK_2 } from './utils/test_data.mjs'

const writeTestFile = filename => {
  const data = new Uint8Array([...DATA_BLK_1, ...DATA_BLK_2])
  writeFileSync(filename, data)
}

writeTestFile("testfile2.bin")
