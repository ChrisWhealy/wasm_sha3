#!/usr/bin/env node

// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

import { startWasm } from "./utils/wasi.mjs"
import { runTest } from "./utils/test_utils.mjs"
import { testData } from "./utils/test_data.mjs"

let sha3Module = await startWasm()

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
runTest(sha3Module, testData.xorDataWithRate)
// runTest(sha3Module, testData.thetaC1)
// runTest(sha3Module, testData.thetaC2)
// runTest(sha3Module, testData.thetaC3)
// runTest(sha3Module, testData.thetaC4)
// runTest(sha3Module, testData.thetaC)
// runTest(sha3Module, testData.thetaD)
// runTest(sha3Module, testData.thetaXorLoop)
// runTest(sha3Module, testData.testTheta)
// runTest(sha3Module, testData.testRho)
// runTest(sha3Module, testData.testPi)
// runTest(sha3Module, testData.testChi)
// runTest(sha3Module, testData.testIota)
// runTest(sha3Module, testData.testThetaRho)
// runTest(sha3Module, testData.testThetaRhoPi)
// runTest(sha3Module, testData.testThetaRhoPiChi)
// runTest(sha3Module, testData.testThetaRhoPiChiIota)
// runTest(sha3Module, testData.testKeccak1)
// runTest(sha3Module, testData.testKeccak2)
// runTest(sha3Module, testData.testKeccak24)
