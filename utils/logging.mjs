import { u64AsHexStr, u32AsHexStr } from "./binary_utils.mjs"
import { debugLabels, debugMsgs } from "./debug_msgs.mjs"

const fnEnter = "===>"
const fnExit = "<==="

const logFnName = fnId => debugMsgs[fnId].fnName
const logFnMsg = (fnId, msgId) => debugMsgs[fnId].msgId[msgId]
const logMsgHdr = (fnId, msgId) => `${logFnName(fnId)} ${logFnMsg(fnId, msgId)}`

const logFnBoundary = fnDirection => fnId => console.log(`${fnDirection} ${logFnName(fnId)}`)

const logFnEnter = logFnBoundary(fnEnter)
const logFnExit = logFnBoundary(fnExit)

const doFnEnter = (isDebug, fnId) => isDebug ? console.log(logFnEnter(fnId)) : {}
const doFnExit = (isDebug, fnId) => isDebug ? console.log(logFnExit(fnId)) : {}
const doFnEnterNth = (isDebug, fnId, n) => isDebug ? console.log(`${logFnEnter(fnId)} ${n}`) : {}
const doFnExitNth = (isDebug, fnId, n) => isDebug ? console.log(`${logFnExit(fnId)} ${n}`) : {}

const singleI64 = (isDebug, fnId, msgId, i64) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)} = ${u64AsHexStr(i64)}`) : {}
const singleI32 = (isDebug, fnId, msgId, i32) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)} = ${u32AsHexStr(i32)}`) : {}
const singleDec = (isDebug, fnId, msgId, dec) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)} = ${dec}`) : {}
const mappedPair = (isDebug, fnId, msgId, v1, v2) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)}: ${v1} -> ${v2}`) : {}
const coordPair = (isDebug, fnId, msgId, v1, v2) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)} = (${v1},${v2})`) : {}
const singleBigInt = (isDebug, fnId, msgId, i64) => isDebug ? console.log(`${logMsgHdr(fnId, msgId)} = ${i64}`) : {}
const label = (isDebug, labelId) => isDebug ? console.log(debugLabels[labelId]) : {}

export {
  doFnEnter,
  doFnExit,
  doFnEnterNth,
  doFnExitNth,
  singleI64,
  singleI32,
  singleDec,
  mappedPair,
  coordPair,
  singleBigInt,
  label,
}
