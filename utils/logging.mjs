import { u64AsHexStr, u32AsHexStr } from "./binary_utils.mjs"
import { debugLabels, debugMsgs } from "./debug_msgs.mjs"

const fnEnterMark = "===>"
const fnExitMark = "<==="

const getFnName = fnId => debugMsgs[fnId].fnName
const getFnMsg = (fnId, msgId) => debugMsgs[fnId].msgId[msgId]
const getMsgHdr = (fnId, msgId) => `${getFnName(fnId)} ${getFnMsg(fnId, msgId)}`

const fnBoundaryMsg = fnDirection => fnId => `${fnDirection} ${getFnName(fnId)}`
const fnEnterMsg = fnBoundaryMsg(fnEnterMark)
const fnExitMsg = fnBoundaryMsg(fnExitMark)

const fnEnter = (isDebug, fnId) => isDebug && console.log(fnEnterMsg(fnId))
const fnExit = (isDebug, fnId) => isDebug && console.log(fnExitMsg(fnId))
const fnEnterNth = (isDebug, fnId, n) => isDebug && console.log(`${fnEnterMsg(fnId)} ${n}`)
const fnExitNth = (isDebug, fnId, n) => isDebug && console.log(`${fnExitMsg(fnId)} ${n}`)
const singleI64 = (isDebug, fnId, msgId, i64) => isDebug && console.log(`${getMsgHdr(fnId, msgId)} = ${u64AsHexStr(i64)}`)
const singleI32 = (isDebug, fnId, msgId, i32) => isDebug && console.log(`${getMsgHdr(fnId, msgId)} = ${u32AsHexStr(i32)}`)
const singleDec = (isDebug, fnId, msgId, dec) => isDebug && console.log(`${getMsgHdr(fnId, msgId)} = ${dec}`)
const mappedPair = (isDebug, fnId, msgId, v1, v2) => isDebug && console.log(`${getMsgHdr(fnId, msgId)}: ${v1} -> ${v2}`)
const coordPair = (isDebug, fnId, msgId, v1, v2) => isDebug && console.log(`${getMsgHdr(fnId, msgId)} = (${v1},${v2})`)
const singleBigInt = (isDebug, fnId, msgId, i64) => isDebug && console.log(`${getMsgHdr(fnId, msgId)} = ${i64}`)
const label = (isDebug, labelId) => isDebug && console.log(debugLabels[labelId])

export {
  fnEnter,
  fnExit,
  fnEnterNth,
  fnExitNth,
  singleI64,
  singleI32,
  singleDec,
  mappedPair,
  coordPair,
  singleBigInt,
  label,
}
