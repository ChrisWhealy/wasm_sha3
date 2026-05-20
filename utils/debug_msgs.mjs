export const debugMsgs = [
  // FnId 0
  {
    fnName: "theta",
    msgId: ["",]
  },
  // FnId 1
  {
    fnName: "rho",
    msgId: ["$w0", "$w0 rotated", "$rot_amt"]
  },
  // FnId 2
  {
    fnName: "pi",
    msgId: ["Old (x,y)", "New (x,y)", "rho_offset", "pi_offset"]
  },
  // FnId 3
  {
    fnName: "chi",
    msgId: ["($col,$row)", "($col,$row+1)", "($col,$row+2)", "$w0", "$w1", "$w2", "result", "round"]
  },
  // FnId 4
  {
    fnName: "iota",
    msgId: ["round", "round constant", "word 0", "XOR Result"]
  },
  // FnId 5
  {
    fnName: "keccak",
    msgId: []
  },
  // FnId 6
  {
    fnName: "prepare_state",
    msgId: ["RATE", "CAPACITY", "Received digest length"]
  },
  // FnId 7
  {
    fnName: "xor_data_with_rate",
    msgId: ["Data index -> Rate offset",]
  },
  // FnId 8
  {
    fnName: "sponge",
    msgId: ["",]
  },
  // FnId 9
  {
    fnName: "_start",
    msgId: ["",]
  },
  // FnId 10
  {
    fnName: "init_state",
    msgId: ["digest_len", "domain_byte", "RATE", "CAPACITY"]
  },
  // FnId 11
  {
    fnName: "absorb",
    msgId: ["src_len", "rate_bytes", "fill_amount", "PARTIAL_BYTES"]
  },
  // FnId 12
  {
    fnName: "finalize",
    msgId: ["PARTIAL_BYTES", "domain_byte", "rate_bytes"]
  },
  // FnId 13
  {
    fnName: "squeeze",
    msgId: ["len", "rate_bytes", "available", "copy_len", "SQUEEZE_OFFSET"]
  },
]

export const debugLabels = [
  /* 0 */  "Data block 1",
  /* 1 */  "Capacity",
  /* 2 */  "Rate (Before XORing with data block)",
  /* 3 */  "Rate (After XORing with data block)",
  /* 4 */  "Theta A block",
  /* 5 */  "New Rate & Capacity",
  /* 6 */  "Theta Result",
  /* 7 */  "Rho Result",
  /* 8 */  "Pi Result",
  /* 9 */  "Chi Result",
  /* 10 */ "Iota Result",
  /* 11 */ "Keccak Round Constants",
  /* 12 */ "Theta C Result",
  /* 13 */ "Theta D Result",
  /* 14 */ "Digest size defaulting to 256",
  /* 15 */ "State initialized",
]
