export const debugMsgs = [
  // FnId 0
  {
    fnName: "theta_c",
    msgId: ["$inner_result"]
  },
  // FnId 1
  {
    fnName: "theta_c_inner",
    msgId: ["$w0", "$w1", "$w2", "$w3", "$w4"]
  },
  // FnId 2
  {
    fnName: "theta_d",
    msgId: ["$w0", "$w1", "i64.rotr($w1, 1)"]
  },
  // FnId 3
  {
    fnName: "theta_d_inner",
    msgId: ["$w0", "$w1", "i64.rotr($w1, 1)"]
  },
  // FnId 4
  {
    fnName: "theta_xor_loop",
    msgId: ["$d_fn_word ", "$a_blk_word", "$a_blk_idx", "$a_blk_offset", 'XOR result ']
  },
  // FnId 5
  {
    fnName: "rho",
    msgId: ["$w0", "$w0 rotated", "$rot_amt"]
  },
  // FnId 6
  {
    fnName: "pi",
    msgId: ["Old (x,y)", "New (x,y)", "rho_offset", "pi_offset"]
  },
  // FnId 7
  {
    fnName: "chi",
    msgId: ["($col,$row)", "($col,$row+1)", "($col,$row+2)", "$w0", "$w1", "$w2", "result", "round"]
  },
  // FnId 8
  {
    fnName: "iota",
    msgId: ["round", "round constant", "word 0", "XOR Result"]
  },
  // FnId 9
  {
    fnName: "keccak",
    msgId: []
  },
  // FnId 10
  {
    fnName: "prepare_state",
    msgId: ["RATE", "CAPACITY", "Received digest length"]
  },
  // FnId 11
  {
    fnName: "xor_data_with_rate",
    msgId: ["Data index -> Rate offset",]
  },
  // FnId 12
  {
    fnName: "test_keccak",
    msgId: ["",]
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
