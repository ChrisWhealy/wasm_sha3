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
    msgId: ["$d_fn_word", "$a_blk_word", "i64.rotr($w1, 1)"]
  },
  // FnId 5
  {
    fnName: "rho",
    msgId: ["$w0", "$w0 rotated", "$rot_amt"]
  },
  // FnId 6
  {
    fnName: "pi",
    msgId: []
  },
  // FnId 7
  {
    fnName: "chi",
    msgId: ["$row", "$row+1", "$row+2", "$col", "$w0", "$w1", "$w2", "result", "round"]
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
]

export const debugLabels = [
  /* 0 */  "Data block 1",
  /* 1 */  "Capacity",
  /* 2 */  "Rate (Before XORing with data block)",
  /* 3 */  "Rate (After XORing with data block)",
  /* 4 */  "Start value of Theta A block data",
  /* 5 */  "New Capacity & Rate",
  /* 6 */  "Theta Result",
  /* 7 */  "Rho Result",
  /* 8 */  "Pi Result",
  /* 9 */  "Chi Result",
  /* 10 */ "Iota Result",
  /* 11 */ "Keccak Round Constants",
  /* 12 */ "Theta D Result",
]
