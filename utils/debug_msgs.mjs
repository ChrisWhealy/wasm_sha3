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
    msgId: ["$w0", "$w0 rotated"]
  },
  // FnId 6
  {
    fnName: "pi",
    msgId: []
  },
  // FnId 7
  {
    fnName: "chi",
    msgId: ["$row", "$row+1", "$row+2", "$col"]
  },
]
