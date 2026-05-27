// Function IDs match the $fn_id constants declared inside each ;;@debug-start block in sha3.wat
export const debugMsgs = [
  // FnId 0
  {
    fnName: "theta",
    msgId: ["",]
  },
  // FnId 1
  {
    fnName: "rho_pi",
    msgId: ["",]
  },
  // FnId 2
  {
    fnName: "chi",
    msgId: ["",]
  },
  // FnId 3
  {
    fnName: "iota",
    msgId: ["round", "round constant", "word 0", "XOR result"]
  },
  // FnId 4
  {
    fnName: "keccak",
    msgId: []
  },
  // FnId 5
  {
    fnName: "prepare_state",
    msgId: ["RATE", "CAPACITY", "digest_len"]
  },
  // FnId 6
  {
    fnName: "xor_block_into_state",
    msgId: ["lane_count -> byte_offset",]
  },
  // FnId 7
  {
    fnName: "sponge",
    msgId: ["",]
  },
  // FnId 8 - Not currently used
  {
    fnName: "",
    msgId: []
  },
  // FnId 9
  {
    fnName: "init_state",
    msgId: ["digest_len", "domain_byte", "RATE", "CAPACITY"]
  },
  // FnId 10
  {
    fnName: "absorb",
    msgId: ["src_len", "rate_bytes", "fill_amount", "PARTIAL_BYTES"]
  },
  // FnId 11
  {
    fnName: "finalize",
    msgId: ["PARTIAL_BYTES", "domain_byte", "rate_bytes"]
  },
  // FnId 12
  {
    fnName: "squeeze",
    msgId: ["len", "rate_bytes", "available", "copy_len", "SQUEEZE_OFFSET"]
  },
]

export const debugLabels = [
  /* 0 */  "Data block",
  /* 1 */  "Capacity",
  /* 2 */  "State (before XOR)",
  /* 3 */  "State (after XOR)",
  /* 4 */  "Theta input (STATE)",
  /* 5 */  "Theta output (WORK)",
  /* 6 */  "Rho+Pi output (STATE)",
  /* 7 */  "Chi output (STATE in-place)",
  /* 8 */  "Iota output (STATE in-place)",
  /* 9 */  "Keccak round constants",
  /* 10 */ "State zeroed",
]
