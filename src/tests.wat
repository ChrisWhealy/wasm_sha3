(module
  ;; Function types for logging/tracing
  (type $type_i32*1 (func (param i32)))
  (type $type_i32*2 (func (param i32 i32)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (import "sha3" "prepare_state"   (func $sha3.prepare_state   (type $type_i32*2)))
  (import "sha3" "theta"           (func $sha3.theta))
  (import "sha3" "rho_pi"          (func $sha3.rho_pi))
  (import "sha3" "chi"             (func $sha3.chi))
  (import "sha3" "iota"            (func $sha3.iota            (type $type_i32*1)))
  (import "sha3" "keccak"    (func $sha3.keccak    (type $type_i32*1)))
  (import "sha3" "keccak24"  (func $sha3.keccak24))
  (import "sha3" "sponge"          (func $sha3.sponge          (type $type_i32*2)))

  (memory 1)

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; XOR the padded rate block at PAD_PTR into a zeroed STATE, leaving the result in STATE/RATE_PTR.
  (func (export "test_xor_data_with_rate")
        (param $digest_len i32)
    (call $sha3.prepare_state (i32.const 1) (local.get $digest_len))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; XOR into STATE then run theta.  Result in THETA_RESULT_PTR (WORK).
  (func (export "test_theta")
        (param $digest_len i32)

    (call $sha3.prepare_state (i32.const 1) (local.get $digest_len))
    (call $sha3.theta)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Rho+pi fused: reads WORK (THETA_RESULT_PTR), writes STATE (RHO_PI_RESULT_PTR).
  ;; Caller must have written the theta result to WORK_PTR before calling this.
  (func (export "test_rho_pi")
    (call $sha3.rho_pi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Chi in-place on STATE (CHI_RESULT_PTR).
  ;; Caller must have written the rho_pi result to STATE_PTR before calling this.
  (func (export "test_chi")
    (call $sha3.chi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Iota round 0 in-place on STATE.
  ;; Caller must have written the chi result to STATE_PTR before calling this.
  (func (export "test_iota")
    (call $sha3.iota (i32.const 0))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Theta → rho_pi pipeline.  Result in RHO_PI_RESULT_PTR (STATE).
  (func (export "test_theta_rho_pi")
        (param $digest_len i32)

    (call $sha3.prepare_state (i32.const 1) (local.get $digest_len))
    (call $sha3.theta)
    (call $sha3.rho_pi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Theta → rho_pi → chi pipeline.  Result in CHI_RESULT_PTR (STATE).
  (func (export "test_theta_rho_pi_chi")
        (param $digest_len i32)

    (call $sha3.prepare_state (i32.const 1) (local.get $digest_len))
    (call $sha3.theta)
    (call $sha3.rho_pi)
    (call $sha3.chi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Theta → rho_pi → chi → iota(0) — one complete Keccak round.  Result in STATE.
  (func (export "test_theta_rho_pi_chi_iota")
        (param $digest_len i32)

    (call $sha3.prepare_state (i32.const 1) (local.get $digest_len))
    (call $sha3.theta)
    (call $sha3.rho_pi)
    (call $sha3.chi)
    (call $sha3.iota (i32.const 0))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Run $n Keccak rounds starting from a freshly XOR'd block.  Result in STATE.
  (func (export "test_keccak")
        (param $digest_len i32)
        (param $n          i32)
    (call $sha3.sponge (local.get $digest_len) (local.get $n))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Run all 24 Keccak rounds.  Result in STATE.
  (func (export "test_sponge")
        (param $digest_len i32)
    (call $sha3.sponge (local.get $digest_len) (i32.const 24))
  )

)
