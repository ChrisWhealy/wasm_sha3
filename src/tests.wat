(module
  ;; Function types for logging/tracing
  (type $type_i32*1     (func (param i32)))
  (type $type_i32*2     (func (param i32 i32)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (import "sha3" "prepareState"  (func $sha3.prepare_state  (type $type_i32*2)))
  (import "sha3" "theta"         (func $sha3.theta))
  (import "sha3" "rho"           (func $sha3.rho))
  (import "sha3" "pi"            (func $sha3.pi))
  (import "sha3" "chi"           (func $sha3.chi))
  (import "sha3" "iota"          (func $sha3.iota           (type $type_i32*1)))
  (import "sha3" "keccak"        (func $sha3.keccak         (type $type_i32*1)))
  (import "sha3" "sponge"        (func $sha3.sponge         (type $type_i32*2)))

  (memory 1)

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_xor_data_with_rate")
        (param $digest_len i32)
    (call $sha3.prepare_state (i32.const 1) (local.get $digest_len))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_theta")
        (param $digest_len i32)

    (call $sha3.prepare_state (i32.const 1) (local.get $digest_len))
    (call $sha3.theta)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_rho")
    (call $sha3.rho)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_pi")
    (call $sha3.pi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_chi")
    (call $sha3.chi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_iota")
    (call $sha3.iota (i32.const 0))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of the inner Keccak functions
  (func (export "test_theta_rho")
        (param $digest_len i32)

    (call $sha3.prepare_state (i32.const 1) (local.get $digest_len))
    (call $sha3.theta)
    (call $sha3.rho)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of Keccak step functions
  (func (export "test_theta_rho_pi")
        (param $digest_len i32)

    (call $sha3.prepare_state (i32.const 1) (local.get $digest_len))
    (call $sha3.theta)
    (call $sha3.rho)
    (call $sha3.pi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of Keccak step functions
  (func (export "test_theta_rho_pi_chi")
        (param $digest_len i32)

    (call $sha3.prepare_state (i32.const 1) (local.get $digest_len))
    (call $sha3.theta)
    (call $sha3.rho)
    (call $sha3.pi)
    (call $sha3.chi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of Keccak step functions
  (func (export "test_theta_rho_pi_chi_iota")
        (param $digest_len i32)

    (call $sha3.prepare_state (i32.const 1) (local.get $digest_len))
    (call $sha3.theta)
    (call $sha3.rho)
    (call $sha3.pi)
    (call $sha3.chi)
    (call $sha3.iota (i32.const 0))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Perform $n rounds of the Keccak function against the 64-byte block of data at $DATA_PTR
  (func (export "test_keccak")
        (param $digest_len i32)
        (param $n i32)
    (call $sha3.sponge (local.get $digest_len) (local.get $n))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test the sponge function against the 64-byte block of data at $DATA_PTR
  (func (export "test_sponge")
        (param $digest_len i32)
    (call $sha3.sponge (local.get $digest_len) (i32.const 24))
  )

)
