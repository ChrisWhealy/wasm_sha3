(module
  (type $type_i32         (func (param i32)))
  (type $type_i32_i32     (func (param i32 i32)))
  (type $type_i32_i32_i32 (func (param i32 i32 i32)))
  (type $type_i32_i32_i64 (func (param i32 i32 i64)))

  (import "env" "debug"   (memory $debug 16))
  (import "env" "hexdump" (func $debug.hexdump (type $type_i32_i32_i32)))

  (import "log" "fnEnter"      (func $log.fnEnter      (type $type_i32)))
  (import "log" "fnExit"       (func $log.fnExit       (type $type_i32)))
  (import "log" "fnEnterNth"   (func $log.fnEnterNth   (type $type_i32_i32)))
  (import "log" "fnExitNth"    (func $log.fnExitNth    (type $type_i32_i32)))
  (import "log" "singleI64"    (func $log.singleI64    (type $type_i32_i32_i64)))
  (import "log" "singleI32"    (func $log.singleI32    (type $type_i32_i32_i32)))
  (import "log" "singleDec"    (func $log.singleDec    (type $type_i32_i32_i32)))
  (import "log" "singleBigInt" (func $log.singleBigInt (type $type_i32_i32_i64)))
  (import "log" "label"        (func $log.label        (type $type_i32)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; WASI requires the WASM module to export memory using the name "memory"
  ;; Memory page   1     Internal stuff
  ;; Memory pages  2     Capacity and rate buffers
  (memory $main (export "memory") 2)

  (global $DEBUG_ACTIVE       i32 (i32.const 0))
  (global $DEBUG_IO_BUFF_PTR  i32 (i32.const 0))
  (global $FD_STDOUT          i32 (i32.const 1))
  (global $FD_STDERR          i32 (i32.const 2))
  (global $SWAP_I64_ENDIANESS v128 (v128.const i8x16 7 6 5 4 3 2 1 0 15 14 13 12 11 10 9 8))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Memory Map: Page 1
  ;;     Offset  Length   Type    Description
  ;; 0x00000000     200   i64x24  24 Keccak round constants
  ;; 0x000000C8     100   i32x25  Rotation table for Rho function
  ;; 0x0000012C     200   i64x25  Theta A block
  ;; 0x000001F4      40   i64x5   Theta C function output
  ;; 0x0000021C      40   i64x5   Theta D function output
  ;; 0x00000244     200   i64x25  Theta function output
  ;; 0x0000030C     200   i64x25  Rho function output
  ;; 0x000003D4     200   i64x25  Pi function output
  ;; 0x0000049C     200   i64x25  Chi function output
  ;;
  (global $KECCAK_ROUND_CONSTANTS_PTR i32 (i32.const 0x00000000))
  ;; IMPORTANT
  ;; The round constant values have been deliberately added in big endian format!
  ;; This is an optimization that avoids the need for two swizzle operations in the iota function
  (data $keccak_round_constants (memory $main) (i32.const 0x00000000)
    "\00\00\00\00\00\00\00\01" (; Round  0;) "\00\00\00\00\00\00\80\82" (; Round  1;)
    "\80\00\00\00\00\00\80\8a" (; Round  2;) "\80\00\00\00\80\00\80\00" (; Round  3;)
    "\00\00\00\00\00\00\80\8b" (; Round  4;) "\00\00\00\00\80\00\00\01" (; Round  5;)
    "\80\00\00\00\80\00\80\81" (; Round  6;) "\80\00\00\00\00\00\80\09" (; Round  7;)
    "\00\00\00\00\00\00\00\8a" (; Round  8;) "\00\00\00\00\00\00\00\88" (; Round  9;)
    "\00\00\00\00\80\00\80\09" (; Round 10;) "\00\00\00\00\80\00\00\0a" (; Round 11;)
    "\00\00\00\00\80\00\80\8b" (; Round 12;) "\80\00\00\00\00\00\00\8b" (; Round 13;)
    "\80\00\00\00\00\00\80\89" (; Round 14;) "\80\00\00\00\00\00\80\03" (; Round 15;)
    "\80\00\00\00\00\00\80\02" (; Round 16;) "\80\00\00\00\00\00\00\80" (; Round 17;)
    "\00\00\00\00\00\00\80\0a" (; Round 18;) "\80\00\00\00\80\00\00\0a" (; Round 19;)
    "\80\00\00\00\80\00\80\81" (; Round 20;) "\80\00\00\00\00\00\80\80" (; Round 21;)
    "\00\00\00\00\80\00\00\01" (; Round 22;) "\80\00\00\00\80\00\80\08" (; Round 23;)
  )

  (global $RHO_ROTATION_TABLE i32 (i32.const 0x000000C8))
  (data $rotation_table (memory $main) (i32.const 0x000000C8)
    "\00\00\00\00"  (;  0;) "\24\00\00\00"  (; 36;) "\03\00\00\00"  (;  3;) "\29\00\00\00"  (; 41;) "\12\00\00\00"  (; 18;)
    "\01\00\00\00"  (;  1;) "\0A\00\00\00"  (; 10;) "\2C\00\00\00"  (; 44;) "\2D\00\00\00"  (; 45;) "\02\00\00\00"  (;  2;)
    "\3E\00\00\00"  (; 62;) "\06\00\00\00"  (;  6;) "\2B\00\00\00"  (; 43;) "\0F\00\00\00"  (; 15;) "\3D\00\00\00"  (; 61;)
    "\1C\00\00\00"  (; 28;) "\37\00\00\00"  (; 55;) "\19\00\00\00"  (; 25;) "\15\00\00\00"  (; 21;) "\38\00\00\00"  (; 56;)
    "\1B\00\00\00"  (; 27;) "\14\00\00\00"  (; 20;) "\27\00\00\00"  (; 39;) "\08\00\00\00"  (;  8;) "\0E\00\00\00"  (; 14;)
  )

  ;; Memory areas used by the Theta function
  (global $THETA_A_BLK_PTR  (export "THETA_A_BLK_PTR")  i32 (i32.const 0x0000012C))  ;; Length 200
  (global $THETA_C_OUT_PTR  (export "THETA_C_OUT_PTR")  i32 (i32.const 0x000001F4))  ;; Length 40
  (global $THETA_D_OUT_PTR  (export "THETA_D_OUT_PTR")  i32 (i32.const 0x0000021C))  ;; Length 40
  (global $THETA_RESULT_PTR (export "THETA_RESULT_PTR") i32 (i32.const 0x00000244))  ;; Length 200
  (global $RHO_RESULT_PTR   (export "RHO_RESULT_PTR")   i32 (i32.const 0x0000030C))  ;; Length 200
  (global $PI_RESULT_PTR    (export "PI_RESULT_PTR")    i32 (i32.const 0x000003D4))  ;; Length 200
  (global $CHI_RESULT_PTR   (export "CHI_RESULT_PTR")   i32 (i32.const 0x0000049C))  ;; Length 200

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Memory Map: Page 2
  ;;     Offset  Length   Type    Description
  ;; 0x00010000      64   i64x8   Rate buffer
  ;; 0x00010088     136   i64x17  Capacity buffer
  (global $CAPACITY_PTR (export "CAPACITY_PTR") i32 (i32.const 0x00010000))  ;; Length 136
  (global $RATE_PTR     (export "RATE_PTR")     i32 (i32.const 0x00010088))  ;; Length 64
  (global $DATA_PTR     (export "DATA_PTR")     i32 (i32.const 0x000100C8))  ;; Length 64

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; In-place XOR the 64 bytes at $RATE_PTR with the 64 bytes at $DATA_PTR
  (func $xor_rate_and_data_blocks
    (local $idx i32)

    (loop $xor_loop
      (i64.store
        (memory $main)
        (i32.add (global.get $RATE_PTR) (local.get $idx))
        (i64.xor
          (i64.load (memory $main) (i32.add (global.get $RATE_PTR) (local.get $idx)))
          (i64.load (memory $main) (i32.add (global.get $DATA_PTR) (local.get $idx)))
        )
      )

      (local.tee $idx (i32.add (local.get $idx) (i32.const 8)))
      (br_if $xor_loop (i32.lt_u (i32.const 64)))
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $prepare_memory
    ;; Ensure that the capacity and rate buffers are zeroed
    (memory.fill (memory $main) (global.get $CAPACITY_PTR) (i32.const 0) (i32.const 200))
    (call $xor_rate_and_data_blocks)

    ;; Copy the 200 bytes starting at $CAPACITY_PTR to $THETA_A_BLK_PTR
    ;; Since $CAPACITY_PTR and $RATE_PTR are contiguous, only memory.copy is needed
    (memory.copy
      (memory $main)
      (memory $main)
      (global.get $THETA_A_BLK_PTR)
      (global.get $CAPACITY_PTR)
      (i32.const 200)
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_theta")
    (call $prepare_memory)
    (call $theta)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_iota")
    (call $iota (i32.const 0))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of the inner Keccak functions
  (func (export "test_theta_rho")
    (call $prepare_memory)
    (call $theta)
    (call $rho)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of the inner Keccak functions
  (func (export "test_theta_rho_pi")
    (call $prepare_memory)
    (call $theta)
    (call $rho)
    (call $pi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of the inner Keccak functions
  (func (export "test_theta_rho_pi_chi")
    (call $prepare_memory)
    (call $theta)
    (call $rho)
    (call $pi)
    (call $chi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of the inner Keccak functions
  (func (export "test_theta_rho_pi_chi_iota")
    (call $prepare_memory)
    (call $theta)
    (call $rho)
    (call $pi)
    (call $chi)
    (call $iota (i32.const 0))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Perform $n rounds of the Keccak function against the 64-byte block of data at $DATA_PTR
  (func (export "test_keccak")
        (param $n i32)
    (local $round i32)

    (call $prepare_memory)

    (loop $next_round
      (call $keccak (local.get $round))
      (local.set $round (i32.add (local.get $round) (i32.const 1)))

      ;; If we still have more rounds to perform
      (if (local.tee $n (i32.sub (local.get $n) (i32.const 1)))
        (then
          ;; Copy the output of this round at $CHI_RESULT_PTR back to $THETA_A_BLK_PTR ready to start the next round
          (memory.copy
            (memory $main)
            (memory $main)
            (global.get $THETA_A_BLK_PTR)
            (global.get $CHI_RESULT_PTR)
            (i32.const 200)
          )
          (br $next_round)
        )
      )
    )

    ;; The output of the last Keccack round becomes the new Capacity and Rate
    (memory.copy
      (memory $main)               ;; Copy to memory
      (memory $main)               ;; Copy from memory
      (global.get $CAPACITY_PTR)   ;; Copy to address
      (global.get $CHI_RESULT_PTR) ;; Copy from address
      (i32.const 200)              ;; Length
    )

    (memory.copy
      (memory $debug)                 ;; Copy to memory
      (memory $main)                  ;; Copy from memory
      (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
      (global.get $CAPACITY_PTR)      ;; Copy from address
      (i32.const 200)                 ;; Length
    )
    (call $log.label (i32.const 5))
    (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Perform a single round of the Keccak function
  ;; The output lives at $CHI_RESULT_PTR because the iota function performs an in-place modification
  (func $keccak
        (param $round i32)
    (call $log.fnEnterNth (i32.const 9) (local.get $round))

    (memory.copy
      (memory $debug)                 ;; Copy to memory
      (memory $main)                  ;; Copy from memory
      (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
      (global.get $THETA_A_BLK_PTR)   ;; Copy from address
      (i32.const 200)                 ;; Length
    )
    (call $log.label (i32.const 4))
    (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))

    (call $theta)
    (call $rho)
    (call $pi)
    (call $chi)
    (call $iota (local.get $round))

    (call $log.fnExitNth (i32.const 9) (local.get $round))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Theta function
  ;;
  ;; Reads 200 bytes starting at $THETA_A_BLK_PTR
  ;; Writes 200 bytes to $THETA_RESULT_PTR
  (func $theta (export "theta")
    (call $theta_c)
    (call $theta_d)
    (call $theta_xor_loop)

    ;; (memory.copy
    ;;   (memory $debug)                 ;; Copy to memory
    ;;   (memory $main)                  ;; Copy from memory
    ;;   (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
    ;;   (global.get $THETA_RESULT_PTR)  ;; Copy from address
    ;;   (i32.const 200)                 ;; Length
    ;; )
    ;; (call $log.label (i32.const 6))
    ;; (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Theta C function
  ;; Perform 5 rounds of $theta_c_inner against the 25 i64s (treated as a 5x5 matrix) starting at $THETA_A_BLK_PTR
  ;; The output of each $theta_c_inner call is written as a successive i64 starting at $THETA_C_OUT_PTR
  ;;
  ;; fn theta_c() {
  ;;   for idx in 0..4 {
  ;;     THETA_C_OUT_PTR[idx] = $theta_c_inner(THETA_A_BLK_PTR + (idx * 40));
  ;;   }
  ;; }
  (func $theta_c (export "theta_c")
    (local $to_ptr       i32)
    (local $idx          i32)
    (local $inner_result i64)

    ;; (call $log.fnEnter (i32.const 0))

    (local.set $to_ptr (global.get $THETA_C_OUT_PTR))

    (loop $xor_round
      (local.set
        $inner_result
        (call $theta_c_inner (i32.add (global.get $THETA_A_BLK_PTR) (i32.mul (local.get $idx) (i32.const 40))))
      )
      ;; (call $log.singleI64 (i32.const 0) (i32.const 0) (local.get $inner_result))

      (i64.store (memory $main) (local.get $to_ptr) (local.get $inner_result))

      (local.set $to_ptr (i32.add (local.get $to_ptr) (i32.const 8)))
      (local.set $idx    (i32.add (local.get $idx)    (i32.const 1)))

      (br_if $xor_round (i32.lt_u (local.get $idx) (i32.const 5)))
    )

    ;; (call $log.fnExit (i32.const 0))
  )

  ;; Inner functionality of Theta C function
  ;; XOR's together the 5 i64s starting at $data_ptr
  ;; (((($word0 XOR $word1) XOR $word2) XOR $word3) XOR $word4)
  (func $theta_c_inner
    (param $data_ptr i32)
    (result i64)

    (i64.xor
      (i64.xor
        (i64.xor
          (i64.xor
            (i64.load (memory $main) offset=0 (local.get $data_ptr)) ;; w0
            (i64.load (memory $main) offset=8 (local.get $data_ptr)) ;; w1
          )
          (i64.load (memory $main) offset=16 (local.get $data_ptr))  ;; w2
        )
        (i64.load (memory $main) offset=24 (local.get $data_ptr))    ;; w3
      )
      (i64.load (memory $main) offset=32 (local.get $data_ptr))      ;; w4
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Theta D function - 5 rounds of $theta_d_inner performed against the 5 i64s at THETA_C_OUT_PTR
  ;; The output of each $theta_d_inner call is written as a successive i64 starting at $THETA_D_OUT_PTR
  ;;
  ;; fn theta_d(data_ptr: i32) {
  ;;   for idx in 0..4 {
  ;;     THETA_D_OUT_PTR[idx] = $theta_d_inner(
  ;;       $THETA_C_OUT_PTR + (((idx - 1) % 5) * 8),
  ;;       $THETA_C_OUT_PTR + (((idx + 1) % 5) * 8),
  ;;     )
  ;;   }
  ;; }
  ;;
  ;; Since the above algorithm uses fixed offsets, there is no need for a loop or modulo operations
  (func $theta_d (export "theta_d")
    (local $w0 i32)
    (local $w1 i32)
    (local $w2 i32)
    (local $w3 i32)
    (local $w4 i32)

    ;; (call $log.fnEnter (i32.const 2))

    (local.set $w0          (global.get $THETA_C_OUT_PTR))
    (local.set $w1 (i32.add (global.get $THETA_C_OUT_PTR) (i32.const 8)))
    (local.set $w2 (i32.add (global.get $THETA_C_OUT_PTR) (i32.const 16)))
    (local.set $w3 (i32.add (global.get $THETA_C_OUT_PTR) (i32.const 24)))
    (local.set $w4 (i32.add (global.get $THETA_C_OUT_PTR) (i32.const 32)))

    (i64.store (memory $main) offset=0  (global.get $THETA_D_OUT_PTR) (call $theta_d_inner (local.get $w4) (local.get $w1)))
    (i64.store (memory $main) offset=8  (global.get $THETA_D_OUT_PTR) (call $theta_d_inner (local.get $w0) (local.get $w2)))
    (i64.store (memory $main) offset=16 (global.get $THETA_D_OUT_PTR) (call $theta_d_inner (local.get $w1) (local.get $w3)))
    (i64.store (memory $main) offset=24 (global.get $THETA_D_OUT_PTR) (call $theta_d_inner (local.get $w2) (local.get $w4)))
    (i64.store (memory $main) offset=32 (global.get $THETA_D_OUT_PTR) (call $theta_d_inner (local.get $w3) (local.get $w0)))

    ;; (call $log.fnExit (i32.const 2))
  )

  ;; Inner functionality of Theta D function -> $w0 XOR ($w1 ROTR 1)
  (func $theta_d_inner
        (param $w0_ptr i32)
        (param $w1_ptr i32)
        (result i64)

    (local $w0  v128)
    (local $w1  v128)
    (local $res v128)

    ;; (call $log.fnEnter (i32.const 3))

    ;; The byte order of $w1 must first be swapped to big endian before the rotate right operation can be performed
    ;; Copy the i64 argument values across both lanes of a v128 in big endian format
    (local.set $w0
      (i8x16.swizzle  ;; Swap byte order
        (i64x2.splat (i64.load (memory $main) (local.get $w0_ptr)))  ;; Copy $w0 into both 64-bit lanes
        (global.get $SWAP_I64_ENDIANESS)
      )
    )
    (local.set $w1
      (i8x16.swizzle  ;; Swap byte order
        (i64x2.splat (i64.load (memory $main) (local.get $w1_ptr)))  ;; Copy $w1 into both 64-bit lanes
        (global.get $SWAP_I64_ENDIANESS)
      )
    )

    (local.set $res
      (v128.xor
        (local.get $w0)
        ;; Rotate $w1 right by 1 bit in each 64-bit lane
        ;; Since there is no SIMD operation to rotate two 64-bit lanes in a V128, we need to shift right and then
        ;; reinstate the senior bit in each lane: hence ($w1 >>> 1) | ($w1 << 63)
        (v128.or
          (i64x2.shr_u (local.get $w1) (i32.const 1))
          (i64x2.shl   (local.get $w1) (i32.const 63))
        )
      )
    )

    ;; (call $log.fnExit (i32.const 3))
    (i64x2.extract_lane 0 (i8x16.swizzle (local.get $res) (global.get $SWAP_I64_ENDIANESS)))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; For each of the 5 i64 words at $THETA_D_OUT_PTR, XOR that word with the 5 successive i64s starting at
  ;; $THETA_A_BLK_PTR.  The output is written to $THETA_RESULT_PTR
  ;;
  ;; fn theta_xor_loop(d_fn_out: [i64; 5], a_blk: mut [i64; 25]) {
  ;;   for a_blk_idx in 0..24 {
  ;;     a_blk[a_blk_idx] = d_fn_out[a_blk_idx div 5] XOR a_blk[a_blk_idx]
  ;;   }
  ;; }
  ;;
  (func $theta_xor_loop (export "theta_xor_loop")
    (local $a_blk_idx     i32)
    (local $a_blk_ptr     i32)
    (local $a_blk_word    i64)
    (local $d_fn_word     i64)
    (local $result_ptr    i32)

    ;; (call $log.fnEnter (i32.const 4))

    (local.set $result_ptr (global.get $THETA_RESULT_PTR))
    (local.set $a_blk_ptr  (global.get $THETA_A_BLK_PTR))

    (loop $xor_loop
      (local.set $d_fn_word
        (i64.load
          (memory $main)
          (i32.add
            (global.get $THETA_D_OUT_PTR)
            ;; Convert the (A block index DIV 5) to an i64 offset by multiplying by 8
            (i32.shl (i32.div_u (local.get $a_blk_idx) (i32.const 5)) (i32.const 3))
          )
        )
      )
      (local.set $a_blk_word (i64.load (memory $main) (local.get $a_blk_ptr)))

      ;; (call $log.singleI64 (i32.const 4) (i32.const 0) (local.get $d_fn_word))
      ;; (call $log.singleI64 (i32.const 4) (i32.const 1) (local.get $a_blk_word))

      (i64.store
        (memory $main)
        (local.get $result_ptr)
        (i64.xor (local.get $d_fn_word) (local.get $a_blk_word))
      )

      (local.set $a_blk_idx  (i32.add (local.get $a_blk_idx)  (i32.const 1)))
      (local.set $a_blk_ptr  (i32.add (local.get $a_blk_ptr)  (i32.const 8)))
      (local.set $result_ptr (i32.add (local.get $result_ptr) (i32.const 8)))

      ;; Quit once all 25 words in the A block have been XOR'ed
      (br_if $xor_loop (i32.lt_u (local.get $a_blk_idx) (i32.const 25)))
    )

    ;; (call $log.fnExit (i32.const 4))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; For each of the 25 i64 words at $THETA_RESULT_PTR, rotate each word by the successive values found in the
  ;; $RHO_ROTATION_TABLE.  The output is written to $RHO_RESULT_PTR
  ;;
  ;; fn rho(theta_out: [i64; 25]) {
  ;;   for theta_idx in 0..24 {
  ;;     rho_result[theta_idx] = ROTR(theta_out[theta_idx], $RHO_ROTATION_TABLE[$theta_idx % 5])
  ;;   }
  ;; }
  ;;
  (func $rho (export "rho")
    (local $result_ptr i32)
    (local $theta_ptr  i32)
    (local $theta_idx  i32)
    (local $rot_ptr    i32)
    (local $rot_amt    i64)
    (local $w0         i64)

    ;; (call $log.fnEnter (i32.const 5))

    (local.set $result_ptr (global.get $RHO_RESULT_PTR))
    (local.set $rot_ptr    (global.get $RHO_ROTATION_TABLE))
    (local.set $theta_ptr  (global.get $THETA_RESULT_PTR))

    (loop $rho_loop
      (local.set $rot_amt (i64.extend_i32_u (i32.load (memory $main) (local.get $rot_ptr))))
      ;; (call $log.singleBigInt (i32.const 5) (i32.const 2) (local.get $rot_amt))

      ;; The value must be in network byte order otherwise the rotate operation will not work correctly!
      (local.set $w0
        (i64.rotr
          (i64x2.extract_lane 0
            (i8x16.swizzle
              ;; Copy value into both 64-bit lanes
              (i64x2.splat (i64.load (memory $main) (local.get $theta_ptr)))
              (global.get $SWAP_I64_ENDIANESS)
            )
          )
          (local.get $rot_amt)
        )
      )
      ;; (call $log.singleI64 (i32.const 5) (i32.const 1) (local.get $w0))

      ;; Swizzle back to little endian byte order and store
      (i64.store
        (memory $main)
        (local.get $result_ptr)
        (i64x2.extract_lane 0
          (i8x16.swizzle
            (i64x2.splat (local.get $w0))
            (global.get $SWAP_I64_ENDIANESS)
          )
        )
      )

      (local.set $theta_ptr  (i32.add (local.get $theta_ptr)  (i32.const 8)))
      (local.set $result_ptr (i32.add (local.get $result_ptr) (i32.const 8)))
      (local.set $rot_ptr    (i32.add (local.get $rot_ptr)    (i32.const 4)))
      ;; Leave increment result on the stack for the following comparison
      (local.tee $theta_idx  (i32.add (local.get $theta_idx)  (i32.const 1)))

      ;; Quit once all 25 words in the theta result block have been rotated
      (br_if $rho_loop (i32.lt_u (i32.const 25)))
    )

    ;; (memory.copy
    ;;   (memory $debug)                 ;; Copy to memory
    ;;   (memory $main)                  ;; Copy from memory
    ;;   (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
    ;;   (global.get $RHO_RESULT_PTR)    ;; Copy from address
    ;;   (i32.const 200)                 ;; Length
    ;; )
    ;; (call $log.label (i32.const 7))
    ;; (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))

    ;; (call $log.fnExit (i32.const 5))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Reorder the 25 i64s at $RHO_RESULT_PTR according to the following transformation
  ;;
  ;; The 200-byte output is treated as a 5x5 matrix of i64s
  ;;
  ;; fn pi(rho_out: [i64; 25]) {
  ;;   let rho_idx = 0
  ;;
  ;;   for x in 0..4 {
  ;;     for y in 0..4 {
  ;;       let row = y
  ;;       let col = ((2 * x) + (3 * y)) % 5
  ;;
  ;;       pi_out[row][col] = rho_out[rho_idx]
  ;;       rho_idx += 1
  ;;     }
  ;;   }
  ;; }
  ;;
  ;; This algorithm performs a static reordering of the 25, i64 words in the input matrix, so the final transformation
  ;; can simply be hardcoded rather than calculated
  (func $pi (export "pi")
    ;; (call $log.fnEnter (i32.const 6))

    (i64.store (memory $main) offset=0   (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=0   (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=64  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=8   (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=88  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=16  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=152 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=24  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=176 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=32  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=16  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=40  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=40  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=48  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=104 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=56  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=128 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=64  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=192 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=72  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=32  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=80  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=56  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=88  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=80  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=96  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=144 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=104 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=168 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=112 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=8   (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=120 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=72  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=128 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=96  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=136 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=120 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=144 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=184 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=152 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=24  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=160 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=48  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=168 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=112 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=176 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=136 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=184 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=160 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=192 (global.get $RHO_RESULT_PTR)))

    ;; (memory.copy
    ;;   (memory $debug)                 ;; Copy to memory
    ;;   (memory $main)                  ;; Copy from memory
    ;;   (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
    ;;   (global.get $PI_RESULT_PTR)     ;; Copy from address
    ;;   (i32.const 200)                 ;; Length
    ;; )
    ;; (call $log.label (i32.const 8))
    ;; (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
    ;; (call $log.fnExit (i32.const 6))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; The 25 i64s at $PI_RESULT_PTR are treated as 5x5 matrix, then transformed by the following function
  ;;
  ;; fn chi(pi_out: [i64; 25]) {
  ;;   let chi_idx = 0
  ;;
  ;;   for row in 0..4 {
  ;;     for col in 0..4 {
  ;;       let w0 = pi_out[row][col]
  ;;       let w1 = pi_out[(row + 1) % 5][col]
  ;;       let w2 = pi_out[(row + 2) % 5][col]
  ;;
  ;;       chi_out[chi_idx] = w0 XOR (NOT(w1) AND w2)
  ;;       chi_idx += 1
  ;;     }
  ;;   }
  ;; }
  ;;
  ;; This algorithm however simply performs a static mapping, so the transformation can be hardcoded rather than calculated
  (func $chi (export "chi")
    (local $col        i32)
    (local $row        i32)
    (local $row+1      i32)
    (local $row+2      i32)
    (local $result_ptr i32)
    (local $w0         i64)
    (local $w1         i64)
    (local $w2         i64)
    (local $chi_result i64)

    ;; (call $log.fnEnter (i32.const 7))

    (local.set $result_ptr (global.get $CHI_RESULT_PTR))

    (loop $row_loop
      ;; Reset $col counter
      (local.set $col (i32.const 0))

      ;; Calculate the current and next two row indicies
      (local.set $row+1 (i32.add (local.get $row) (i32.const 1)))
      (local.set $row+1 (select (i32.const 0) (local.get $row+1) (i32.ge_u (local.get $row+1) (i32.const 5))))

      (local.set $row+2 (i32.add (local.get $row) (i32.const 2)))
      (local.set $row+2 (select (i32.sub (local.get $row+2) (i32.const 5)) (local.get $row+2) (i32.ge_u (local.get $row+2) (i32.const 5))))

      ;; (call $log.singleI32 (i32.const 7) (i32.const 0) (local.get $row))
      ;; (call $log.singleI32 (i32.const 7) (i32.const 1) (local.get $row+1))
      ;; (call $log.singleI32 (i32.const 7) (i32.const 2) (local.get $row+2))

      (loop $col_loop
        ;; (call $log.singleI32 (i32.const 7) (i32.const 3) (local.get $col))
        ;; (call $log.singleDec (i32.const 7) (i32.const 8)
        ;;   (i32.add
        ;;     (i32.mul (local.get $row) (i32.const 5))
        ;;     (local.get $col)
        ;;   )
        ;; )

        (local.set $w0 (i64.load (memory $main) (call $chi_word_offset (local.get $row)   (local.get $col))))
        (local.set $w1 (i64.load (memory $main) (call $chi_word_offset (local.get $row+1) (local.get $col))))
        (local.set $w2 (i64.load (memory $main) (call $chi_word_offset (local.get $row+2) (local.get $col))))

        ;; (call $log.singleI64 (i32.const 7) (i32.const 4) (local.get $w0))
        ;; (call $log.singleI64 (i32.const 7) (i32.const 5) (local.get $w1))
        ;; (call $log.singleI64 (i32.const 7) (i32.const 6) (local.get $w2))

        (local.set $chi_result (call $chi_inner (local.get $w0) (local.get $w1) (local.get $w2)))
        ;; (call $log.singleI64 (i32.const 7) (i32.const 7) (local.get $chi_result))

        (i64.store (memory $main) (local.get $result_ptr) (local.get $chi_result))

        (local.set $result_ptr (i32.add (local.get $result_ptr) (i32.const 8)))
        (local.tee $col        (i32.add (local.get $col)        (i32.const 1)))
        (br_if $col_loop (i32.lt_u (i32.const 5)))
      )

      (local.tee $row (i32.add (local.get $row) (i32.const 1)))
      (br_if $row_loop (i32.lt_u (i32.const 5)))
    )

    ;; (memory.copy
    ;;   (memory $debug)                 ;; Copy to memory
    ;;   (memory $main)                  ;; Copy from memory
    ;;   (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
    ;;   (global.get $CHI_RESULT_PTR)    ;; Copy from address
    ;;   (i32.const 200)                 ;; Length
    ;; )
    ;; (call $log.label (i32.const 9))
    ;; (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
    ;; (call $log.fnExit (i32.const 7))
  )

  ;; $w0 XOR (NOT($w1) AND $w2)
  (func $chi_inner
        (param $w0 i64)
        (param $w1 i64)
        (param $w2 i64)
        (result i64)
    (i64.xor (local.get $w0) (i64.and (i64.xor (local.get $w1) (i64.const -1)) (local.get $w2)))
  )

  ;; Offset = (($row * 5) + $col) * 8
  (func $chi_word_offset
        (param $row i32)
        (param $col i32)
        (result i32)
    (i32.add
      (global.get $PI_RESULT_PTR)
      (i32.shl  ;; Multiply index by 8 to get offset
        (i32.add (i32.mul (local.get $row) (i32.const 5)) (local.get $col))  ;; Calculate index from row and column
        (i32.const 3)
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; XOR in place the i64 at $CHI_RESULT_PTR with the supplied constant for this round of the Keccak function.
  ;;
  ;; The endianess of the first word at $CHI_RESULT_PTR can be left in network byte order as long as the round constant
  ;; is also given in network (big endian) byte order.  This avoids having to perform two swizzle operations:
  ;;   1) Swizzle network byte order -> little endian
  ;;   2) XOR the data value with the round constant
  ;;   3) Swizzle back into network byte order
  (func $iota (export "iota")
        (param $round i32)

    (local $w0         i64)
    (local $rnd_const  i64)
    (local $xor_result i64)

    ;; (call $log.fnEnter (i32.const 8))
    ;; (call $log.singleDec (i32.const 8) (i32.const 0) (local.get $round))

    ;; (memory.copy
    ;;   (memory $debug)                 ;; Copy to memory
    ;;   (memory $main)                  ;; Copy from memory
    ;;   (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
    ;;   (global.get $KECCAK_ROUND_CONSTANTS_PTR) ;; Copy from address
    ;;   (i32.const 192)                 ;; Length
    ;; )
    ;; (call $log.label (i32.const 11))
    ;; (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 192))

    (local.set $rnd_const
      (i64.load
        (memory $main)
        (i32.add
          (global.get $KECCAK_ROUND_CONSTANTS_PTR)
          (i32.shl (local.get $round) (i32.const 3)) ;; Convert the round number to an i64 offset
        )
      )
    )
    ;; (call $log.singleI64 (i32.const 8) (i32.const 1) (local.get $rnd_const))

    (local.set $w0 (i64.load (memory $main) (global.get $CHI_RESULT_PTR)))
    ;; (call $log.singleI64 (i32.const 8) (i32.const 2) (local.get $w0))

    (local.set $xor_result (i64.xor (local.get $rnd_const) (local.get $w0)))
    ;; (call $log.singleI64 (i32.const 8) (i32.const 3) (local.get $xor_result))

    (i64.store
      (memory $main)
      (global.get $CHI_RESULT_PTR)
      (local.get $xor_result)
    )

    ;; (memory.copy
    ;;   (memory $debug)                 ;; Copy to memory
    ;;   (memory $main)                  ;; Copy from memory
    ;;   (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
    ;;   (global.get $CHI_RESULT_PTR)    ;; Copy from address
    ;;   (i32.const 200)                 ;; Length
    ;; )
    ;; (call $log.label (i32.const 10))
    ;; (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
    ;; (call $log.fnExit (i32.const 8))
  )
)
