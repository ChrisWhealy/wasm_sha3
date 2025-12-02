;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
;; An implementation of the SHA3 algorithm based on the specification published as NIST FIPS 202
;; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
;;
;; The SHA3 algorithm uses an internal state size (in bits) is treated a s 3-dimensional matrix whose size is given by
;; b = 5 * 5 * w, where w = 2^l and l is 0..6
;;
;; When SHA3 is being used as a drop-in replacement for SHA2, l is fixed at 6
;;
;; Thus b = 5 * 5 * 2^6
;;      b = 1600
;;
;; The state is partioned into 2 regions known as the "rate" (r) and the "capacity" (c) where r + c = b.
;;
;; Further, the size (in bits) of the rate is fixed at r = 2 * d, where d is the digest size (in bits) produced by the
;; hash function. Given that SHA3 is being used as a SHA2 replacement, SHA3 must produce digests of exactly the same
;; size as those produced by SHA2. Therefore d may only be one of 224, 256, 384 or 512.
;;
;; Given that the internal state size (b) is fixed at 1600 and b = c + 2d, the rate/capacity partition sizes may only be
;; one of the pairs listed in the table below:
;;
;; +--------+--------------+--------------+
;; |        | Size in bits | Size in u64s |
;; | Digest +--------------|-------+------|
;; | Length |     r |    c |     r |    c |
;; +--------+-------+------+-------+------+
;; |    224 |  1152 |  448 |    18 |    7 |
;; |    256 |  1088 |  512 |    17 |    8 |
;; |    384 |   832 |  768 |    13 |   12 |
;; |    512 |   572 | 1024 |     9 |   16 |
;; +--------+-------+------+-------+------+
;;
;; This module follows the indexing convention described in section 3.1.4 of the above document
;;                     ___ ___ ___ ___ ___
;;                   /___/___/___/___/___/|
;;                 /___/___/___/___/___/| |
;;               /___/___/___/___/___/| |/|
;;             /___/___/___/___/___/| |/| |
;;           /___/___/___/___/___/| |/| |/|
;;  ⋀   2   |104|112| 80| 88| 96| |/| |/| |
;;  |       |___|___|___|___|___|/| |/| |/|
;;  |   1   | 64| 72| 40| 48| 56| |/| |/| |
;;          |___|___|___|___|___|/| |/| |/|
;;  Y   0   | 24| 32|  0|  8| 16| |/| |/| |
;;          |___|___|___|___|___|/| |/| |/   w-1   /
;;  |   4   |184|192|160|168|176| |/| |/   ...   /
;;  |       |___|___|___|___|___|/| |/   2     Z
;;  |   3   |144|152|120|128|136| |/   1     /
;;  ∨       |___|___|___|___|___|/   0     /
;;            3   4   0   1   2
;;           <------- X ------->
;;
;; The linear offset of the data written to the internal state starts at the centre of the matrix and follows a wrapped,
;; left-to-right, top-to-bottom ordering.
;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(module
  ;; Function types for logging/tracing
  (type $type_i32*1     (func (param i32)))
  (type $type_i32*2     (func (param i32 i32)))
  (type $type_i32*3     (func (param i32 i32 i32)))
  (type $type_i32*4     (func (param i32 i32 i32 i32)))
  (type $type_i32*5     (func (param i32 i32 i32 i32 i32)))
  (type $type_i32*3_i64 (func (param i32 i32 i32 i64)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (import "env" "debug"   (memory $debug 16))
  (import "env" "hexdump" (func $debug.hexdump (type $type_i32*3)))

  (import "log" "fnEnter"        (func $log.fnEnter      (type $type_i32*2)))
  (import "log" "fnExit"         (func $log.fnExit       (type $type_i32*2)))
  (import "log" "fnEnterNth"     (func $log.fnEnterNth   (type $type_i32*3)))
  (import "log" "fnExitNth"      (func $log.fnExitNth    (type $type_i32*3)))
  (import "log" "singleI64"      (func $log.singleI64    (type $type_i32*3_i64)))
  (import "log" "singleI32"      (func $log.singleI32    (type $type_i32*4)))
  (import "log" "singleDec"      (func $log.singleDec    (type $type_i32*4)))
  (import "log" "singleBigInt"   (func $log.singleBigInt (type $type_i32*3_i64)))
  (import "log" "label"          (func $log.label        (type $type_i32*2)))
  (import "log" "coordinatePair" (func $log.coords       (type $type_i32*5)))
  (import "log" "mappedPair"     (func $log.mappedPair   (type $type_i32*5)))

  ;; Memory page   1     Internal stuff
  ;; Memory pages  2     Rate and Capacity buffers
  (memory $main (export "memory") 2)

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
  ;; The round constant values listed here are deliberately given in big endian format!
  ;; This optimization avoids having to perform two extra swizzle operations in the iota function
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

  ;; The rotation amounts used by the Rho function (hence "rhotation" table) are derived from the word length w which in
  ;; turn is derived from the length l (where w = 2^l)
  ;;
  ;; Word zero always has a rotation value of 0, but for the 24 other words in the 5 * 5 state matrix, the rotation
  ;; amount for the word at x,y is stored as r[x,y] and defined as
  ;;
  ;; for w=64
  ;;
  ;; r[0,0] = 0
  ;; Then for t = 0..23:
  ;;   Walk x,y coordinates with (x, y) <- (y, (2x + 3y) mod 5)
  ;;   r[x, y] = ((t+1) * (t+2) / 2) mod w
  ;;
  (global $RHOTATION_TABLE i32 (i32.const 0x000000C8))
  (data (memory $main) (i32.const 0x000000C8)
    (;  0;) "\00\00\00\00"  (; 36;) "\24\00\00\00" (;  3;) "\03\00\00\00" (; 41;) "\29\00\00\00" (; 18;) "\12\00\00\00"
    (;  1;) "\01\00\00\00"  (; 44;) "\2C\00\00\00" (; 10;) "\0A\00\00\00" (; 45;) "\2D\00\00\00" (;  2;) "\02\00\00\00"
    (; 62;) "\3E\00\00\00"  (;  6;) "\06\00\00\00" (; 43;) "\2B\00\00\00" (; 15;) "\0F\00\00\00" (; 61;) "\3D\00\00\00"
    (; 28;) "\1C\00\00\00"  (; 55;) "\37\00\00\00" (; 25;) "\19\00\00\00" (; 21;) "\15\00\00\00" (; 56;) "\38\00\00\00"
    (; 27;) "\1B\00\00\00"  (; 20;) "\14\00\00\00" (; 39;) "\27\00\00\00" (;  8;) "\08\00\00\00" (; 14;) "\0E\00\00\00"
  )

  ;; Memory areas used by the inner Keccak functions
  ;; These pointers point to locations in page 1 of memory $main
  (global $THETA_A_BLK_PTR  (export "THETA_A_BLK_PTR")  i32 (i32.const 0x0000012C))  ;; Length 200
  (global $THETA_C_OUT_PTR  (export "THETA_C_OUT_PTR")  i32 (i32.const 0x000001F4))  ;; Length 40
  (global $THETA_D_OUT_PTR  (export "THETA_D_OUT_PTR")  i32 (i32.const 0x0000021C))  ;; Length 40
  (global $THETA_RESULT_PTR (export "THETA_RESULT_PTR") i32 (i32.const 0x00000244))  ;; Length 200
  (global $RHO_RESULT_PTR   (export "RHO_RESULT_PTR")   i32 (i32.const 0x0000030C))  ;; Length 200
  (global $PI_RESULT_PTR    (export "PI_RESULT_PTR")    i32 (i32.const 0x000003D4))  ;; Length 200
  (global $CHI_RESULT_PTR   (export "CHI_RESULT_PTR")   i32 (i32.const 0x0000049C))  ;; Length 200

  ;; The n'th i32 in this table holds the offset into the state at which the n'th i64 in the incoming data should be written
  (global $STATE_IDX_TAB i32 (i32.const 0x00000564))  ;; Length 25 * i32 = 100
  (data (memory $main) (i32.const 0x00000564)
    (; 96;) "\60\00\00\00" (;104;) "\68\00\00\00" (;112;) "\70\00\00\00" (; 80;) "\50\00\00\00" (; 88;) "\58\00\00\00"
    (;136;) "\88\00\00\00" (;144;) "\90\00\00\00" (;152;) "\98\00\00\00" (;120;) "\78\00\00\00" (;128;) "\80\00\00\00"
    (;176;) "\B0\00\00\00" (;184;) "\B8\00\00\00" (;192;) "\C0\00\00\00" (;160;) "\A0\00\00\00" (;168;) "\A8\00\00\00"
    (; 16;) "\10\00\00\00" (; 24;) "\18\00\00\00" (; 32;) "\20\00\00\00" (;  0;) "\00\00\00\00" (;  8;) "\08\00\00\00"
    (; 56;) "\38\00\00\00" (; 64;) "\40\00\00\00" (; 72;) "\48\00\00\00" (; 40;) "\28\00\00\00" (; 48;) "\30\00\00\00"
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Memory Map: Page 2
  ;;     Offset  Length   Type    Description
  ;; 0x00010000     200  i64x25   Internal state buffer - fixed at 200 bytes or 1600 bits
  ;; 0x00010000      64   i64x8   Rate buffer
  ;; 0x00010088     136   i64x17  Capacity buffer
  (global $STATE_PTR    (export "STATE_PTR")    i32 (i32.const 0x00010000))  ;; Length fixed at 200
  (global $DATA_PTR     (export "DATA_PTR")     i32 (i32.const 0x000100C8))  ;; Length determined by the rate

  ;; Default digest size = 256, so in 64-bit words, rate = 17 and capacity = 8
  (global $RATE         (export "RATE")         (mut i32) (i32.const 17))
  (global $CAPACITY     (export "CAPACITY")     (mut i32) (i32.const 8))
  (global $RATE_PTR     (export "RATE_PTR")          i32  (i32.const 0x00010000))
  (global $CAPACITY_PTR (export "CAPACITY_PTR") (mut i32) (i32.const 0x00010000))  ;; Length depends on digest size

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $prepare_state
        (param $init_mem      i32) ;; Initialise state memory?
        (param $copy_to_a_blk i32) ;; Copy state to Theta A block?
        (param $digest_len    i32) ;; Defaults to 256

    (local $debug_active i32)
    ;; (local.set $debug_active (i32.const 1))

    (call $log.fnEnter (local.get $debug_active) (i32.const 10))
    (call $log.singleDec (local.get $debug_active) (i32.const 10) (i32.const 2) (local.get $digest_len))

    ;; If $digest_len is not one of 224, 256, 384 or 512, then default to 256
    (block $digest_ok
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 224)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 256)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 384)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 512)))

      (local.set $digest_len (i32.const 256))
      (call $log.label (local.get $debug_active) (i32.const 14))
    )


    ;; Initialise the internal state?
    (if (local.get $init_mem)
      (then
        (memory.fill (memory $main) (global.get $STATE_PTR) (i32.const 0) (i32.const 200))
        (call $log.label (local.get $debug_active) (i32.const 15))
      )
    )

    ;; Calculate rate and capacity sizes as i64 words
    ;; rate     = (1600 - (digest_size * 2)) / 64
    ;; capacity = 25 - rate
    (global.set $RATE
      (i32.shr_u
        (i32.sub (i32.const 1600) (i32.shl (local.get $digest_len) (i32.const 1)))
        (i32.const 6)
      )
    )
    (global.set $CAPACITY (i32.sub (i32.const 25) (global.get $RATE)))

    ;; Partition the internal state for the given rate/capacity
    (global.set $CAPACITY_PTR (i32.add (global.get $STATE_PTR) (i32.shl (global.get $RATE) (i32.const 3))))

    (call $log.singleDec (local.get $debug_active) (i32.const 10) (i32.const 0) (global.get $RATE))
    (call $log.singleDec (local.get $debug_active) (i32.const 10) (i32.const 1) (global.get $CAPACITY))

    ;; XOR first input block with the rate
    (call $xor_data_with_rate (global.get $RATE))

    ;; If necessary, copy the internal state to $THETA_A_BLK_PTR
    (if (local.get $copy_to_a_blk)
      (then
        (memory.copy
          (memory $main)
          (memory $main)
          (global.get $THETA_A_BLK_PTR)
          (global.get $STATE_PTR)
          (i32.const 200)
        )
      )
    )

    (call $log.fnExit (local.get $debug_active) (i32.const 10))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; In place XOR the data at $RATE_PTR with the data at $DATA_PTR
  ;; The data is wrtten to the rate in the order determined by the indexing convention
  (func $xor_data_with_rate
        (param $rate_words i32)
    (local $data_idx    i32)
    (local $rate_offset i32)
    (local $rate_ptr    i32)
    (local $debug_active i32)
    ;; (local.set $debug_active (i32.const 1))

    (call $log.fnEnter (local.get $debug_active) (i32.const 11))

    (loop $xor_loop
      ;; Derive the offset within the rate at which the n'th i64 in the incoming data should be written
      (local.set $rate_offset
        (i32.load
          (memory $main)
          (i32.add (global.get $STATE_IDX_TAB) (i32.shl (local.get $data_idx) (i32.const 2)))
        )
      )
      (local.set $rate_ptr (i32.add (global.get $RATE_PTR) (local.get $rate_offset)))

      (call $log.mappedPair (local.get $debug_active) (i32.const 11) (i32.const 0) (local.get $data_idx) (local.get $rate_offset))

      (i64.store
        (memory $main)
        (local.get $rate_ptr)
        (i64.xor
          (i64.load (memory $main) (local.get $rate_ptr))
          (i64.load (memory $main) (i32.add (global.get $DATA_PTR) (i32.shl (local.get $data_idx) (i32.const 3))))
        )
      )

      (local.set $data_idx   (i32.add (local.get $data_idx)   (i32.const 1)))
      (local.tee $rate_words (i32.sub (local.get $rate_words) (i32.const 1)))
      (br_if $xor_loop)
    )

    ;; (memory.copy
    ;;   (memory $debug)                 ;; Copy to memory
    ;;   (memory $main)                  ;; Copy from memory
    ;;   (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
    ;;   (global.get $STATE_PTR)         ;; Copy from address
    ;;   (i32.const 200)                 ;; Length
    ;; )
    ;; (call $log.label (local.get $debug_active) (i32.const 3))
    ;; (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))

    (call $log.fnExit (local.get $debug_active) (i32.const 11))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_xor_data_with_rate")
        (param $digest_len i32)
    (call $prepare_state (i32.const 1) (i32.const 1) (local.get $digest_len))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_theta_c")
        (param $digest_len i32)
        (param $rounds i32)
    (call $prepare_state (i32.const 1) (i32.const 1) (local.get $digest_len))
    (call $theta_c (local.get $rounds))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_theta_d")
        (param $digest_len i32)

    (call $prepare_state (i32.const 1) (i32.const 1) (local.get $digest_len))
    (call $theta_c (i32.const 5))
    (call $theta_d)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_theta_xor_loop")
        (param $digest_len i32)

    (call $prepare_state (i32.const 1) (i32.const 0) (local.get $digest_len))
    (call $theta_xor_loop)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_theta")
        (param $digest_len i32)

    (call $prepare_state (i32.const 1) (i32.const 1) (local.get $digest_len))
    (call $theta)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "test_iota")
    (call $iota (i32.const 0))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of the inner Keccak functions
  (func (export "test_theta_rho")
        (param $digest_len i32)

    (call $prepare_state (i32.const 1) (i32.const 1) (local.get $digest_len))
    (call $theta)
    (call $rho)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of the inner Keccak functions
  (func (export "test_theta_rho_pi")
        (param $digest_len i32)

    (call $prepare_state (i32.const 1) (i32.const 1) (local.get $digest_len))
    (call $theta)
    (call $rho)
    (call $pi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of the inner Keccak functions
  (func (export "test_theta_rho_pi_chi")
        (param $digest_len i32)

    (call $prepare_state (i32.const 1) (i32.const 1) (local.get $digest_len))
    (call $theta)
    (call $rho)
    (call $pi)
    (call $chi)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test a succession of the inner Keccak functions
  (func (export "test_theta_rho_pi_chi_iota")
        (param $digest_len i32)

    (call $prepare_state (i32.const 1) (i32.const 1) (local.get $digest_len))
    (call $theta)
    (call $rho)
    (call $pi)
    (call $chi)
    (call $iota (i32.const 0))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Perform $n rounds of the Keccak function against the 64-byte block of data at $DATA_PTR
  (func (export "test_keccak")
        (param $digest_len i32)
        (param $n i32)

    (local $round i32)
    (local $debug_active i32)

    ;; (local.set $debug_active (i32.const 1))

    (call $log.fnEnter (local.get $debug_active) (i32.const 12))

    (call $prepare_state (i32.const 1) (i32.const 1) (local.get $digest_len))

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
      (global.get $STATE_PTR)      ;; Copy to address
      (global.get $CHI_RESULT_PTR) ;; Copy from address
      (i32.const 200)              ;; Length
    )

    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $STATE_PTR)         ;; Copy from address
          (i32.const 200)                 ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 5))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
      )
    )
    (call $log.fnExit (local.get $debug_active) (i32.const 12))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Transform $row and $col indices into a memory offset following the indexing convention
  ;; Return the offset stored at STATE_IDX_TAB[($row * 5) + $col]
  (func $xy_to_state_offset
        (param $row i32)
        (param $col i32)
        (result i32)

    ;; Return offset from the state index table
    (i32.load
      (memory $main)
      (i32.add
        (global.get $STATE_IDX_TAB)
        ;; Multiply linear index by 4 to derive offset within the state index table
        (i32.shl
          ;; Transform 5x5 row/col coordinates to a linear index
          (i32.add (i32.mul (local.get $row) (i32.const 5)) (local.get $col))
          (i32.const 2)
        )
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Perform a single round of the Keccak function
  ;; The output lives at $CHI_RESULT_PTR because the iota function performs an in-place modification
  (func $keccak
        (param $round i32)
    (local $debug_active i32)
    ;; (local.set $debug_active (i32.const 1))
    (call $log.fnEnterNth (local.get $debug_active) (i32.const 9) (local.get $round))

    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $THETA_A_BLK_PTR)   ;; Copy from address
          (i32.const 200)                 ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 4))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
      )
    )

    (call $theta)
    (call $rho)
    (call $pi)
    (call $chi)
    (call $iota (local.get $round))

    (call $log.fnExitNth (local.get $debug_active) (i32.const 9) (local.get $round))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Theta function
  ;;
  ;; Reads 200 bytes starting at $THETA_A_BLK_PTR
  ;; Writes 200 bytes to $THETA_RESULT_PTR
  (func $theta (export "theta")
    (local $debug_active i32)
    ;; (local.set $debug_active (i32.const 1))
    (call $log.fnEnter (local.get $debug_active) (i32.const 2))

    (call $theta_c (i32.const 5))
    (call $theta_d)
    (call $theta_xor_loop)

    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $THETA_RESULT_PTR)  ;; Copy from address
          (i32.const 200)                 ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 6))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
      )
    )
    (call $log.fnExit (local.get $debug_active) (i32.const 2))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Theta C function
  ;; For each row of the state matrix, XOR words 0..4 together write the results as successive i64s starting at
  ;; $THETA_C_OUT_PTR.  The XOR functionality is containing in function $theta_c_inner
  ;;
  ;; The parameter $n is only needed to test a single round of $theta_c_inner.
  ;; In normal operation, this parameter is hard-coded to 5
  (func $theta_c
        (param $n i32)
    (local $result i64)
    (local $to_ptr i32)
    (local $debug_active i32)
    ;; (local.set $debug_active (i32.const 1))
    (call $log.fnEnter (local.get $debug_active) (i32.const 0))

    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $THETA_A_BLK_PTR)   ;; Copy from address
          (i32.const 200)                 ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 4))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
      )
    )

    (block $call_count
      ;; State row 0
      (local.set $to_ptr (i32.add (global.get $THETA_A_BLK_PTR) (i32.const 80)))
      (local.set $result (call $theta_c_inner (local.get $to_ptr)))
      (call $log.singleI64 (local.get $debug_active) (i32.const 1) (i32.const 0) (local.get $result))
      (i64.store (memory $main) (global.get $THETA_C_OUT_PTR) (local.get $result))
      (br_if $call_count (i32.eq (local.get $n) (i32.const 1)))

      ;; State row 1
      (local.set $to_ptr (i32.add (global.get $THETA_A_BLK_PTR) (i32.const 40)))
      (local.set $result (call $theta_c_inner (local.get $to_ptr)))
      (call $log.singleI64 (local.get $debug_active) (i32.const 1) (i32.const 1) (local.get $result))
      (i64.store (memory $main) offset=8 (global.get $THETA_C_OUT_PTR) (call $theta_c_inner (local.get $to_ptr)))
      (br_if $call_count (i32.eq (local.get $n) (i32.const 2)))

      ;; State row 2
      (local.set $to_ptr (global.get $THETA_A_BLK_PTR))
      (local.set $result (call $theta_c_inner (local.get $to_ptr)))
      (call $log.singleI64 (local.get $debug_active) (i32.const 1) (i32.const 2) (local.get $result))
      (i64.store (memory $main) offset=16 (global.get $THETA_C_OUT_PTR) (local.get $result))
      (br_if $call_count (i32.eq (local.get $n) (i32.const 3)))

      ;; State row 3
      (local.set $to_ptr (i32.add (global.get $THETA_A_BLK_PTR) (i32.const 160)))
      (local.set $result (call $theta_c_inner (local.get $to_ptr)))
      (call $log.singleI64 (local.get $debug_active) (i32.const 1) (i32.const 3) (local.get $result))
      (i64.store (memory $main) offset=24 (global.get $THETA_C_OUT_PTR) (local.get $result))
      (br_if $call_count (i32.eq (local.get $n) (i32.const 4)))

      ;; State row 4
      (local.set $to_ptr (i32.add (global.get $THETA_A_BLK_PTR) (i32.const 120)))
      (local.set $result (call $theta_c_inner (local.get $to_ptr)))
      (call $log.singleI64 (local.get $debug_active) (i32.const 1) (i32.const 4) (local.get $result))
      (i64.store (memory $main) offset=32 (global.get $THETA_C_OUT_PTR) (local.get $result))
    )

    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $THETA_C_OUT_PTR)   ;; Copy from address
          (i32.const 40)                  ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 12))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 40))
      )
    )

    (call $log.fnExit (local.get $debug_active) (i32.const 0))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Inner functionality of Theta C function
  ;; XOR the 5 i64s starting at $data_ptr
  ;; Matrix access must follow the indexing convention where (0,0) is the centre of the 5 * 5 matrix
  (func $theta_c_inner
    (param $data_ptr i32)
    (result i64)

    (i64.xor
      (i64.xor
        (i64.xor
          (i64.xor
            (i64.load (memory $main) offset=16 (local.get $data_ptr)) ;; w0
            (i64.load (memory $main) offset=24 (local.get $data_ptr)) ;; w1
          )
          (i64.load (memory $main) offset=32 (local.get $data_ptr))   ;; w2
        )
        (i64.load (memory $main) offset=0 (local.get $data_ptr))      ;; w3
      )
      (i64.load (memory $main) offset=8 (local.get $data_ptr))        ;; w4
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
  ;; Since the above algorithm always yields fixed offsets, these values can be hard coded, thus saving the need to
  ;; perform modulo operations inside a loop
  (func $theta_d
    (local $w0 i32)
    (local $w1 i32)
    (local $w2 i32)
    (local $w3 i32)
    (local $w4 i32)
    (local $debug_active i32)
    ;; (local.set $debug_active (i32.const 1))
    (call $log.fnEnter (local.get $debug_active) (i32.const 2))

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

    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $THETA_D_OUT_PTR)   ;; Copy from address
          (i32.const 40)                  ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 13))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 40))
      )
    )

    (call $log.fnExit (local.get $debug_active) (i32.const 2))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Inner functionality of Theta D function -> $w0 XOR ($w1 ROTR 1)
  (func $theta_d_inner
        (param $w0_ptr i32)
        (param $w1_ptr i32)
        (result i64)

    (local $w0  v128)
    (local $w1  v128)
    (local $res v128)
    (local $debug_active i32)
    ;; (local.set $debug_active (i32.const 1))
    (call $log.fnEnter (local.get $debug_active) (i32.const 3))

    ;; The byte order of $w1 must first be swapped to big endian before the rotate right operation can be performed
    (local.set $w0
      (i8x16.swizzle  ;; Swap byte order
        (i64x2.splat (i64.load (memory $main) (local.get $w0_ptr)))  ;; Copy $w0 into both 64-bit lanes of the v128
        (global.get $SWAP_I64_ENDIANESS)
      )
    )
    (local.set $w1
      (i8x16.swizzle  ;; Swap byte order
        (i64x2.splat (i64.load (memory $main) (local.get $w1_ptr)))  ;; Copy $w1 into both 64-bit lanes of the v128
        (global.get $SWAP_I64_ENDIANESS)
      )
    )

    (local.set $res
      (v128.xor
        (local.get $w0)
        ;; Rotate $w1 right by 1 bit in each 64-bit lane
        ;; Since there is no SIMD operation to rotate two 64-bit lanes in a V128, we need to shift right and then
        ;; manually reinstate the junior bit at the senior position: hence ($w1 >>> 1) | ($w1 << 63)
        (v128.or
          (i64x2.shr_u (local.get $w1) (i32.const 1))  ;; The junior bit is now lost
          (i64x2.shl   (local.get $w1) (i32.const 63)) ;; Reinstate the junior bit in the senior position
        )
      )
    )

    (i64x2.extract_lane 0 (i8x16.swizzle (local.get $res) (global.get $SWAP_I64_ENDIANESS)))
    (call $log.fnExit (local.get $debug_active) (i32.const 3))
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
  ;; Matrix access must follow the indexing convention where (0,0) is the centre of the 5 * 5 matrix
  (func $theta_xor_loop
    (local $a_blk_idx    i32)
    (local $a_blk_offset i32)
    (local $a_blk_ptr    i32)
    (local $a_blk_word   i64)
    (local $d_fn_word    i64)
    (local $xor_result   i64)
    (local $result_ptr   i32)
    (local $debug_active i32)
    ;; (local.set $debug_active (i32.const 1))

    (call $log.fnEnter (local.get $debug_active) (i32.const 4))

    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $THETA_A_BLK_PTR)   ;; Copy from address
          (i32.const 200)                  ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 4))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
      )
    )

    (loop $xor_loop
      (local.set $d_fn_word
        (i64.load
          (memory $main)
          (i32.add
            (global.get $THETA_D_OUT_PTR)
            ;; D block index is the A block index DIV 5 * 8
            (i32.shl (i32.div_u (local.get $a_blk_idx) (i32.const 5)) (i32.const 3))
          )
        )
      )

      ;; The offset of the n'th A block word is picked up from the state index table.
      ;; This offset is then added to $THETA_A_BLK_PTR to pick up the correct word
      ;;
      ;; $a_blk_offset = $STATE_IDX_TAB + ($a_blk_idx * 4)
      ;; $a_blk_ptr = $THETA_A_BLK_PTR + $a_blk_offset
      (call $log.singleDec (local.get $debug_active) (i32.const 4) (i32.const 2) (local.get $a_blk_idx))

      (local.set $a_blk_offset
        (i32.load
          (memory $main)
          (i32.add (global.get $STATE_IDX_TAB) (i32.shl (local.get $a_blk_idx) (i32.const 2)))
        )
      )
      (call $log.singleDec (local.get $debug_active) (i32.const 4) (i32.const 3) (local.get $a_blk_offset))

      ;; The offset of the input word and the result word should be the same
      (local.set $result_ptr (i32.add (global.get $THETA_RESULT_PTR) (local.get $a_blk_offset)))
      (local.set $a_blk_ptr  (i32.add (global.get $THETA_A_BLK_PTR)  (local.get $a_blk_offset)))
      (local.set $a_blk_word (i64.load (memory $main) (local.get $a_blk_ptr)))
      (local.set $xor_result (i64.xor (local.get $d_fn_word) (local.get $a_blk_word)))

      (call $log.singleI64 (local.get $debug_active) (i32.const 4) (i32.const 0) (local.get $d_fn_word))
      (call $log.singleI64 (local.get $debug_active) (i32.const 4) (i32.const 1) (local.get $a_blk_word))
      (call $log.singleI64 (local.get $debug_active) (i32.const 4) (i32.const 4) (local.get $xor_result))

      (i64.store (memory $main) (local.get $result_ptr) (local.get $xor_result))

      (local.set $a_blk_idx (i32.add (local.get $a_blk_idx) (i32.const 1)))

      ;; Quit once all 5 words in the D block have been XOR'ed with successive words in the A block
      (br_if $xor_loop (i32.lt_u (local.get $a_blk_idx) (i32.const 25)))
    )

    (call $log.fnExit (local.get $debug_active) (i32.const 4))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; For each of the 25 i64 words at $THETA_RESULT_PTR, rotate each word by the successive values found in the
  ;; $RHOTATION_TABLE.  The output is written to $RHO_RESULT_PTR
  ;;
  ;; Matrix access must follow the indexing convention where (0,0) is the centre of the 5 * 5 matrix
  ;;
  ;; fn rho(theta_out: [i64; 25]) {
  ;;   for theta_idx in 0..24 {
  ;;     rho_result[theta_idx] = ROTR(theta_out[theta_idx], $RHOTATION_TABLE[$theta_idx % 5])
  ;;   }
  ;; }
  ;;
  (func $rho (export "rho")
    (local $result_ptr   i32)
    (local $theta_offset i32)
    (local $theta_ptr    i32)
    (local $theta_idx    i32)
    (local $rot_ptr      i32)
    (local $rot_amt      i64)
    (local $w0           i64)
    (local $debug_active i32)
    ;; (local.set $debug_active (i32.const 1))

    (call $log.fnEnter (local.get $debug_active) (i32.const 5))

    (local.set $rot_ptr (global.get $RHOTATION_TABLE))

    (loop $rho_loop
      (local.set $rot_amt (i64.extend_i32_u (i32.load (memory $main) (local.get $rot_ptr))))
      (call $log.singleBigInt (local.get $debug_active) (i32.const 5) (i32.const 2) (local.get $rot_amt))

      ;; Transform loop index into state offset
      (local.set $theta_offset
        (i32.load
          (memory $main)
          (i32.add (global.get $STATE_IDX_TAB) (i32.shl (local.get $theta_idx) (i32.const 2)))
        )
      )

      ;; $theta_ptr and $result_ptr must point to the same index location within their respective memory blocks
      (local.set $theta_ptr  (i32.add (global.get $THETA_RESULT_PTR) (local.get $theta_offset)))
      (local.set $result_ptr (i32.add (global.get $RHO_RESULT_PTR)   (local.get $theta_offset)))

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
      (call $log.singleI64 (local.get $debug_active) (i32.const 5) (i32.const 1) (local.get $w0))

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

      (local.set $rot_ptr   (i32.add (local.get $rot_ptr)    (i32.const 4)))
      (local.tee $theta_idx (i32.add (local.get $theta_idx)  (i32.const 1)))

      ;; Quit once all 25 words in the theta result block have been rotated
      (br_if $rho_loop (i32.lt_u (i32.const 25)))
    )

    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $RHO_RESULT_PTR)    ;; Copy from address
          (i32.const 200)                 ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 7))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
      )
    )

    (call $log.fnExit (local.get $debug_active) (i32.const 5))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; For each row in the state matrix, reorder the columns according to the following transformation.
  ;; Matrix access must follow the indexing convention where (0,0) is the centre of the 5 * 5 matrix
  ;;
  ;; fn pi(rho_out: [i64; 25]) {
  ;;   let rho_idx = 0
  ;;
  ;;   for x in 0..4 {
  ;;     for row in 0..4 {
  ;;       let col = ((2 * x) + (3 * row)) % 5
  ;;
  ;;       pi_out[row][col] = rho_out[rho_idx]
  ;;       rho_idx += 1
  ;;     }
  ;;   }
  ;; }
  ;;
  ;; Since this algorithm results in a static reordering of the i64s, the final transformation can simply be hardcoded
  ;; rather than calculated.
  (func $pi (export "pi")
    (local $debug_active i32)
    ;; (local.set $debug_active (i32.const 1))
    (call $log.fnEnter (local.get $debug_active) (i32.const 6))

    ;; Row 2: offsets 160 - 192
    (i64.store (memory $main) offset=184 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=176 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=160 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=184 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=176 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=192 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=192 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=160 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=168 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=168 (global.get $RHO_RESULT_PTR)))

    ;; Row 1: offsets 120 - 152
    (i64.store (memory $main) offset=120 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=136 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=136 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=144 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=152 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=152 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=128 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=120 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=144 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=128 (global.get $RHO_RESULT_PTR)))

    ;; Row 0: offsets 80 - 112
    (i64.store (memory $main) offset=96  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=96  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=112 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=104 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=88  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=112 (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=104 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=80  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=80  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=88  (global.get $RHO_RESULT_PTR)))

    ;; Row 4: offsets 40 - 72
    (i64.store (memory $main) offset=72  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=56  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=48  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=64  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=64  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=72  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=40  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=40  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=56  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=48  (global.get $RHO_RESULT_PTR)))

    ;; Row 3: offsets 0 - 32
    (i64.store (memory $main) offset=8   (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=16  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=24  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=24  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=0   (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=32  (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=16  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=0   (global.get $RHO_RESULT_PTR)))
    (i64.store (memory $main) offset=32  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=8   (global.get $RHO_RESULT_PTR)))

    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $PI_RESULT_PTR)     ;; Copy from address
          (i32.const 200)                 ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 8))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
      )
    )
    (call $log.fnExit (local.get $debug_active) (i32.const 6))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; For each column in the state matrix, reorder the row entries according to the following transformation.
  ;; Matrix access must follow the indexing convention where (0,0) is the centre of the 5 * 5 matrix
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
    (local $col           i32)
    (local $row           i32)
    (local $row+1         i32)
    (local $row+2         i32)
    (local $result_ptr    i32)
    (local $result_offset i32)
    (local $w0            i64)
    (local $w1            i64)
    (local $w2            i64)
    (local $chi_result    i64)
    (local $debug_active  i32)

    ;; (local.set $debug_active (i32.const 1))

    (call $log.fnEnter (local.get $debug_active) (i32.const 7))

    ;; Dump state before transformation
    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $PI_RESULT_PTR)     ;; Copy from address
          (i32.const 200)                 ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 8))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
      )
    )

    (loop $row_loop
      ;; Reset $col counter
      (local.set $col (i32.const 0))

      ;; Calculate the next two row indices
      (local.set $row+1 (i32.rem_u (i32.add (local.get $row) (i32.const 1)) (i32.const 5)))
      (local.set $row+2 (i32.rem_u (i32.add (local.get $row) (i32.const 2)) (i32.const 5)))

      (loop $col_loop
        (call $log.coords (local.get $debug_active) (i32.const 7) (i32.const 0) (local.get $col) (local.get $row))
        (call $log.coords (local.get $debug_active) (i32.const 7) (i32.const 1) (local.get $col) (local.get $row+1))
        (call $log.coords (local.get $debug_active) (i32.const 7) (i32.const 2) (local.get $col) (local.get $row+2))

        (local.tee $result_offset (call $xy_to_state_offset (local.get $row) (local.get $col)))
        (local.set $result_ptr (i32.add (global.get $CHI_RESULT_PTR)))

        (local.set $w0
          (i64.load
            (memory $main)
            (i32.add (global.get $PI_RESULT_PTR) (local.get $result_offset))
          )
        )
        (local.set $w1
          (i64.load
            (memory $main)
            (i32.add (global.get $PI_RESULT_PTR) (call $xy_to_state_offset (local.get $row+1) (local.get $col)))
          )
        )
        (local.set $w2
          (i64.load
            (memory $main)
            (i32.add (global.get $PI_RESULT_PTR) (call $xy_to_state_offset (local.get $row+2) (local.get $col)))
          )
        )

        (call $log.singleI64 (local.get $debug_active) (i32.const 7) (i32.const 3) (local.get $w0))
        (call $log.singleI64 (local.get $debug_active) (i32.const 7) (i32.const 4) (local.get $w1))
        (call $log.singleI64 (local.get $debug_active) (i32.const 7) (i32.const 5) (local.get $w2))

        ;; $w0 XOR (NOT($w1) AND $w2)
        (local.set $chi_result
          (i64.xor
            (local.get $w0)
            (i64.and
              (i64.xor (local.get $w1) (i64.const -1))
              (local.get $w2)
            )
          )
        )
        (call $log.singleI64 (local.get $debug_active) (i32.const 7) (i32.const 6) (local.get $chi_result))

        (i64.store (memory $main) (local.get $result_ptr) (local.get $chi_result))

        (local.tee $col (i32.add (local.get $col) (i32.const 1)))
        (br_if $col_loop (i32.lt_u (i32.const 5)))
      )

      (local.tee $row (i32.add (local.get $row) (i32.const 1)))
      (br_if $row_loop (i32.lt_u (i32.const 5)))
    )

    ;; Dump state after transformation
    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $CHI_RESULT_PTR)    ;; Copy from address
          (i32.const 200)                 ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 9))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
      )
    )
    (call $log.fnExit (local.get $debug_active) (i32.const 7))
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
    (local $debug_active i32)
    ;; (local.set $debug_active (i32.const 1))

    (call $log.fnEnter (local.get $debug_active) (i32.const 8))
    (call $log.singleDec (local.get $debug_active) (i32.const 8) (i32.const 0) (local.get $round))

    (if (local.get $debug_active)
      (then
      (memory.copy
        (memory $debug)                 ;; Copy to memory
        (memory $main)                  ;; Copy from memory
        (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
        (global.get $KECCAK_ROUND_CONSTANTS_PTR) ;; Copy from address
        (i32.const 192)                 ;; Length
      )
      (call $log.label (local.get $debug_active) (i32.const 11))
      (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 192))
      )
    )

    (local.set $rnd_const
      (i64.load
        (memory $main)
        (i32.add
          (global.get $KECCAK_ROUND_CONSTANTS_PTR)
          (i32.shl (local.get $round) (i32.const 3)) ;; Convert the round number to an i64 offset
        )
      )
    )
    (call $log.singleI64 (local.get $debug_active) (i32.const 8) (i32.const 1) (local.get $rnd_const))

    (local.set $w0 (i64.load (memory $main) (global.get $CHI_RESULT_PTR)))
    (call $log.singleI64 (local.get $debug_active) (i32.const 8) (i32.const 2) (local.get $w0))

    (local.set $xor_result (i64.xor (local.get $rnd_const) (local.get $w0)))
    (call $log.singleI64 (local.get $debug_active) (i32.const 8) (i32.const 3) (local.get $xor_result))

    (i64.store
      (memory $main)
      (global.get $CHI_RESULT_PTR)
      (local.get $xor_result)
    )

    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $CHI_RESULT_PTR)    ;; Copy from address
          (i32.const 200)                 ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 10))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
      )
    )
    (call $log.fnExit (local.get $debug_active) (i32.const 8))
  )
)
