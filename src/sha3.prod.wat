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
;; left-to-right, bottom-to-top ordering.
;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(module
  ;; Function types
  (type $type_i32*1          (func (param i32)))
  (type $type_i32*2          (func (param i32 i32)))
  (type $type_i32*3          (func (param i32 i32 i32)))
  (type $type_i32*4          (func (param i32 i32 i32 i32)))
  (type $type_i32*5          (func (param i32 i32 i32 i32 i32)))
  (type $type_i32*3_i64      (func (param i32 i32 i32 i64)))
  (type $type_wasi_fd_close  (func (param i32)                                 (result i32)))
  (type $type_wasi_args      (func (param i32 i32)                             (result i32)))
  (type $type_wasi_path_open (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (type $type_wasi_fd_io     (func (param i32 i32 i32 i32)                     (result i32)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Import WASI preview 1 OS system calls
  (import "wasi_snapshot_preview1" "args_sizes_get" (func $wasi.args_sizes_get (type $type_wasi_args)))
  (import "wasi_snapshot_preview1" "args_get"       (func $wasi.args_get       (type $type_wasi_args)))
  (import "wasi_snapshot_preview1" "path_open"      (func $wasi.path_open      (type $type_wasi_path_open)))
  (import "wasi_snapshot_preview1" "fd_read"        (func $wasi.fd_read        (type $type_wasi_fd_io)))
  (import "wasi_snapshot_preview1" "fd_write"       (func $wasi.fd_write       (type $type_wasi_fd_io)))
  (import "wasi_snapshot_preview1" "fd_close"       (func $wasi.fd_close       (type $type_wasi_fd_close)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Memory page   1     Internal stuff
  ;; Memory pages  2     File IO pointers and buffers
  (memory $main (export "memory") 33)

  (global $DEBUG_IO_BUFF_PTR  i32 (i32.const 0))
  (global $FD_STDOUT          i32 (i32.const 1))
  (global $FD_STDERR          i32 (i32.const 2))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; $main Memory Map: Page 1
  ;;     Offset  Length   Type    Description
  ;; 0x00000000     200   i64x24  24 Keccak round constants
  ;; 0x000000C8     100   i32x25  Rotation table for Rho function
  ;; 0x0000012C     200   i64x25  Ping-pong BUF_0 — theta input / rho output / chi+iota output  (THETA_A_BLK_PTR = RHO_RESULT_PTR = CHI_RESULT_PTR)
  ;; 0x000001F4     200   i64x25  Ping-pong BUF_1 — theta output / pi output                    (THETA_RESULT_PTR = PI_RESULT_PTR)
  ;; 0x000002BC      40   i64x5   Theta C function output
  ;; 0x000002E4      40   i64x5   Theta D function output
  ;; 0x0000030C     100   i32x25  State index table
  ;; 0x00000370      25   i8x25   Theta XOR D offset table
  ;; 0x00000389       3           Padding (32-bit alignment)
  ;; 0x0000038C     200   bytes   DATA_PTR scratch buffer (rate-block staging; max 168 bytes for SHAKE128)
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; File IO  (all i64 output pointers must be 8-byte aligned otherwise wasmtime throws its toys out of the pram)
  ;; 0x000004E4       4   i32     file_fd
  ;; 0x000004F0       8   i64     Bytes transferred by fd_read [8-byte aligned]
  ;; 0x000004F8       8   i32x2   Read  iovec (ptr + len)
  ;; 0x00000500       8   i32x2   Write iovec (ptr + len)
  ;; 0x00000508       4   i32     Pointer to file path name
  ;; 0x0000050C       4   i32     Pointer to file path length
  ;; 0x00000510       4   i32     Number of command line arguments
  ;; 0x00000514       4   i32     Command line buffer size
  ;; 0x00000518       ?   i32[]   Array of argument pointers (needs double dereferencing)
  ;; Unused
  ;; 0x000005E4     256   data    Command line args buffer
  ;; Unused
  ;; 0x00000A44     128   data    ASCII representation of SHA value (up to 512 bits = 128 hex chars)
  ;; 0x00000AC4      16   data    Nybble-to-ASCII lookup table
  ;; 0x00000AE4       2   data    Two ASCII spaces
  ;; 0x00000AE7       5   data    Error message prefix "Err: "
  ;; 0x00000AEC      63           Error message "Bad args. Expected one of 224, 256, 384, or 512 plus <filename>"
  ;; 0x00000B30      25           Error message "No such file or directory"
  ;; 0x00000B50      24           Error message "Unable to read file size"
  ;; 0x00000B68      21           Error message "File too large (>4Gb)"
  ;; 0x00000B88      18           Error message "Error reading file"
  ;; 0x00000BA8      48           Error message "Neither a directory nor a symlink to a directory"
  ;; 0x00000BD8      19           Error message "Bad file descriptor"
  ;; 0x00000BF8      26           Error message "Memory allocation failed: "
  ;; 0x00000C18      23           Error message "Operation not permitted"
  ;; 0x00000C38      25           Error message "Filename too long (>=256)"
  ;; 0x00000C58      17           Error message "Permission denied"
  ;; 0x00000C78      21           Error message "IO error opening file"
  ;; The following debug messages are declared within debug start/end comment markers
  ;; These are stripped from the production build
  ;; 0x00000C90       6           "argc: "
  ;; 0x00000CA0      14           "argv_buf_len: "
  ;; 0x00000CB0       6           "Step: "
  ;; 0x00000CB8      13           "Return code: "
  ;; 0x00000CD0      15           "msg_blk_count: "
  ;; 0x00000CE0      19           "File size (bytes): "
  ;; 0x00000D00      28           "Bytes read by wasi.fd_read: "
  ;; 0x00000D20      20           "wasi.fd_read count: "
  ;; 0x00000D40      18           "Copy to new addr: "
  ;; 0x00000D60      18           "Copy length     : "
  ;; 0x00000D80      30           "Allocated extra memory pages: "
  ;; 0x00000DB0      27           "No memory allocation needed"
  ;; 0x00000DD0      32           "Current memory page allocation: "
  ;; 0x00000DF0      25           "wasi.fd_read chunk size: "
  ;; 0x00000E10      22           "Processing full buffer"
  ;; 0x00000E30      19           "Hit EOF (Partial): "
  ;; 0x00000E60      16           "Hit EOF (Zero): "
  ;; 0x00000E70      22           "Building empty msg blk"
  ;; 0x00000E90      18           "File size (bits): "
  ;; 0x00000EB0      17           "Distance to EOB: "
  ;; 0x00000ED0      12           "EOD offset: "
  ;; 0x00000EE0       9           "SHA arg: "
  ;; Unused
  ;; 0x00001DE4       ?   data    Buffer for strings being written to the console
  ;;

  (global $KECCAK_ROUND_CONSTANTS_PTR i32 (i32.const 0x00000000))
  ;; Round constants stored in little-endian byte order to match the LE state lanes
  (data $keccak_round_constants (memory $main) (i32.const 0x00000000)
    "\01\00\00\00\00\00\00\00" (; Round  0;) "\82\80\00\00\00\00\00\00" (; Round  1;)
    "\8a\80\00\00\00\00\00\80" (; Round  2;) "\00\80\00\80\00\00\00\80" (; Round  3;)
    "\8b\80\00\00\00\00\00\00" (; Round  4;) "\01\00\00\80\00\00\00\00" (; Round  5;)
    "\81\80\00\80\00\00\00\80" (; Round  6;) "\09\80\00\00\00\00\00\80" (; Round  7;)
    "\8a\00\00\00\00\00\00\00" (; Round  8;) "\88\00\00\00\00\00\00\00" (; Round  9;)
    "\09\80\00\80\00\00\00\00" (; Round 10;) "\0a\00\00\80\00\00\00\00" (; Round 11;)
    "\8b\80\00\80\00\00\00\00" (; Round 12;) "\8b\00\00\00\00\00\00\80" (; Round 13;)
    "\89\80\00\00\00\00\00\80" (; Round 14;) "\03\80\00\00\00\00\00\80" (; Round 15;)
    "\02\80\00\00\00\00\00\80" (; Round 16;) "\80\00\00\00\00\00\00\80" (; Round 17;)
    "\0a\80\00\00\00\00\00\00" (; Round 18;) "\0a\00\00\80\00\00\00\80" (; Round 19;)
    "\81\80\00\80\00\00\00\80" (; Round 20;) "\80\80\00\00\00\00\00\80" (; Round 21;)
    "\01\00\00\80\00\00\00\00" (; Round 22;) "\08\80\00\80\00\00\00\80" (; Round 23;)
  )

  ;; Memory areas used by the inner Keccak functions
  ;; Ping-pong buffer pointers — BUF_0 and BUF_1 are adjacent; aliases share the same address
  (global $THETA_A_BLK_PTR  (export "THETA_A_BLK_PTR")  i32 (i32.const 0x0000012C))  ;; BUF_0 — 200 bytes
  (global $RHO_RESULT_PTR   (export "RHO_RESULT_PTR")   i32 (i32.const 0x0000012C))  ;; BUF_0 alias
  (global $CHI_RESULT_PTR   (export "CHI_RESULT_PTR")   i32 (i32.const 0x0000012C))  ;; BUF_0 alias
  (global $THETA_RESULT_PTR (export "THETA_RESULT_PTR") i32 (i32.const 0x000001F4))  ;; BUF_1 — 200 bytes
  (global $PI_RESULT_PTR    (export "PI_RESULT_PTR")    i32 (i32.const 0x000001F4))  ;; BUF_1 alias
  (global $THETA_C_OUT_PTR  (export "THETA_C_OUT_PTR")  i32 (i32.const 0x000002BC))  ;; 40 bytes
  (global $THETA_D_OUT_PTR  (export "THETA_D_OUT_PTR")  i32 (i32.const 0x000002E4))  ;; 40 bytes

  ;; STATE_PTR/RATE_PTR alias BUF_0: state lives permanently in the permutation working buffer
  (global $STATE_PTR    (export "STATE_PTR")    i32 (i32.const 0x0000012C))  ;; BUF_0 alias — 200 bytes
  (global $DATA_PTR     (export "DATA_PTR")     i32 (i32.const 0x0000038C))  ;; length = rate bytes (up to 168 bytes for SHAKE128)

  ;; Default digest size = 256 bits, so in 64-bit words, rate = 17 and capacity = 8
  (global $RATE         (export "RATE")         (mut i32) (i32.const 17))
  (global $CAPACITY     (export "CAPACITY")     (mut i32) (i32.const 8))
  (global $RATE_PTR     (export "RATE_PTR")          i32  (i32.const 0x0000012C))  ;; BUF_0 alias
  (global $CAPACITY_PTR (export "CAPACITY_PTR") (mut i32) (i32.const 0x0000012C))  ;; set at runtime: STATE_PTR + RATE*8

  (global $FD_FILE_PTR         i32 (i32.const 0x000004E4))
  (global $NREAD_PTR           i32 (i32.const 0x000004F0))  ;; 8-byte aligned for fd_read i64 output
  (global $IOVEC_READ_BUF_PTR  i32 (i32.const 0x000004F8))
  (global $IOVEC_WRITE_BUF_PTR i32 (i32.const 0x00000500))
  (global $FILE_PATH_PTR       i32 (i32.const 0x00000508))
  (global $FILE_PATH_LEN_PTR   i32 (i32.const 0x0000050C))
  (global $ARGS_COUNT_PTR      i32 (i32.const 0x00000510))
  (global $ARGV_BUF_LEN_PTR    i32 (i32.const 0x00000514))
  (global $ARGV_PTRS_PTR       i32 (i32.const 0x00000518))
  (global $ARGV_BUF_PTR        i32 (i32.const 0x000005E4))
  (global $ASCII_HASH_PTR      i32 (i32.const 0x00000A44))  ;; Will need at most 128 bytes (SHA3-512 = 128 hex chars)

  (global $NYBBLE_TABLE        i32 (i32.const 0x00000AC4))  ;; Length = 16
  (data (memory $main) (i32.const 0x00000AC4) "0123456789abcdef")

  (global $DIGEST_LEN     (mut i32) (i32.const 256))  ;; Set by init_state; default 256
  (global $PARTIAL_BYTES  (mut i32) (i32.const 0))    ;; absorb: bytes accumulated in current partial rate-block
  (global $DOMAIN_BYTE    (mut i32) (i32.const 0x06)) ;; 0x06 = SHA3, 0x1f = SHAKE
  (global $SQUEEZE_OFFSET (mut i32) (i32.const 0))    ;; squeeze: byte offset within current rate-block
  (global $SHAKE_BYTE          i32  (i32.const 0x1f)) ;; Rate block terminator for SHAKE functions
  (global $SHA3_BYTE           i32  (i32.const 0x06)) ;; Rate block terminator for SHA3 functions

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Error messages
  (global $ASCII_SPACES        i32 (i32.const 0x00000AE4))  ;; Length = 2
  (data (memory $main) (i32.const 0x00000AE4) "  ")

  (global $ERR_MSG_PREFIX      i32 (i32.const 0x00000AE7))  ;; Length = 5
  (data (memory $main) (i32.const 0x00000AE7) "Err: ")

  (global $ERR_MSG_BAD_ARGS    i32 (i32.const 0x00000AEC))  ;; Length = 65
  (data (memory $main) (i32.const 0x00000AEC) "Bad args: 224|256|384|512 <file>  or  shake128|256 <bytes> <file>")

  (global $ERR_MSG_NOENT       i32 (i32.const 0x00000B30))  ;; Length = 25
  (data (memory $main) (i32.const 0x00000B30) "No such file or directory")

  (global $ERR_READING_FILE    i32 (i32.const 0x00000B88))  ;; Length = 18
  (data (memory $main) (i32.const 0x00000B88) "Error reading file")

  (global $ERR_NOT_DIR_SYMLINK i32 (i32.const 0x00000BA8))  ;; Length = 48
  (data (memory $main) (i32.const 0x00000BA8) "Neither a directory nor a symlink to a directory")

  (global $ERR_BAD_FD          i32 (i32.const 0x00000BD8))  ;; Length = 19
  (data (memory $main) (i32.const 0x00000BD8) "Bad file descriptor")

  (global $ERR_MEM_ALLOC       i32 (i32.const 0x00000BF8))  ;; Length = 26
  (data (memory $main) (i32.const 0x00000BF8) "Memory allocation failed: ")

  (global $ERR_NOT_PERMITTED   i32 (i32.const 0x00000C18))  ;; Length = 23
  (data (memory $main) (i32.const 0x00000C18) "Operation not permitted")

  (global $ERR_ARGV_TOO_LONG   i32 (i32.const 0x00000C38))  ;; Length = 25
  (data (memory $main) (i32.const 0x00000C38) "Filename too long (>=256)")

  (global $ERR_ACCESS          i32 (i32.const 0x00000C58))  ;; Length = 17
  (data (memory $main) (i32.const 0x00000C58) "Permission denied")

  (global $ERR_GEN_IO          i32 (i32.const 0x00000C78))  ;; Length = 21
  (data (memory $main) (i32.const 0x00000C78) "IO error opening file")

  (global $STR_WRITE_BUF_PTR   i32 (i32.const 0x00001DE4))

  ;; $main Memory Map: Pages 2-33
  (global $READ_BUFFER_PTR     i32 (i32.const 0x00010000))  ;; Start of memory page 2
  (global $READ_BUFFER_SIZE    i32 (i32.const 0x00200000))  ;; fd_read buffer size = 2Mb

  ;; If you change the value of $READ_BUFFER_SIZE, you must manually update $MSG_BLKS_PER_BUFFER!
  (global $MSG_BLKS_PER_BUFFER i32 (i32.const 0x00008000))  ;; $READ_BUFFER_SIZE / 64

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Initialise module state for a new hash/XOF computation.
  ;; Sets rate, capacity, domain byte; zeros the Keccak state; resets the absorb and squeeze cursors.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $init_state (export "init_state")
        (param $digest_len  i32)  ;; SHA3: 224|256|384|512; SHAKE: 128 (SHAKE128) or 256 (SHAKE256)
        (param $domain_byte i32)  ;; 0x06 = SHA3, 0x1f = SHAKE

    (global.set $DOMAIN_BYTE    (local.get $domain_byte))
    (global.set $DIGEST_LEN     (local.get $digest_len))
    (global.set $PARTIAL_BYTES  (i32.const 0))
    (global.set $SQUEEZE_OFFSET (i32.const 0))

    ;; Both $RATE and $CAPACITY hold the number of u64 words in each portion of the state
    ;; $RATE + $CAPACITY must always equal 25
    (global.set $RATE
      (i32.shr_u
        (i32.sub (i32.const 1600) (i32.shl (local.get $digest_len) (i32.const 1)))
        (i32.const 6)
      )
    )
    (global.set $CAPACITY     (i32.sub (i32.const 25) (global.get $RATE)))
    (global.set $CAPACITY_PTR (i32.add (global.get $STATE_PTR) (i32.shl (global.get $RATE) (i32.const 3))))

    (memory.fill (memory $main) (global.get $STATE_PTR) (i32.const 0) (i32.const 200))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Absorb $src_len bytes at $src_ptr into the sponge state.
  ;; Handles partial-block accumulation across calls; call finalize() when all input has been absorbed.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $absorb (export "absorb")
        (param $src_ptr  i32)
        (param $src_len  i32)

    (local $rate_bytes  i32)
    (local $fill_amount i32)

    (local.set $rate_bytes (i32.shl (global.get $RATE) (i32.const 3)))

    ;; Complete any partial rate-block accumulated from a previous absorb call
    (if (global.get $PARTIAL_BYTES)
      (then
        (local.set $fill_amount (i32.sub (local.get $rate_bytes) (global.get $PARTIAL_BYTES)))
        (if (i32.gt_u (local.get $fill_amount) (local.get $src_len))
          (then (local.set $fill_amount (local.get $src_len)))
        )
        (memory.copy (memory $main) (memory $main)
          (i32.add (global.get $DATA_PTR) (global.get $PARTIAL_BYTES))
          (local.get $src_ptr)
          (local.get $fill_amount)
        )
        (global.set $PARTIAL_BYTES (i32.add (global.get $PARTIAL_BYTES) (local.get $fill_amount)))
        (local.set $src_ptr        (i32.add (local.get $src_ptr)        (local.get $fill_amount)))
        (local.set $src_len        (i32.sub (local.get $src_len)        (local.get $fill_amount)))

        (if (i32.eq (global.get $PARTIAL_BYTES) (local.get $rate_bytes))
          (then
            (call $xor_data_with_rate (global.get $RATE) (global.get $DATA_PTR))
            (call $keccak24)
            (global.set $PARTIAL_BYTES (i32.const 0))
          )
        )
      )
    )

    ;; Absorb complete rate-blocks directly from the source buffer
    (block $no_full_blocks
      (loop $full_blocks
        (br_if $no_full_blocks (i32.lt_u (local.get $src_len) (local.get $rate_bytes)))

        (call $xor_data_with_rate (global.get $RATE) (local.get $src_ptr))
        (call $keccak24)

        (local.set $src_ptr (i32.add (local.get $src_ptr) (local.get $rate_bytes)))
        (local.set $src_len (i32.sub (local.get $src_len) (local.get $rate_bytes)))

        (br $full_blocks)
      )
    )

    ;; Save any leftover bytes into DATA_PTR for the next absorb call or for finalize
    (if (local.get $src_len)
      (then
        (memory.copy (memory $main) (memory $main)
          (global.get $DATA_PTR)
          (local.get $src_ptr)
          (local.get $src_len)
        )
        (global.set $PARTIAL_BYTES (local.get $src_len))
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Complete the absorb phase by appling the correct padding byte (0x06 for SHA3 or 0x1f for SHAKE) in the remainder of
  ;; the rate block, then run the final Keccak round
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $finalize (export "finalize")
    (local $rate_bytes i32)
    (local.set $rate_bytes (i32.shl (global.get $RATE) (i32.const 3)))

    ;; Zero the portion of DATA_PTR that follows the last absorbed byte
    (memory.fill (memory $main)
      (i32.add (global.get $DATA_PTR) (global.get $PARTIAL_BYTES))
      (i32.const 0)
      (i32.sub (local.get $rate_bytes) (global.get $PARTIAL_BYTES))
    )
    ;; Write domain separator immediately after the last absorbed byte
    (i32.store8 (memory $main)
      (i32.add (global.get $DATA_PTR) (global.get $PARTIAL_BYTES))
      (global.get $DOMAIN_BYTE)
    )
    ;; Set the high bit of the last byte in the rate block (pad10*1 rule)
    (i32.store8 (memory $main)
      (i32.add (global.get $DATA_PTR) (i32.sub (local.get $rate_bytes) (i32.const 1)))
      (i32.or
        (i32.load8_u (memory $main)
          (i32.add (global.get $DATA_PTR) (i32.sub (local.get $rate_bytes) (i32.const 1)))
        )
        (i32.const 0x80)
      )
    )
    (call $xor_data_with_rate (global.get $RATE) (global.get $DATA_PTR))
    (call $keccak24)

    (global.set $SQUEEZE_OFFSET (i32.const 0))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Squeeze $len bytes from the sponge state into the buffer at $out_ptr.
  ;; May be called repeatedly; applies an additional Keccak permutation whenever the rate block is exhausted.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $squeeze (export "squeeze")
        (param $out_ptr i32)
        (param $len     i32)

    (local $rate_bytes i32)
    (local $available  i32)
    (local $copy_len   i32)

    (local.set $rate_bytes (i32.shl (global.get $RATE) (i32.const 3)))

    (block $done
      (loop $squeeze_loop
        (br_if $done (i32.eqz (local.get $len)))

        (local.set $available
          (i32.sub (local.get $rate_bytes) (global.get $SQUEEZE_OFFSET))
        )
        (local.set $copy_len
          (if (result i32) (i32.lt_u (local.get $len) (local.get $available))
            (then (local.get $len))
            (else (local.get $available))
          )
        )
        (memory.copy (memory $main) (memory $main)
          (local.get $out_ptr)
          (i32.add (global.get $STATE_PTR) (global.get $SQUEEZE_OFFSET))
          (local.get $copy_len)
        )
        (global.set $SQUEEZE_OFFSET (i32.add (global.get $SQUEEZE_OFFSET) (local.get $copy_len)))
        (local.set $out_ptr         (i32.add (local.get $out_ptr)         (local.get $copy_len)))
        (local.set $len             (i32.sub (local.get $len)             (local.get $copy_len)))

        (if (i32.eq (global.get $SQUEEZE_OFFSET) (local.get $rate_bytes))
          (then
            (call $keccak24)
            (global.set $SQUEEZE_OFFSET (i32.const 0))
          )
        )

        (br $squeeze_loop)
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; This entry point is only called when the WASI instance is started - E.G. in JavaScript, by calling wasi.start().
  ;;
  ;; Expects two command line arguments:
  ;;   <digest-bits>  one of 224, 256, 384, or 512
  ;;   <file>         a path to the file to be hashed.
  ;;                  This pathname is relative to directory preopened when the WASI instance is created.
  ;;
  ;; Step 0) Parse the command line arguments using wasi.args_sizes_get and wasi.args_get.
  ;;         Validate that argument count is correct and that total argument length does not exceed some arbitrary limit
  ;;         (i.e., is not > 256 bytes)
  ;; Step 1) Parse digest bit length argument
  ;; Step 2) Parse filename argument and open file
  ;; Step 3) Initialise Keccak state
  ;; Step 4) While bytes_read > 0, read the file in 2 MB chunks, absorbing each rate-sized block into the Keccak state.
  ;; Step 5) Once we hit EOF, finalize the last block by applying domain specific padding (FIPS 202 §B.2)
  ;; Step 6) Close the file
  ;; Step 7) Squeeze digest_bytes from the state and write the result as "<hex>  <filename>\n" to stdout.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "_start")
    (local $argc            i32)
    (local $argv_buf_len    i32)
    (local $hash_len_ptr    i32)
    (local $hash_len_val    i32)  ;; 4-byte LE load of the algo argument
    (local $digest_len      i32)  ;; SHA3: 224|256|384|512  SHAKE: 128|256
    (local $digest_bytes    i32)  ;; SHA3: digest_len/8; SHAKE: user-supplied output byte count
    (local $domain_byte     i32)  ;; 0x06 = SHA3, 0x1f = SHAKE
    (local $remaining       i32)  ;; bytes still to output in the hex-squeeze loop
    (local $chunk           i32)  ;; current chunk size in the hex-squeeze loop
    (local $filename_ptr    i32)
    (local $filename_len    i32)
    (local $file_fd         i32)
    (local $return_code     i32)
    (local $bytes_read      i32)
    (local $byte_offset     i32)
    (block $exit
      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 0: Fetch argument count and total buffer size
      (drop
        (call $wasi.args_sizes_get (global.get $ARGS_COUNT_PTR) (global.get $ARGV_BUF_LEN_PTR))
      )

      (local.set $argc         (i32.load (memory $main) (global.get $ARGS_COUNT_PTR)))
      (local.set $argv_buf_len (i32.load (memory $main) (global.get $ARGV_BUF_LEN_PTR)))

      ;; Avoid buffer overrun
      (if (i32.gt_u (local.get $argv_buf_len) (i32.const 256))
        (then
          (call $writeln (i32.const 2) (global.get $ERR_ARGV_TOO_LONG) (i32.const 25))
          (br $exit)
        )
      )

      ;; Minimum: needs at least hash/variant + filename (2 user args)
      (if (i32.lt_u (local.get $argc) (i32.const 2))
        (then
          (call $writeln (i32.const 2) (global.get $ERR_MSG_BAD_ARGS) (i32.const 65))
          (br $exit)
        )
      )

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 1: Parse algorithm argument to determine SHA3 or SHAKE mode.
      ;;
      ;; Uses relative indexing from the end of argv so that the module works regardless of how many leading args the
      ;; host runtime prepends (argv[0], script path, etc.):
      ;;   SHA3:   [..., hash_size, filename]      — hash_size at argc-1, filename at argc
      ;;   SHAKE:  [..., variant, bytes, filename] — variant at argc-2, bytes at argc-1, filename at argc
      ;;
      (drop
        (call $wasi.args_get (global.get $ARGV_PTRS_PTR) (global.get $ARGV_BUF_PTR))
      )

      (block $args_ok
        ;; SHAKE detection: check the third-to-last arg for "shak" (only when at least 3 args exist)
        (if (i32.ge_u (local.get $argc) (i32.const 3))
          (then
            (drop
              (local.set $hash_len_ptr (call $fetch_arg_n (i32.sub (local.get $argc) (i32.const 2))))
            )
            ;; Does the third last argument start with "shak"?
            (if (i32.eq
                  (i32.load (memory $main) (local.get $hash_len_ptr))
                  (i32.const 0x6B616873) ;; "shak"
                )
              (then
                (block $shake_ok
                  ;; Bytes 4-7 distinguish the variant: "e128" (LE 0x38323165) or "e256" (LE 0x36353265)
                  (if (i32.eq
                        (i32.load (memory $main) (i32.add (local.get $hash_len_ptr) (i32.const 4)))
                        (i32.const 0x38323165) ;; "e128"
                      )
                    (then
                      (local.set $digest_len  (i32.const 128))
                      (local.set $domain_byte (global.get $SHAKE_BYTE))
                      (br $shake_ok)
                    )
                  )
                  (if (i32.eq
                        (i32.load (memory $main) (i32.add (local.get $hash_len_ptr) (i32.const 4)))
                        (i32.const 0x36353265) ;; "e256"
                      )
                    (then
                      (local.set $digest_len  (i32.const 256))
                      (local.set $domain_byte (global.get $SHAKE_BYTE))
                      (br $shake_ok)
                    )
                  )
                  (call $writeln (i32.const 2) (global.get $ERR_MSG_BAD_ARGS) (i32.const 65))
                  (br $exit)
                )

                ;; Parse output_bytes from the second  last arg (argc-1)
                (local.set $hash_len_val
                  (local.set $hash_len_ptr
                    (call $fetch_arg_n (i32.sub (local.get $argc) (i32.const 1)))
                  )
                )
                (local.set $digest_bytes
                  (call $parse_decimal (local.get $hash_len_ptr) (local.get $hash_len_val))
                )
                (br $args_ok)
              )
            )
          )
        )

        ;; SHA3 mode: second last arg should hold the number of digest bits
        (drop
          (local.set $hash_len_ptr (call $fetch_arg_n (i32.sub (local.get $argc) (i32.const 1))))
        )
        (local.set $hash_len_val (i32.load (memory $main) (local.get $hash_len_ptr)))

        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00343232)) ;; "224\0"
          (then
            (local.set $digest_len  (i32.const 224))
            (local.set $domain_byte (global.get $SHA3_BYTE))
            (br $args_ok)
          )
        )
        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00363532)) ;; "256\0"
          (then
            (local.set $digest_len  (i32.const 256))
            (local.set $domain_byte (global.get $SHA3_BYTE))
            (br $args_ok)
          )
        )
        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00343833)) ;; "384\0"
          (then
            (local.set $digest_len  (i32.const 384))
            (local.set $domain_byte (global.get $SHA3_BYTE))
            (br $args_ok)
          )
        )
        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00323135)) ;; "512\0"
          (then
            (local.set $digest_len  (i32.const 512))
            (local.set $domain_byte (global.get $SHA3_BYTE))
            (br $args_ok)
          )
        )

        (call $writeln (i32.const 2) (global.get $ERR_MSG_BAD_ARGS) (i32.const 65))
        (br $exit)
      ) ;; $args_ok

      ;; For SHA3 mode, derive output byte count from digest length; SHAKE already set it above
      (if (i32.ne (local.get $domain_byte) (global.get $SHAKE_BYTE))
        (then
          (local.set $digest_bytes (i32.shr_u (local.get $digest_len) (i32.const 3)))
        )
      )

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 2: Extract filename (last arg) and open the file
      (local.set $filename_len
        (local.set $filename_ptr
          (call $fetch_arg_n (local.get $argc)) ;; fetch_arg_n leaves two values on the stack, hence nested set calls
        )
      )

      (i32.store (memory $main) (global.get $FILE_PATH_PTR)     (local.get $filename_ptr))
      (i32.store (memory $main) (global.get $FILE_PATH_LEN_PTR) (local.get $filename_len))

      (local.tee $return_code
        (local.set $file_fd
          (call $file_open
            (i32.const 3)              ;; preopened fd for the directory
            (local.get $filename_ptr)
            (local.get $filename_len)
          )
        )
      )

      (if ;; $return_code > 0
        (then
          (br $exit)
        )
      )

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 3: Initialise Keccak state
      (call $init_state (local.get $digest_len) (local.get $domain_byte))

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 4: Read file in 2 MB chunks and absorb into the sponge
      (i32.store (memory $main) (global.get $IOVEC_READ_BUF_PTR) (global.get $READ_BUFFER_PTR))
      (i32.store (memory $main)
        (i32.add (global.get $IOVEC_READ_BUF_PTR) (i32.const 4))
        (global.get $READ_BUFFER_SIZE)
      )

      (block $eof
        (loop $read_chunk
          (local.tee $return_code
            ;; Returns errno: i32
            ;; The bytes read is discovered by reading the i32 at $NREAD_PTR
            (call $wasi.fd_read
              (local.get $file_fd)
              (global.get $IOVEC_READ_BUF_PTR)
              (i32.const 1)
              (global.get $NREAD_PTR)
            )
          )

          (if ;; $return_code > 0
            (then
              (call $writeln (i32.const 2) (global.get $ERR_READING_FILE) (i32.const 18))
              (br $exit)
            )
          )

          (if ;; EOF?
            (i32.eqz (local.tee $bytes_read (i32.load (memory $main) (global.get $NREAD_PTR))))
            (then
              (br $eof)
            )
          )

          (call $absorb (global.get $READ_BUFFER_PTR) (local.get $bytes_read))

          (br $read_chunk)
        )
      )

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 5: Apply SHA3 padding and run the final keccak round
      (call $finalize)

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 6: Close the file
      (local.set $return_code (call $wasi.fd_close (local.get $file_fd)))

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 7: Squeeze digest_bytes in 64-byte chunks, hex-encode each chunk and write to stdout.
      ;;         Works for both fixed-length SHA3 digests and arbitrary-length SHAKE XOF output.
      (local.set $remaining (local.get $digest_bytes))

      (block $hex_done
        (loop $hex_chunk
          (br_if $hex_done (i32.eqz (local.get $remaining)))

          (local.set $chunk
            (if (result i32) (i32.lt_u (local.get $remaining) (i32.const 64))
              (then (local.get $remaining))
              (else (i32.const 64))
            )
          )

          (call $squeeze (global.get $DATA_PTR) (local.get $chunk))

          (local.set $byte_offset (i32.const 0))
          (loop $to_hex
            (call $to_asc_pair
              (i32.load8_u (memory $main) (i32.add (global.get $DATA_PTR) (local.get $byte_offset)))
              (i32.add (global.get $ASCII_HASH_PTR) (i32.shl (local.get $byte_offset) (i32.const 1)))
            )
            (br_if $to_hex
              (i32.lt_u
                (local.tee $byte_offset (i32.add (local.get $byte_offset) (i32.const 1)))
                (local.get $chunk)
              )
            )
          )

          (call $write (global.get $FD_STDOUT) (global.get $ASCII_HASH_PTR) (i32.shl (local.get $chunk) (i32.const 1)))

          (local.set $remaining (i32.sub (local.get $remaining) (local.get $chunk)))
          (br $hex_chunk)
        ) ;; Loop $hex_chunk
      ) ;; Block $hex_done

      ;; Write "  <filename>\n" to stdout
      (call $write   (global.get $FD_STDOUT) (global.get $ASCII_SPACES) (i32.const 2))
      (call $writeln
        (global.get $FD_STDOUT)
        (i32.load (memory $main) (global.get $FILE_PATH_PTR))
        (i32.load (memory $main) (global.get $FILE_PATH_LEN_PTR))
      )
    ) ;; Block $exit
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Write $str_len bytes at $str_ptr to file descriptor $fd
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $write
        (param $fd      i32)
        (param $str_ptr i32)
        (param $str_len i32)

    (i32.store (memory $main) (global.get $IOVEC_WRITE_BUF_PTR) (local.get $str_ptr))
    (i32.store (memory $main)
      (i32.add (global.get $IOVEC_WRITE_BUF_PTR) (i32.const 4))
      (local.get $str_len)
    )

    (drop ;; Don't care about the number of bytes written
      (call $wasi.fd_write
        (local.get $fd)
        (global.get $IOVEC_WRITE_BUF_PTR)
        (i32.const 1)
        (global.get $NREAD_PTR)
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Write optional "Err: " prefix (when fd=2) then $str_len bytes from $str_ptr into STR_WRITE_BUF_PTR.
  ;; Returns $buf_ptr positioned immediately after the message, ready for further appending.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $format_msg
        (param $fd      i32)
        (param $str_ptr i32)
        (param $str_len i32)
        (result i32)

    (local $buf_ptr i32)
    (local.set $buf_ptr (global.get $STR_WRITE_BUF_PTR))

    ;; Are we writing to stderr?
    (if (i32.eq (local.get $fd) (i32.const 2))
      (then ;; prefix the message with "Err: "
        (memory.copy (memory $main) (memory $main)
          (local.get $buf_ptr) (global.get $ERR_MSG_PREFIX) (i32.const 5)
        )
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 5)))
      )
    )

    (memory.copy (memory $main) (memory $main)
      (local.get $buf_ptr) (local.get $str_ptr) (local.get $str_len)
    )

    (i32.add (local.get $buf_ptr) (local.get $str_len))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Write $str_len bytes followed by a line feed; prefix with "Err: " when writing to stderr
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $writeln
        (param $fd      i32)
        (param $str_ptr i32)
        (param $str_len i32)

    (local $buf_ptr i32)
    (local.set $buf_ptr
      (call $format_msg (local.get $fd) (local.get $str_ptr) (local.get $str_len))
    )

    (i32.store8 (memory $main) (local.get $buf_ptr) (i32.const 0x0A))

    (call $write
      (local.get $fd)
      (global.get $STR_WRITE_BUF_PTR)
      (i32.sub (i32.add (local.get $buf_ptr) (i32.const 1)) (global.get $STR_WRITE_BUF_PTR))
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Write $str_len bytes followed by " 0x<hex_val>" and a line feed; prefix with "Err: " when writing to stderr
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $writeln_with_value
        (param $fd      i32)
        (param $str_ptr i32)
        (param $str_len i32)
        (param $val     i32)

    (local $buf_ptr i32)
    (local.set $buf_ptr
      (call $format_msg (local.get $fd) (local.get $str_ptr) (local.get $str_len))
    )

    (i32.store8 (memory $main) (local.get $buf_ptr) (i32.const 0x20)) ;; ASCII space
    (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 1)))

    (i32.store16 (memory $main) (local.get $buf_ptr) (i32.const 0x7830)) ;; ASCII "0x" as LE integer
    (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))

    (call $i32_to_hex_str (local.get $val) (local.get $buf_ptr))
    (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 8)))

    (i32.store8 (memory $main) (local.get $buf_ptr) (i32.const 0x0A)) ;; ASCII line feed

    (call $write
      (local.get $fd)
      (global.get $STR_WRITE_BUF_PTR)
      (i32.sub (i32.add (local.get $buf_ptr) (i32.const 1)) (global.get $STR_WRITE_BUF_PTR))
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Convert one byte to two hex ASCII characters and write them to $out_ptr
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $to_asc_pair
        (param $byte    i32)
        (param $out_ptr i32)

    (i32.store8 (memory $main)
      (local.get $out_ptr)
      (i32.load8_u (memory $main)
        (i32.add (global.get $NYBBLE_TABLE) (i32.shr_u (local.get $byte) (i32.const 4)))
      )
    )
    (i32.store8 (memory $main)
      (i32.add (local.get $out_ptr) (i32.const 1))
      (i32.load8_u (memory $main)
        (i32.add (global.get $NYBBLE_TABLE) (i32.and (local.get $byte) (i32.const 0x0F)))
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Convert an i32 to 8 ASCII hex characters in network (big-endian) byte order, write to $str_ptr
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $i32_to_hex_str
        (param $i32_val i32)
        (param $str_ptr i32)

    (call $to_asc_pair
      (i32.shr_u (local.get $i32_val) (i32.const 24))
      (local.get $str_ptr)
    )
    (call $to_asc_pair
      (i32.and (i32.shr_u (local.get $i32_val) (i32.const 16)) (i32.const 0xFF))
      (i32.add (local.get $str_ptr) (i32.const 2))
    )
    (call $to_asc_pair
      (i32.and (i32.shr_u (local.get $i32_val) (i32.const 8)) (i32.const 0xFF))
      (i32.add (local.get $str_ptr) (i32.const 4))
    )
    (call $to_asc_pair
      (i32.and (local.get $i32_val) (i32.const 0xFF))
      (i32.add (local.get $str_ptr) (i32.const 6))
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Return the pointer and byte length of the n'th (1-based) command line argument.
  ;; $wasi.args_get must have been called before this function.
  ;;
  ;; Returns: (ptr: i32, len: i32)
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $fetch_arg_n
        (param $arg_num i32)
        (result i32 i32)

    (local $argc         i32)
    (local $argv_buf_len i32)
    (local $arg_n_ptr    i32)
    (local $arg_n_len    i32)

    (local.set $argc         (i32.load (memory $main) (global.get $ARGS_COUNT_PTR)))
    (local.set $argv_buf_len (i32.load (memory $main) (global.get $ARGV_BUF_LEN_PTR)))

    (local.set $arg_n_ptr
      (i32.load (memory $main)
        (i32.add
          (global.get $ARGV_PTRS_PTR)
          (i32.shl (i32.sub (local.get $arg_num) (i32.const 1)) (i32.const 2))
        )
      )
    )

    (local.tee $arg_n_len
      (i32.sub
        (if (result i32)
          (i32.eq (local.get $arg_num) (local.get $argc))
          (then
            (i32.sub
              (i32.add (i32.load (memory $main) (global.get $ARGV_PTRS_PTR)) (local.get $argv_buf_len))
              (local.get $arg_n_ptr)
            )
          )
          (else
            (i32.sub
              (i32.load (memory $main)
                (i32.add (global.get $ARGV_PTRS_PTR) (i32.shl (local.get $arg_num) (i32.const 2)))
              )
              (local.get $arg_n_ptr)
            )
          )
        )
        (i32.const 1)  ;; subtract null terminator
      )
    )

    (local.get $arg_n_ptr)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Parse an ASCII decimal string at $ptr/$len into an i32
  ;; Stops at the first non-digit byte
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $parse_decimal
        (param $ptr i32)
        (param $len i32)
        (result i32)

    (local $result i32)
    (local $i      i32)
    (local $ch     i32)

    (block $done
      (loop $digits
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $ch
          (i32.sub
            (i32.load8_u (memory $main) (i32.add (local.get $ptr) (local.get $i)))
            (i32.const 48) ;; All ASCII digits start at 0x30
          )
        )
        (br_if $done (i32.gt_u (local.get $ch) (i32.const 9)))
        (local.set $result
          (i32.add
            (i32.mul (local.get $result) (i32.const 10))
            (local.get $ch)
          )
        )
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $digits)
      )
    )

    (local.get $result)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Open the file at $path_offset/$path_len inside the preopened directory $fd_dir.
  ;;
  ;; Returns: (return_code: i32, file_fd: i32)
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $file_open
        (param $fd_dir      i32)
        (param $path_offset i32)
        (param $path_len    i32)
        (result i32 i32)

    (local $return_code i32)
    (local $file_fd     i32)

    (block $exit
      (local.tee $return_code
        (call $wasi.path_open
          (local.get $fd_dir)
          (i32.const 0)             ;; dirflags
          (local.get $path_offset)
          (local.get $path_len)
          (i32.const 0)             ;; oflags (O_RDONLY)
          (i64.const 2)             ;; rights: FD_READ
          (i64.const 0)             ;; inherited rights
          (i32.const 0)             ;; fdflags
          (global.get $FD_FILE_PTR)
        )
      )

      (if ;; some sort of IO error occurred
        (then
          (block $error_handled
            (if (i32.eq (local.get $return_code) (i32.const 0x02))  ;; Permission denied
              (then (call $writeln (i32.const 2) (global.get $ERR_ACCESS)         (i32.const 17)) (br $error_handled))
            )
            (if (i32.eq (local.get $return_code) (i32.const 0x08))  ;; Bad file descriptor
              (then (call $writeln (i32.const 2) (global.get $ERR_BAD_FD)          (i32.const 19)) (br $error_handled))
            )
            (if (i32.eq (local.get $return_code) (i32.const 0x2C))  ;; No such file or directory
              (then (call $writeln (i32.const 2) (global.get $ERR_MSG_NOENT)       (i32.const 25)) (br $error_handled))
            )
            (if (i32.eq (local.get $return_code) (i32.const 0x36))  ;; Neither a directory nor a symlink
              (then (call $writeln (i32.const 2) (global.get $ERR_NOT_DIR_SYMLINK) (i32.const 48)) (br $error_handled))
            )
            (if (i32.eq (local.get $return_code) (i32.const 0x3F))  ;; Operation not permitted
              (then (call $writeln (i32.const 2) (global.get $ERR_NOT_PERMITTED)   (i32.const 23)) (br $error_handled))
            )
            ;; Generic fallback: unrecognised WASI errno — display message and return code
            (call $writeln_with_value (i32.const 2) (global.get $ERR_GEN_IO) (i32.const 21) (local.get $return_code))
          )
          (br $exit)
        )
      )

      (local.set $file_fd (i32.load (memory $main) (global.get $FD_FILE_PTR)))
    )

    (local.get $return_code)
    (local.get $file_fd)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Run 24 Keccak rounds in-place on BUF_0 (STATE_PTR = THETA_A_BLK_PTR = CHI_RESULT_PTR)
  ;; The loop has been unrolled to improve optimisation
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $keccak24
    (call $keccak (i32.const 0))
    (call $keccak (i32.const 1))
    (call $keccak (i32.const 2))
    (call $keccak (i32.const 3))
    (call $keccak (i32.const 4))
    (call $keccak (i32.const 5))
    (call $keccak (i32.const 6))
    (call $keccak (i32.const 7))
    (call $keccak (i32.const 8))
    (call $keccak (i32.const 9))
    (call $keccak (i32.const 10))
    (call $keccak (i32.const 11))
    (call $keccak (i32.const 12))
    (call $keccak (i32.const 13))
    (call $keccak (i32.const 14))
    (call $keccak (i32.const 15))
    (call $keccak (i32.const 16))
    (call $keccak (i32.const 17))
    (call $keccak (i32.const 18))
    (call $keccak (i32.const 19))
    (call $keccak (i32.const 20))
    (call $keccak (i32.const 21))
    (call $keccak (i32.const 22))
    (call $keccak (i32.const 23))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Prepare the Keccak internal state, partitioning it according to the specified digest length and absorbing the first
  ;; input block
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $prepare_state
        (export "prepare_state")
        (param $init_mem   i32) ;; Initialise state memory?
        (param $digest_len i32) ;; Defaults to 256

    ;; If $digest_len is not one of 224, 256, 384 or 512, then default to 256
    (block $digest_ok
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 224)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 256)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 384)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 512)))

      (local.set $digest_len (i32.const 256))
    )

    ;; Initialise the internal state?
    (if (local.get $init_mem)
      (then
        (memory.fill (memory $main) (global.get $STATE_PTR) (i32.const 0) (i32.const 200))
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

    ;; XOR first input block with the rate
    (call $xor_data_with_rate (global.get $RATE) (global.get $DATA_PTR))

)

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; In place XOR the data at $RATE_PTR with the data at $DATA_PTR
  ;; Data is absorbed in FIPS 202 lane order: A[0,0], A[1,0], ..., A[4,0], A[0,1], ...
  ;; i.e. sequential byte offsets 0, 8, 16, ... from RATE_PTR (FIPS 202 §3.1.2)
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $xor_data_with_rate
        (param $rate_words i32)
        (param $src_ptr    i32)

    (local $data_idx     i32)
    (local $rate_ptr     i32)
    (loop $xor_loop
      ;; FIPS 202 §3.1.2: lane(x,y) is at byte offset (5y+x)*8; absorb sequentially from lane(0,0)
      (local.set $rate_ptr
        (i32.add (global.get $RATE_PTR) (i32.shl (local.get $data_idx) (i32.const 3)))
      )

      (i64.store
        (memory $main)
        (local.get $rate_ptr)
        (i64.xor
          (i64.load (memory $main) (local.get $rate_ptr))
          (i64.load (memory $main) (i32.add (local.get $src_ptr) (i32.shl (local.get $data_idx) (i32.const 3))))
        )
      )

      (local.set $data_idx (i32.add (local.get $data_idx) (i32.const 1)))

      (br_if $xor_loop
        (local.tee $rate_words (i32.sub (local.get $rate_words) (i32.const 1)))
      )
    )

  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Perform a single round of the Keccak function
  ;; The output lives at $CHI_RESULT_PTR because the the last step function (iota) performs an in-place modification
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $keccak (export "keccak")
        (param $round i32)

    (call $theta)
    (call $rho)
    (call $pi)
    (call $chi)
    (call $iota (local.get $round))

  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Theta function — merged C/D/XOR stages: C[0..4] and D[0..4] held as i64 locals, eliminating the
  ;; THETA_C_OUT_PTR and THETA_D_OUT_PTR memory round-trips that the three-sub-function pipeline required.
  ;;
  ;; Reads 200 bytes starting at $THETA_A_BLK_PTR
  ;; Writes 200 bytes to $THETA_RESULT_PTR
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $theta (export "theta")
    (local $c0 i64) (local $c1 i64) (local $c2 i64) (local $c3 i64) (local $c4 i64)
    (local $d0 i64) (local $d1 i64) (local $d2 i64) (local $d3 i64) (local $d4 i64)
    ;; C[x] = XOR of all 5 rows in column x (inter-row stride = 40, inter-column stride = 8)
    (local.set $c0
      (i64.xor
        (i64.xor
          (i64.xor
            (i64.xor
              (i64.load (memory $main) offset=0  (global.get $THETA_A_BLK_PTR)) ;; y=0
              (i64.load (memory $main) offset=40 (global.get $THETA_A_BLK_PTR)) ;; y=1
            )
            (i64.load (memory $main) offset=80 (global.get $THETA_A_BLK_PTR))   ;; y=2
          )
          (i64.load (memory $main) offset=120 (global.get $THETA_A_BLK_PTR))    ;; y=3
        )
        (i64.load (memory $main) offset=160 (global.get $THETA_A_BLK_PTR))      ;; y=4
      )
    )
    (local.set $c1
      (i64.xor
        (i64.xor
          (i64.xor
            (i64.xor
              (i64.load (memory $main) offset=8  (global.get $THETA_A_BLK_PTR)) ;; y=0
              (i64.load (memory $main) offset=48 (global.get $THETA_A_BLK_PTR)) ;; y=1
            )
            (i64.load (memory $main) offset=88 (global.get $THETA_A_BLK_PTR))   ;; y=2
          )
          (i64.load (memory $main) offset=128 (global.get $THETA_A_BLK_PTR))    ;; y=3
        )
        (i64.load (memory $main) offset=168 (global.get $THETA_A_BLK_PTR))      ;; y=4
      )
    )
    (local.set $c2
      (i64.xor
        (i64.xor
          (i64.xor
            (i64.xor
              (i64.load (memory $main) offset=16  (global.get $THETA_A_BLK_PTR)) ;; y=0
              (i64.load (memory $main) offset=56  (global.get $THETA_A_BLK_PTR)) ;; y=1
            )
            (i64.load (memory $main) offset=96  (global.get $THETA_A_BLK_PTR))   ;; y=2
          )
          (i64.load (memory $main) offset=136 (global.get $THETA_A_BLK_PTR))     ;; y=3
        )
        (i64.load (memory $main) offset=176 (global.get $THETA_A_BLK_PTR))       ;; y=4
      )
    )
    (local.set $c3
      (i64.xor
        (i64.xor
          (i64.xor
            (i64.xor
              (i64.load (memory $main) offset=24 (global.get $THETA_A_BLK_PTR)) ;; y=0
              (i64.load (memory $main) offset=64 (global.get $THETA_A_BLK_PTR)) ;; y=1
            )
            (i64.load (memory $main) offset=104 (global.get $THETA_A_BLK_PTR))  ;; y=2
          )
          (i64.load (memory $main) offset=144 (global.get $THETA_A_BLK_PTR))    ;; y=3
        )
        (i64.load (memory $main) offset=184 (global.get $THETA_A_BLK_PTR))      ;; y=4
      )
    )
    (local.set $c4
      (i64.xor
        (i64.xor
          (i64.xor
            (i64.xor
              (i64.load (memory $main) offset=32 (global.get $THETA_A_BLK_PTR)) ;; y=0
              (i64.load (memory $main) offset=72 (global.get $THETA_A_BLK_PTR)) ;; y=1
            )
            (i64.load (memory $main) offset=112 (global.get $THETA_A_BLK_PTR))  ;; y=2
          )
          (i64.load (memory $main) offset=152 (global.get $THETA_A_BLK_PTR))    ;; y=3
        )
        (i64.load (memory $main) offset=192 (global.get $THETA_A_BLK_PTR))      ;; y=4
      )
    )

    ;; D[x] = C[x-1] XOR rotl(C[x+1], 1) — FIPS 202 §3.2.1
    (local.set $d0 (i64.xor (local.get $c4) (i64.rotl (local.get $c1) (i64.const 1))))
    (local.set $d1 (i64.xor (local.get $c0) (i64.rotl (local.get $c2) (i64.const 1))))
    (local.set $d2 (i64.xor (local.get $c1) (i64.rotl (local.get $c3) (i64.const 1))))
    (local.set $d3 (i64.xor (local.get $c2) (i64.rotl (local.get $c4) (i64.const 1))))
    (local.set $d4 (i64.xor (local.get $c3) (i64.rotl (local.get $c0) (i64.const 1))))

    ;; For each of the 25 a_blk_idx values (0-24), the byte offset into THETA_D_OUT_PTR for D[x].
    ;; x = (a_blk_idx % 5 + 2) % 5 maps to D-offsets [16,24,32,0,8] repeating across all 5 rows.
    ;;
    ;; A'[x,y] = A[x,y] XOR D[x] — written to THETA_RESULT_PTR in the above D-offset traversal order

    ;; y=2 group: A[2,2]=96, A[3,2]=104, A[4,2]=112, A[0,2]=80, A[1,2]=88
    (i64.store (memory $main) offset=96
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d2) (i64.load (memory $main) offset=96  (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=104
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d3) (i64.load (memory $main) offset=104 (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=112
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d4) (i64.load (memory $main) offset=112 (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=80
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d0) (i64.load (memory $main) offset=80  (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=88
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d1) (i64.load (memory $main) offset=88  (global.get $THETA_A_BLK_PTR)))
    )

    ;; y=3 group: A[2,3]=136, A[3,3]=144, A[4,3]=152, A[0,3]=120, A[1,3]=128
    (i64.store (memory $main) offset=136
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d2) (i64.load (memory $main) offset=136 (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=144
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d3) (i64.load (memory $main) offset=144 (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=152
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d4) (i64.load (memory $main) offset=152 (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=120
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d0) (i64.load (memory $main) offset=120 (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=128
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d1) (i64.load (memory $main) offset=128 (global.get $THETA_A_BLK_PTR)))
    )

    ;; y=4 group: A[2,4]=176, A[3,4]=184, A[4,4]=192, A[0,4]=160, A[1,4]=168
    (i64.store (memory $main) offset=176
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d2) (i64.load (memory $main) offset=176 (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=184
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d3) (i64.load (memory $main) offset=184 (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=192
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d4) (i64.load (memory $main) offset=192 (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=160
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d0) (i64.load (memory $main) offset=160 (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=168
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d1) (i64.load (memory $main) offset=168 (global.get $THETA_A_BLK_PTR)))
    )

    ;; y=0 group: A[2,0]=16, A[3,0]=24, A[4,0]=32, A[0,0]=0, A[1,0]=8
    (i64.store (memory $main) offset=16
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d2) (i64.load (memory $main) offset=16  (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=24
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d3) (i64.load (memory $main) offset=24  (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=32
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d4) (i64.load (memory $main) offset=32  (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=0
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d0) (i64.load (memory $main) offset=0   (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=8
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d1) (i64.load (memory $main) offset=8   (global.get $THETA_A_BLK_PTR)))
    )

    ;; y=1 group: A[2,1]=56, A[3,1]=64, A[4,1]=72, A[0,1]=40, A[1,1]=48
    (i64.store (memory $main) offset=56
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d2) (i64.load (memory $main) offset=56  (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=64
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d3) (i64.load (memory $main) offset=64  (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=72
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d4) (i64.load (memory $main) offset=72  (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=40
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d0) (i64.load (memory $main) offset=40  (global.get $THETA_A_BLK_PTR)))
    )
    (i64.store (memory $main) offset=48
      (global.get $THETA_RESULT_PTR)
      (i64.xor (local.get $d1) (i64.load (memory $main) offset=48  (global.get $THETA_A_BLK_PTR)))
    )

  )
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; For each of the 25 i64 words at $THETA_RESULT_PTR, rotate each word by an amount derived from the word length w
  ;; which in turn, is derived from the length l (where w = 2^l)
  ;;
  ;; Word zero always has a rotation value of 0, but for the 24 other words in the 5 * 5 state matrix, the rotation
  ;; amount for the word at x,y is given by r[x,y] and defined as
  ;;
  ;; for w=64
  ;;
  ;; r[0,0] = 0
  ;; Then for t = 0..23:
  ;;   Walk x,y coordinates with (x, y) <- (y, (2x + 3y) mod 5)
  ;;   r[x, y] = ((t+1) * (t+2) / 2) mod w
  ;;
  ;; The traversal order is stored in a table known as the RHOTATION_TABLE.  However, these values do not need to be
  ;; stored in memory as they are constants that can be hard coded into the function.
  ;;
  ;; The rotation amounts for the 24 non-zero words are as follows:
  ;;   A[2,2] A[3,2] A[4,2] A[0,2] A[1,2]  (y=2 group)
  ;;   A[2,3] A[3,3] A[4,3] A[0,3] A[1,3]  (y=3 group)
  ;;   A[2,4] A[3,4] A[4,4] A[0,4] A[1,4]  (y=4 group)
  ;;   A[2,0] A[3,0] A[4,0] A[0,0] A[1,0]  (y=0 group)
  ;;   A[2,1] A[3,1] A[4,1] A[0,1] A[1,1]  (y=1 group)
  ;;
  ;; Matrix access must follow the indexing convention where (0,0) is the centre of the 5 * 5 matrix
  ;;
  ;; fn rho(theta_out: [i64; 25]) {
  ;;   for theta_idx in 0..24 {
  ;;     rho_result[theta_idx] = ROTR(theta_out[theta_idx], $RHOTATION_TABLE[$theta_idx % 5])
  ;;   }
  ;; }
  ;;
  ;; For the purposes of runtime efficiency, this loop has been unrolled and the rotation amounts have been hard coded
  ;; according to the values found in the $RHOTATION_TABLE.  This saves the need to perform modulo operations inside a
  ;; loop, as well as avoiding the need to perform 25 separate loads from the rotation table.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $rho (export "rho")
    ;; y=2 group: A[2,2]=43, A[3,2]=25, A[4,2]=39, A[0,2]=3, A[1,2]=10
    (i64.store (memory $main) offset=96
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=96  (global.get $THETA_RESULT_PTR)) (i64.const 43))
    )
    (i64.store (memory $main) offset=104
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=104 (global.get $THETA_RESULT_PTR)) (i64.const 25))
    )
    (i64.store (memory $main) offset=112
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=112 (global.get $THETA_RESULT_PTR)) (i64.const 39))
    )
    (i64.store (memory $main) offset=80
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=80  (global.get $THETA_RESULT_PTR)) (i64.const  3))
    )
    (i64.store (memory $main) offset=88
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=88  (global.get $THETA_RESULT_PTR)) (i64.const 10))
    )

    ;; y=3 group: A[2,3]=15, A[3,3]=21, A[4,3]=8, A[0,3]=41, A[1,3]=45
    (i64.store (memory $main) offset=136
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=136 (global.get $THETA_RESULT_PTR)) (i64.const 15))
    )
    (i64.store (memory $main) offset=144
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=144 (global.get $THETA_RESULT_PTR)) (i64.const 21))
    )
    (i64.store (memory $main) offset=152
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=152 (global.get $THETA_RESULT_PTR)) (i64.const  8))
    )
    (i64.store (memory $main) offset=120
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=120 (global.get $THETA_RESULT_PTR)) (i64.const 41))
    )
    (i64.store (memory $main) offset=128
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=128 (global.get $THETA_RESULT_PTR)) (i64.const 45))
    )

    ;; y=4 group: A[2,4]=61, A[3,4]=56, A[4,4]=14, A[0,4]=18, A[1,4]=2
    (i64.store (memory $main) offset=176
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=176 (global.get $THETA_RESULT_PTR)) (i64.const 61))
    )
    (i64.store (memory $main) offset=184
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=184 (global.get $THETA_RESULT_PTR)) (i64.const 56))
    )
    (i64.store (memory $main) offset=192
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=192 (global.get $THETA_RESULT_PTR)) (i64.const 14))
    )
    (i64.store (memory $main) offset=160
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=160 (global.get $THETA_RESULT_PTR)) (i64.const 18))
    )
    (i64.store (memory $main) offset=168
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=168 (global.get $THETA_RESULT_PTR)) (i64.const  2))
    )

    ;; y=0 group: A[2,0]=62, A[3,0]=28, A[4,0]=27, A[0,0]=0, A[1,0]=1
    (i64.store (memory $main) offset=16
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=16  (global.get $THETA_RESULT_PTR)) (i64.const 62))
    )
    (i64.store (memory $main) offset=24
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=24  (global.get $THETA_RESULT_PTR)) (i64.const 28))
    )
    (i64.store (memory $main) offset=32
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=32  (global.get $THETA_RESULT_PTR)) (i64.const 27))
    )
    (i64.store (memory $main) offset=0
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=0   (global.get $THETA_RESULT_PTR)) (i64.const  0))
    )
    (i64.store (memory $main) offset=8
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=8   (global.get $THETA_RESULT_PTR)) (i64.const  1))
    )

    ;; y=1 group: A[2,1]=6, A[3,1]=55, A[4,1]=20, A[0,1]=36, A[1,1]=44
    (i64.store (memory $main) offset=56
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=56  (global.get $THETA_RESULT_PTR)) (i64.const  6))
    )
    (i64.store (memory $main) offset=64
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=64  (global.get $THETA_RESULT_PTR)) (i64.const 55))
    )
    (i64.store (memory $main) offset=72
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=72  (global.get $THETA_RESULT_PTR)) (i64.const 20))
    )
    (i64.store (memory $main) offset=40
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=40  (global.get $THETA_RESULT_PTR)) (i64.const 36))
    )
    (i64.store (memory $main) offset=48
      (global.get $RHO_RESULT_PTR)
      (i64.rotl (i64.load (memory $main) offset=48  (global.get $THETA_RESULT_PTR)) (i64.const 44))
    )

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
  ;; For the purposes of runtime efficiency, this loop has been unrolled. The final transformation can simply be
  ;; hardcoded since the algorithm results in a static reordering of the i64s.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $pi (export "pi")
    ;; FIPS 202 §3.2.3: A'[x,y] = A[(x+3y) mod 5, x]  offset(x,y) = y*40 + x*8
    ;; A'[0,0] <- A[0,0]
    (i64.store (memory $main) offset=0
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=0   (global.get $RHO_RESULT_PTR))
    )
    ;; A'[1,0] <- A[1,1]
    (i64.store (memory $main) offset=8
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=48  (global.get $RHO_RESULT_PTR))
    )
    ;; A'[2,0] <- A[2,2]
    (i64.store (memory $main) offset=16
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=96  (global.get $RHO_RESULT_PTR))
    )
    ;; A'[3,0] <- A[3,3]
    (i64.store (memory $main) offset=24
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=144 (global.get $RHO_RESULT_PTR))
    )
    ;; A'[4,0] <- A[4,4]
    (i64.store (memory $main) offset=32
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=192 (global.get $RHO_RESULT_PTR))
    )
    ;; A'[0,1] <- A[3,0]
    (i64.store (memory $main) offset=40
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=24  (global.get $RHO_RESULT_PTR))
    )
    ;; A'[1,1] <- A[4,1]
    (i64.store (memory $main) offset=48
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=72  (global.get $RHO_RESULT_PTR))
    )
    ;; A'[2,1] <- A[0,2]
    (i64.store (memory $main) offset=56
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=80  (global.get $RHO_RESULT_PTR))
    )
    ;; A'[3,1] <- A[1,3]
    (i64.store (memory $main) offset=64
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=128 (global.get $RHO_RESULT_PTR))
    )
    ;; A'[4,1] <- A[2,4]
    (i64.store (memory $main) offset=72
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=176 (global.get $RHO_RESULT_PTR))
    )
    ;; A'[0,2] <- A[1,0]
    (i64.store (memory $main) offset=80
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=8   (global.get $RHO_RESULT_PTR))
    )
    ;; A'[1,2] <- A[2,1]
    (i64.store (memory $main) offset=88
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=56  (global.get $RHO_RESULT_PTR))
    )
    ;; A'[2,2] <- A[3,2]
    (i64.store (memory $main) offset=96
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=104 (global.get $RHO_RESULT_PTR))
    )
    ;; A'[3,2] <- A[4,3]
    (i64.store (memory $main) offset=104
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=152 (global.get $RHO_RESULT_PTR))
    )
    ;; A'[4,2] <- A[0,4]
    (i64.store (memory $main) offset=112
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=160 (global.get $RHO_RESULT_PTR))
    )
    ;; A'[0,3] <- A[4,0]
    (i64.store (memory $main) offset=120
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=32  (global.get $RHO_RESULT_PTR))
    )
    ;; A'[1,3] <- A[0,1]
    (i64.store (memory $main) offset=128
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=40  (global.get $RHO_RESULT_PTR))
    )
    ;; A'[2,3] <- A[1,2]
    (i64.store (memory $main) offset=136
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=88  (global.get $RHO_RESULT_PTR))
    )
    ;; A'[3,3] <- A[2,3]
    (i64.store (memory $main) offset=144
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=136 (global.get $RHO_RESULT_PTR))
    )
    ;; A'[4,3] <- A[3,4]
    (i64.store (memory $main) offset=152
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=184 (global.get $RHO_RESULT_PTR))
    )
    ;; A'[0,4] <- A[2,0]
    (i64.store (memory $main) offset=160
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=16  (global.get $RHO_RESULT_PTR))
    )
    ;; A'[1,4] <- A[3,1]
    (i64.store (memory $main) offset=168
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=64  (global.get $RHO_RESULT_PTR))
    )
    ;; A'[2,4] <- A[4,2]
    (i64.store (memory $main) offset=176
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=112 (global.get $RHO_RESULT_PTR))
    )
    ;; A'[3,4] <- A[0,3]
    (i64.store (memory $main) offset=184
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=120 (global.get $RHO_RESULT_PTR))
    )
    ;; A'[4,4] <- A[1,4]
    (i64.store (memory $main) offset=192
      (global.get $PI_RESULT_PTR)
      (i64.load (memory $main) offset=168 (global.get $RHO_RESULT_PTR))
    )

  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; For each column in the state matrix, reorder the row entries according to the following transformation.
  ;; Matrix access must follow the indexing convention where (0,0) is the centre of the 5 * 5 matrix
  ;;
  ;; fn chi(pi_out: [i64; 25]) {
  ;;   for y in 0..4 {
  ;;     for x in 0..4 {
  ;;       let w0 = pi_out[y][x]
  ;;       let w1 = pi_out[y][(x + 1) % 5]
  ;;       let w2 = pi_out[y][(x + 2) % 5]
  ;;
  ;;       chi_out[y][x] = w0 XOR (NOT(w1) AND w2)
  ;;     }
  ;;   }
  ;; }
  ;;
  ;; FIPS 202 §3.2.4: A'[x,y] = A[x,y] XOR (NOT(A[x+1,y]) AND A[x+2,y])
  ;;
  ;; For the purposes of runtime efficiency, this loop has been unrolled as the algorithm simply performs a static
  ;; mapping
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $chi (export "chi")
    ;; y=2 group: A[2,2], A[3,2], A[4,2], A[0,2], A[1,2]  — offsets: 96, 104, 112, 80, 88
    (i64.store (memory $main) offset=96
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=96  (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=104 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=112 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=104
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=104 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=112 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=80  (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=112
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=112 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=80  (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=88  (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=80
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=80  (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=88  (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=96  (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=88
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=88  (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=96  (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=104 (global.get $PI_RESULT_PTR))
        )
      )
    )

    ;; y=3 group: A[2,3], A[3,3], A[4,3], A[0,3], A[1,3]  — offsets: 136, 144, 152, 120, 128
    (i64.store (memory $main) offset=136
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=136 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=144 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=152 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=144
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=144 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=152 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=120 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=152
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=152 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=120 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=128 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=120
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=120 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=128 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=136 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=128
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=128 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=136 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=144 (global.get $PI_RESULT_PTR))
        )
      )
    )

    ;; y=4 group: A[2,4], A[3,4], A[4,4], A[0,4], A[1,4]  — offsets: 176, 184, 192, 160, 168
    (i64.store (memory $main) offset=176
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=176 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=184 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=192 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=184
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=184 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=192 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=160 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=192
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=192 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=160 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=168 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=160
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=160 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=168 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=176 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=168
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=168 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=176 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=184 (global.get $PI_RESULT_PTR))
        )
      )
    )

    ;; y=0 group: A[2,0], A[3,0], A[4,0], A[0,0], A[1,0]  — offsets: 16, 24, 32, 0, 8
    (i64.store (memory $main) offset=16
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=16(global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=24 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=32 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=24
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=24(global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=32 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=0  (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=32
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=32(global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=0  (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=8  (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=0
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=0 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=8  (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=16 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=8
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=8 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=16 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=24 (global.get $PI_RESULT_PTR))
        )
      )
    )

    ;; y=1 group: A[2,1], A[3,1], A[4,1], A[0,1], A[1,1] — offsets: 56, 64, 72, 40, 48
    (i64.store (memory $main) offset=56
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=56 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=64 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=72 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=64
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=64 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=72 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=40 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=72
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=72 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=40 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=48 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=40
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=40 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=48 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=56 (global.get $PI_RESULT_PTR))
        )
      )
    )
    (i64.store (memory $main) offset=48
      (global.get $CHI_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=48 (global.get $PI_RESULT_PTR))
        (i64.and
          (i64.xor
            (i64.load (memory $main) offset=56 (global.get $PI_RESULT_PTR))
            (i64.const -1)
          )
          (i64.load (memory $main) offset=64 (global.get $PI_RESULT_PTR))
        )
      )
    )

  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; XOR in place the i64 at $CHI_RESULT_PTR with the supplied round constant.
  ;; FIPS 202 §3.2.5: A'[0,0] = A[0,0] XOR RC[round]
  ;; A[0,0] lives at offset 0 of CHI_RESULT_PTR; round constants are stored little-endian.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $iota (export "iota")
        (param $round i32)

    (local $w0           i64)
    (local $rnd_const    i64)
    (local $xor_result   i64)
    (local.set $rnd_const
      (i64.load
        (memory $main)
        (i32.add
          (global.get $KECCAK_ROUND_CONSTANTS_PTR)
          (i32.shl (local.get $round) (i32.const 3)) ;; Convert the round number to an i64 offset
        )
      )
    )
    (local.set $w0 (i64.load (memory $main) (global.get $CHI_RESULT_PTR)))
    (local.set $xor_result (i64.xor (local.get $rnd_const) (local.get $w0)))
    (i64.store
      (memory $main)
      (global.get $CHI_RESULT_PTR)
      (local.get $xor_result)
    )

  )

)
