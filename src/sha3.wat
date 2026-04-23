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
  ;; Function types
  (type $type_i32*1          (func (param i32)))
  (type $type_i32*2          (func (param i32 i32)))
  (type $type_i32*3          (func (param i32 i32 i32)))
  (type $type_i32*4          (func (param i32 i32 i32 i32)))
  (type $type_i32*5          (func (param i32 i32 i32 i32 i32)))
  (type $type_i32*3_i64      (func (param i32 i32 i32 i64)))
  (type $type_wasi_path_open (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (type $type_wasi_fd_seek   (func (param i32 i64 i32 i32)                     (result i32)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Import WASI preview 2 OS system calls
  (import "wasi_snapshot_preview2" "args_sizes_get" (func $wasi.args_sizes_get (type $type_i32*2)))
  (import "wasi_snapshot_preview2" "args_get"       (func $wasi.args_get       (type $type_i32*2)))
  (import "wasi_snapshot_preview2" "path_open"      (func $wasi.path_open      (type $type_wasi_path_open)))
  (import "wasi_snapshot_preview2" "fd_seek"        (func $wasi.fd_seek        (type $type_wasi_fd_seek)))
  (import "wasi_snapshot_preview2" "fd_read"        (func $wasi.fd_read        (type $type_i32*4)))
  (import "wasi_snapshot_preview2" "fd_write"       (func $wasi.fd_write       (type $type_i32*4)))
  (import "wasi_snapshot_preview2" "fd_close"       (func $wasi.fd_close       (type $type_i32*1)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;;@debug-start
  (import "debug" "memory"  (memory $debug 16))
  (import "debug" "hexdump" (func $debug.hexdump (type $type_i32*3)))

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
  ;;@debug-end

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
  ;; 0x000001F4     200   i64x25  Ping-pong BUF_1 — theta output / pi output                   (THETA_RESULT_PTR = PI_RESULT_PTR)
  ;; 0x000002BC      40   i64x5   Theta C function output
  ;; 0x000002E4      40   i64x5   Theta D function output
  ;; 0x0000030C     100   i32x25  State index table
  ;; 0x00000370      25   i8x25   Theta XOR D offset table
  ;; 0x00000389       3           Padding (32-bit alignment)
  ;; 0x0000038C     200   i64x25  Entropy pool (fixed at 200 bytes, subdivided into rate and capacity)
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; File IO
  ;; 0x000004E4       4   i32     file_fd
  ;; 0x000004EC       8   i64     fd_seek file size
  ;; 0x000004F4       8   i32x2   Pointer to read iovec buffer address + size
  ;; 0x000004FC       8   i32x2   Pointer to write iovec buffer address + size
  ;; 0x00000504       8   i64     Bytes transferred by the last io operation
  ;; 0x00000514       8   i64     File size (little endian)
  ;; 0x00000524       8   i64     File size (big endian)
  ;; 0x00000534       4   i32     Pointer to file path name
  ;; 0x00000538       4   i32     Pointer to file path length
  ;; 0x0000053C       4   i32     Number of command line arguments
  ;; 0x00000540       4   i32     Command line buffer size
  ;; 0x00000544       4   i32     Pointer to array of argument pointers (needs double dereferencing)
  ;; Unused
  ;; 0x000005E4     256   data    Command line args buffer
  ;; Unused
  ;; 0x00000A44      64   data    ASCII representation of SHA value
  ;; Unused
  ;; 0x00000AE4       2   data    Two ASCII spaces
  ;; 0x00000AE7       5   data    Error message prefix "Err: "
  ;; 0x00000AEC      43           Error message "Bad args. Expected sha256|sha224 <filename>"
  ;; 0x00000B1C      25           Error message "No such file or directory"
  ;; 0x00000B3C      24           Error message "Unable to read file size"
  ;; 0x00000B54      21           Error message "File too large (>4Gb)"
  ;; 0x00000B74      18           Error message "Error reading file"
  ;; 0x00000B94      48           Error message "Neither a directory nor a symlink to a directory"
  ;; 0x00000BC4      19           Error message "Bad file descriptor"
  ;; 0x00000BE4      26           Error message "Memory allocation failed: "
  ;; 0x00000C04      23           Error message "Operation not permitted"
  ;; 0x00000C24      25           Error message "Filename too long (>=256)"
  ;; Debug messages — stripped from production build by ;;@debug-start/;;@debug-end markers
  ;; 0x00000C44       6           "argc: "
  ;; 0x00000C54      14           "argv_buf_len: "
  ;; 0x00000C64       6           "Step: "
  ;; 0x00000C6C      13           "Return code: "
  ;; 0x00000C84      15           "msg_blk_count: "
  ;; 0x00000C94      19           "File size (bytes): "
  ;; 0x00000CB4      28           "Bytes read by wasi.fd_read: "
  ;; 0x00000CD4      20           "wasi.fd_read count: "
  ;; 0x00000CF4      18           "Copy to new addr: "
  ;; 0x00000D14      18           "Copy length     : "
  ;; 0x00000D34      30           "Allocated extra memory pages: "
  ;; 0x00000D64      27           "No memory allocation needed"
  ;; 0x00000D84      32           "Current memory page allocation: "
  ;; 0x00000DA4      25           "wasi.fd_read chunk size: "
  ;; 0x00000DC4      22           "Processing full buffer"
  ;; 0x00000DE4      19           "Hit EOF (Partial): "
  ;; 0x00000E14      16           "Hit EOF (Zero): "
  ;; 0x00000E24      22           "Building empty msg blk"
  ;; 0x00000E44      18           "File size (bits): "
  ;; 0x00000E64      17           "Distance to EOB: "
  ;; 0x00000E84      12           "EOD offset: "
  ;; 0x00000E94       9           "SHA arg: "
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

  ;; The rotation amounts used by the Rho function (hence "rhotation" table) are derived from the word length w which in
  ;; turn is derived from the length l (where w = 2^l)
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
  ;; Values are stored in STATE_IDX_TAB traversal order so that the rho loop can pair each entry directly with the
  ;; corresponding cell offset from STATE_IDX_TAB without any secondary lookup.
  ;; Traversal order: A[2,2] A[3,2] A[4,2] A[0,2] A[1,2]  (y=2 group)
  ;;                  A[2,3] A[3,3] A[4,3] A[0,3] A[1,3]  (y=3 group)
  ;;                  A[2,4] A[3,4] A[4,4] A[0,4] A[1,4]  (y=4 group)
  ;;                  A[2,0] A[3,0] A[4,0] A[0,0] A[1,0]  (y=0 group)
  ;;                  A[2,1] A[3,1] A[4,1] A[0,1] A[1,1]  (y=1 group)
  (global $RHOTATION_TABLE i32 (i32.const 0x000000C8))
  (data (memory $main) (i32.const 0x000000C8)
    (; 43;) "\2B\00\00\00"  (; 25;) "\19\00\00\00" (; 39;) "\27\00\00\00" (;  3;) "\03\00\00\00" (; 10;) "\0A\00\00\00"
    (; 15;) "\0F\00\00\00"  (; 21;) "\15\00\00\00" (;  8;) "\08\00\00\00" (; 41;) "\29\00\00\00" (; 45;) "\2D\00\00\00"
    (; 61;) "\3D\00\00\00"  (; 56;) "\38\00\00\00" (; 14;) "\0E\00\00\00" (; 18;) "\12\00\00\00" (;  2;) "\02\00\00\00"
    (; 62;) "\3E\00\00\00"  (; 28;) "\1C\00\00\00" (; 27;) "\1B\00\00\00" (;  0;) "\00\00\00\00" (;  1;) "\01\00\00\00"
    (;  6;) "\06\00\00\00"  (; 55;) "\37\00\00\00" (; 20;) "\14\00\00\00" (; 36;) "\24\00\00\00" (; 44;) "\2C\00\00\00"
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

  ;; The n'th i32 in this table holds the byte offset into the state at which the n'th i64 in the incoming data lives
  (global $STATE_IDX_TAB i32 (i32.const 0x0000030C))  ;; 25 * i32 = 100 bytes
  (data (memory $main) (i32.const 0x0000030C)
    (; 96;) "\60\00\00\00" (;104;) "\68\00\00\00" (;112;) "\70\00\00\00" (; 80;) "\50\00\00\00" (; 88;) "\58\00\00\00"
    (;136;) "\88\00\00\00" (;144;) "\90\00\00\00" (;152;) "\98\00\00\00" (;120;) "\78\00\00\00" (;128;) "\80\00\00\00"
    (;176;) "\B0\00\00\00" (;184;) "\B8\00\00\00" (;192;) "\C0\00\00\00" (;160;) "\A0\00\00\00" (;168;) "\A8\00\00\00"
    (; 16;) "\10\00\00\00" (; 24;) "\18\00\00\00" (; 32;) "\20\00\00\00" (;  0;) "\00\00\00\00" (;  8;) "\08\00\00\00"
    (; 56;) "\38\00\00\00" (; 64;) "\40\00\00\00" (; 72;) "\48\00\00\00" (; 40;) "\28\00\00\00" (; 48;) "\30\00\00\00"
  )

  ;; For each of the 25 a_blk_idx values (0-24), the byte offset into THETA_D_OUT_PTR for D[x].
  ;; x = (a_blk_idx % 5 + 2) % 5 maps to D-offsets [16,24,32,0,8] repeating across all 5 rows.
  (global $THETA_XOR_D_OFFSET_TAB i32 (i32.const 0x00000370))  ;; 25 bytes
  (data (memory $main) (i32.const 0x00000370)  ;; D[2]  D[3]  D[4]  D[0]  D[1]
    "\10\18\20\00\08"  ;; a_blk_idx  0- 4
    "\10\18\20\00\08"  ;; a_blk_idx  5- 9
    "\10\18\20\00\08"  ;; a_blk_idx 10-14
    "\10\18\20\00\08"  ;; a_blk_idx 15-19
    "\10\18\20\00\08"  ;; a_blk_idx 20-24
  )
  ;; 3 bytes padding at 0x389-0x38B for 32-bit alignment of STATE_PTR

  (global $STATE_PTR    (export "STATE_PTR")    i32 (i32.const 0x0000038C))  ;; 200 bytes
  (global $DATA_PTR     (export "DATA_PTR")     i32 (i32.const 0x00000454))  ;; length = rate bytes (varies with digest size)

  ;; Default digest size = 256 bits, so in 64-bit words, rate = 17 and capacity = 8
  (global $RATE         (export "RATE")         (mut i32) (i32.const 17))
  (global $CAPACITY     (export "CAPACITY")     (mut i32) (i32.const 8))
  (global $RATE_PTR     (export "RATE_PTR")          i32  (i32.const 0x0000038C))
  (global $CAPACITY_PTR (export "CAPACITY_PTR") (mut i32) (i32.const 0x0000038C))  ;; set at runtime: STATE_PTR + RATE*8

  (global $FD_FILE_PTR         i32 (i32.const 0x000004E4))
  (global $FILE_SIZE_PTR       i32 (i32.const 0x000004EC))
  (global $IOVEC_READ_BUF_PTR  i32 (i32.const 0x000004F4))
  (global $IOVEC_WRITE_BUF_PTR i32 (i32.const 0x000004FC))
  (global $NREAD_PTR           i32 (i32.const 0x00000504))
  (global $FILE_SIZE_LE_PTR    i32 (i32.const 0x00000514))
  (global $FILE_SIZE_BE_PTR    i32 (i32.const 0x00000524))
  (global $FILE_PATH_PTR       i32 (i32.const 0x00000534))
  (global $FILE_PATH_LEN_PTR   i32 (i32.const 0x00000538))
  (global $ARGS_COUNT_PTR      i32 (i32.const 0x0000053C))
  (global $ARGV_BUF_LEN_PTR    i32 (i32.const 0x00000540))
  (global $ARGV_PTRS_PTR       i32 (i32.const 0x00000544))

  (global $ARGV_BUF_PTR        i32 (i32.const 0x000005E4))
  (global $ASCII_HASH_PTR      i32 (i32.const 0x00000A44))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Error messages
  (global $ASCII_SPACES        i32 (i32.const 0x00000AE4))  ;; Length = 2
  (data (memory $main) (i32.const 0x00000AE4) "  ")

  (global $ERR_MSG_PREFIX      i32 (i32.const 0x00000AE7))  ;; Length = 5
  (data (memory $main) (i32.const 0x00000AE7) "Err: ")

  (global $ERR_MSG_BAD_ARGS    i32 (i32.const 0x00000AEC))  ;; Length = 43
  (data (memory $main) (i32.const 0x00000AEC) "Bad args. Expected sha256|sha224 <filename>")

  (global $ERR_MSG_NOENT       i32 (i32.const 0x00000B1C))  ;; Length = 25
  (data (memory $main) (i32.const 0x00000B1C) "No such file or directory")

  (global $ERR_FILE_SIZE_READ  i32 (i32.const 0x00000B3C))  ;; Length = 24
  (data (memory $main) (i32.const 0x00000B3C) "Unable to read file size")

  (global $ERR_FILE_TOO_LARGE  i32 (i32.const 0x00000B54))  ;; Length = 21
  (data (memory $main) (i32.const 0x00000B54) "File too large (>4Gb)")

  (global $ERR_READING_FILE    i32 (i32.const 0x00000B74))  ;; Length = 18
  (data (memory $main) (i32.const 0x00000B74) "Error reading file")

  (global $ERR_NOT_DIR_SYMLINK i32 (i32.const 0x00000B94))  ;; Length = 48
  (data (memory $main) (i32.const 0x00000B94) "Neither a directory nor a symlink to a directory")

  (global $ERR_BAD_FD          i32 (i32.const 0x00000BC4))  ;; Length = 19
  (data (memory $main) (i32.const 0x00000BC4) "Bad file descriptor")

  (global $ERR_MEM_ALLOC       i32 (i32.const 0x00000BE4))  ;; Length = 26
  (data (memory $main) (i32.const 0x00000BE4) "Memory allocation failed: ")

  (global $ERR_NOT_PERMITTED   i32 (i32.const 0x00000C04))  ;; Length = 23
  (data (memory $main) (i32.const 0x00000C04) "Operation not permitted")

  (global $ERR_ARGV_TOO_LONG   i32 (i32.const 0x00000C24))  ;; Length = 25
  (data (memory $main) (i32.const 0x00000C24) "Filename too long (>=256)")

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Debug messages
  ;;@debug-start
  (global $DBG_MSG_ARGC        i32 (i32.const 0x00000C44))  ;; Length = 6
  (data (memory $main) (i32.const 0x00000C44) "argc: ")

  (global $DBG_MSG_ARGV_LEN    i32 (i32.const 0x00000C54))  ;; Length = 14
  (data (memory $main) (i32.const 0x00000C54) "argv_buf_len: ")

  (global $DBG_STEP            i32 (i32.const 0x00000C64))  ;; Length = 6
  (data (memory $main) (i32.const 0x00000C64) "Step: ")

  (global $DBG_RETURN_CODE     i32 (i32.const 0x00000C6C))  ;; Length = 13
  (data (memory $main) (i32.const 0x00000C6C) "Return code: ")

  (global $DBG_MSG_BLK_COUNT   i32 (i32.const 0x00000C84))  ;; Length = 15
  (data (memory $main) (i32.const 0x00000C84) "msg_blk_count: ")

  (global $DBG_FILE_SIZE       i32 (i32.const 0x00000C94))  ;; Length = 19
  (data (memory $main) (i32.const 0x00000C94) "File size (bytes): ")

  (global $DBG_BYTES_READ      i32 (i32.const 0x00000CB4))  ;; Length = 28
  (data (memory $main) (i32.const 0x00000CB4) "Bytes read by wasi.fd_read: ")

  (global $DBG_READ_COUNT      i32 (i32.const 0x00000CD4))  ;; Length = 20
  (data (memory $main) (i32.const 0x00000CD4) "wasi.fd_read count: ")

  (global $DBG_COPY_MEM_TO     i32 (i32.const 0x00000CF4))  ;; Length = 18
  (data (memory $main) (i32.const 0x00000CF4) "Copy to new addr: ")

  (global $DBG_COPY_MEM_LEN    i32 (i32.const 0x00000D14))  ;; Length = 18
  (data (memory $main) (i32.const 0x00000D14) "Copy length     : ")

  (global $DBG_MEM_GROWN       i32 (i32.const 0x00000D34))  ;; Length = 30
  (data (memory $main) (i32.const 0x00000D34) "Allocated extra memory pages: ")

  (global $DBG_NO_MEM_ALLOC    i32 (i32.const 0x00000D64))  ;; Length = 27
  (data (memory $main) (i32.const 0x00000D64) "No memory allocation needed")

  (global $DBG_MEM_SIZE        i32 (i32.const 0x00000D84))  ;; Length = 32
  (data (memory $main) (i32.const 0x00000D84) "Current memory page allocation: ")

  (global $DBG_CHUNK_SIZE      i32 (i32.const 0x00000DA4))  ;; Length = 25
  (data (memory $main) (i32.const 0x00000DA4) "wasi.fd_read chunk size: ")

  (global $DBG_FULL_BUFFER     i32 (i32.const 0x00000DC4))  ;; Length = 22
  (data (memory $main) (i32.const 0x00000DC4) "Processing full buffer")

  (global $DBG_EOF_PARTIAL     i32 (i32.const 0x00000DE4))  ;; Length = 19
  (data (memory $main) (i32.const 0x00000DE4) "Hit EOF (Partial): ")

  (global $DBG_EOF_ZERO        i32 (i32.const 0x00000E14))  ;; Length = 16
  (data (memory $main) (i32.const 0x00000E14) "Hit EOF (Zero): ")

  (global $DBG_EMPTY_MSG_BLK   i32 (i32.const 0x00000E24))  ;; Length = 22
  (data (memory $main) (i32.const 0x00000E24) "Building empty msg blk")

  (global $DBG_FILE_SIZE_BITS  i32 (i32.const 0x00000E44))  ;; Length = 18
  (data (memory $main) (i32.const 0x00000E44) "File size (bits): ")

  (global $DBG_EOB_DISTANCE    i32 (i32.const 0x00000E64))  ;; Length = 17
  (data (memory $main) (i32.const 0x00000E64) "Distance to EOB: ")

  (global $DBG_EOD_OFFSET      i32 (i32.const 0x00000E84))  ;; Length = 12
  (data (memory $main) (i32.const 0x00000E84) "EOD offset: ")

  (global $DBG_SHA_ARG         i32 (i32.const 0x00000E94))  ;; Length = 9
  (data (memory $main) (i32.const 0x00000E94) "SHA arg: ")
  ;;@debug-end

  (global $STR_WRITE_BUF_PTR   i32 (i32.const 0x00001DE4))

  ;; $main Memory Map: Pages 2-33
  (global $READ_BUFFER_PTR     i32 (i32.const 0x00010000))  ;; Start of memory page 2
  (global $READ_BUFFER_SIZE    i32 (i32.const 0x00200000))  ;; fd_read buffer size = 2Mb

  ;; If you change the value of $READ_BUFFER_SIZE, you must manually update $MSG_BLKS_PER_BUFFER!
  (global $MSG_BLKS_PER_BUFFER i32 (i32.const 0x00008000))  ;; $READ_BUFFER_SIZE / 64

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "_start"))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "get_command_line_args")
        (result i32)
    (call $wasi.args_sizes_get (global.get $ARGS_COUNT_PTR) (global.get $ARGV_BUF_LEN_PTR))
    ;; drop  ;; This is always 0, so ignore it

    (i32.load (global.get $ARGS_COUNT_PTR))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $prepare_state
        (export "prepare_state")
        (param $init_mem      i32) ;; Initialise state memory?
        (param $copy_to_a_blk i32) ;; Copy state to Theta A block?
        (param $digest_len    i32) ;; Defaults to 256

    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id        (i32.const 10))

    (call $log.fnEnter   (local.get $debug_active) (local.get $fn_id))
    (call $log.singleDec (local.get $debug_active) (local.get $fn_id) (i32.const 2) (local.get $digest_len))
    ;;@debug-end

    ;; If $digest_len is not one of 224, 256, 384 or 512, then default to 256
    (block $digest_ok
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 224)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 256)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 384)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 512)))

      (local.set $digest_len (i32.const 256))
      ;;@debug-start
      (call $log.label (local.get $debug_active) (i32.const 14))
      ;;@debug-end
    )

    ;; Initialise the internal state?
    (if (local.get $init_mem)
      (then
        (memory.fill (memory $main) (global.get $STATE_PTR) (i32.const 0) (i32.const 200))
        ;;@debug-start
        (call $log.label (local.get $debug_active) (i32.const 15))
        ;;@debug-end
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

    ;;@debug-start
    (call $log.singleDec (local.get $debug_active) (local.get $fn_id) (i32.const 0) (global.get $RATE))
    (call $log.singleDec (local.get $debug_active) (local.get $fn_id) (i32.const 1) (global.get $CAPACITY))
    ;;@debug-end

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

    ;;@debug-start
    (call $log.fnExit (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
)

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; In place XOR the data at $RATE_PTR with the data at $DATA_PTR
  ;; Data is absorbed in FIPS 202 lane order: A[0,0], A[1,0], ..., A[4,0], A[0,1], ...
  ;; i.e. sequential byte offsets 0, 8, 16, ... from RATE_PTR (FIPS 202 §3.1.2)
  (func $xor_data_with_rate
        (param $rate_words i32)

    (local $data_idx     i32)
    (local $rate_ptr     i32)
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id        (i32.const 11))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end

    (loop $xor_loop
      ;; FIPS 202 §3.1.2: lane(x,y) is at byte offset (5y+x)*8; absorb sequentially from lane(0,0)
      (local.set $rate_ptr
        (i32.add (global.get $RATE_PTR) (i32.shl (local.get $data_idx) (i32.const 3)))
      )

      ;;@debug-start
      (call $log.mappedPair
        (local.get $debug_active)
        (local.get $fn_id)
        (i32.const 0)
        (local.get $data_idx)
        (local.get $rate_ptr)
      )
      ;;@debug-end

      (i64.store
        (memory $main)
        (local.get $rate_ptr)
        (i64.xor
          (i64.load (memory $main) (local.get $rate_ptr))
          (i64.load (memory $main) (i32.add (global.get $DATA_PTR) (i32.shl (local.get $data_idx) (i32.const 3))))
        )
      )

      (local.set $data_idx (i32.add (local.get $data_idx) (i32.const 1)))

      (br_if $xor_loop
        (local.tee $rate_words (i32.sub (local.get $rate_words) (i32.const 1)))
      )
    )

    ;;@debug-start
    (if (local.get $debug_active)
      (then
        (memory.copy
          (memory $debug)                 ;; Copy to memory
          (memory $main)                  ;; Copy from memory
          (global.get $DEBUG_IO_BUFF_PTR) ;; Copy to address
          (global.get $STATE_PTR)         ;; Copy from address
          (i32.const 200)                 ;; Length
        )
        (call $log.label (local.get $debug_active) (i32.const 3))
        (call $debug.hexdump (global.get $FD_STDOUT) (global.get $DEBUG_IO_BUFF_PTR) (i32.const 200))
      )
    )

    (call $log.fnExit (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
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
  ;; Run the absorb and squeeze phases of the sponge function
  (func (export "sponge")
        (param $digest_len i32)
        (param $n          i32)

    (local $round        i32)
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 13))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
    (call $prepare_state (i32.const 1) (i32.const 1) (local.get $digest_len))

    ;; CHI_RESULT_PTR = THETA_A_BLK_PTR (ping-pong BUF_0), so each round's output lands
    ;; directly where the next round's theta reads it — no inter-round copy needed.
    (loop $next_round
      (call $keccak (local.get $round))
      (local.set $round (i32.add (local.get $round) (i32.const 1)))
      (br_if $next_round
        (local.tee $n (i32.sub (local.get $n) (i32.const 1)))
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

    ;;@debug-start
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
    (call $log.fnExit (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
)

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Perform a single round of the Keccak function
  ;; The output lives at $CHI_RESULT_PTR because the the last step function (iota) performs an in-place modification
  (func $keccak (export "keccak")
        (param $round i32)

    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 9))

    (call $log.fnEnterNth (local.get $debug_active) (local.get $fn_id) (local.get $round))

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
    ;;@debug-end

    (call $theta)
    (call $rho)
    (call $pi)
    (call $chi)
    (call $iota (local.get $round))

    ;;@debug-start
    (call $log.fnExitNth (local.get $debug_active) (local.get $fn_id) (local.get $round))
    ;;@debug-end
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Theta function
  ;;
  ;; Reads 200 bytes starting at $THETA_A_BLK_PTR
  ;; Writes 200 bytes to $THETA_RESULT_PTR
  (func $theta (export "theta")
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 15))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end

    (call $theta_c_all)
    (call $theta_d)
    (call $theta_xor_loop)

    ;;@debug-start
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
    (call $log.fnExit (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
)

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Production entry point for Theta C — passes n=5 as a compile-time constant
  ;; wasm-opt constant propagation will fold n=5 into $theta_c and DCE all four br_if guards
  (func $theta_c_all
    (call $theta_c (i32.const 5))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; n-column Theta C function - used for testing
  ;;
  ;; The parameter $n is only needed to test a single round of $theta_c_inner.
  ;; In normal operation, this parameter is hard-coded to 5
  (func $theta_c (export "theta_c")
        (param $n i32)

    (local $result       i64)
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))

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

    (local.set $fn_id (i32.const 1))
    ;;@debug-end

    (block $call_count
      ;; C[x=0]: XOR A[0,0..4] — column base offset 0
      (local.set $result (call $theta_c_inner (global.get $THETA_A_BLK_PTR)))
      ;;@debug-start
      (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 0) (local.get $result))
      ;;@debug-end
      (i64.store (memory $main) (global.get $THETA_C_OUT_PTR) (local.get $result))
      (br_if $call_count (i32.eq (local.get $n) (i32.const 1)))

      ;; C[x=1]: XOR A[1,0..4] — column base offset 8
      (local.set $result (call $theta_c_inner (i32.add (global.get $THETA_A_BLK_PTR) (i32.const 8))))
      ;;@debug-start
      (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 1) (local.get $result))
      ;;@debug-end
      (i64.store (memory $main) offset=8 (global.get $THETA_C_OUT_PTR) (local.get $result))
      (br_if $call_count (i32.eq (local.get $n) (i32.const 2)))

      ;; C[x=2]: XOR A[2,0..4] — column base offset 16
      (local.set $result (call $theta_c_inner (i32.add (global.get $THETA_A_BLK_PTR) (i32.const 16))))
      ;;@debug-start
      (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 2) (local.get $result))
      ;;@debug-end
      (i64.store (memory $main) offset=16 (global.get $THETA_C_OUT_PTR) (local.get $result))
      (br_if $call_count (i32.eq (local.get $n) (i32.const 3)))

      ;; C[x=3]: XOR A[3,0..4] — column base offset 24
      (local.set $result (call $theta_c_inner (i32.add (global.get $THETA_A_BLK_PTR) (i32.const 24))))
      ;;@debug-start
      (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 3) (local.get $result))
      ;;@debug-end
      (i64.store (memory $main) offset=24 (global.get $THETA_C_OUT_PTR) (local.get $result))
      (br_if $call_count (i32.eq (local.get $n) (i32.const 4)))

      ;; C[x=4]: XOR A[4,0..4] — column base offset 32
      (local.set $result (call $theta_c_inner (i32.add (global.get $THETA_A_BLK_PTR) (i32.const 32))))
      ;;@debug-start
      (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 4) (local.get $result))
      ;;@debug-end
      (i64.store (memory $main) offset=32 (global.get $THETA_C_OUT_PTR) (local.get $result))
    )

    ;;@debug-start
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
    ;;@debug-end
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
            (i64.load (memory $main) offset=0   (local.get $data_ptr)) ;; y=0
            (i64.load (memory $main) offset=40  (local.get $data_ptr)) ;; y=1
          )
          (i64.load (memory $main) offset=80  (local.get $data_ptr))   ;; y=2
        )
        (i64.load (memory $main) offset=120 (local.get $data_ptr))     ;; y=3
      )
      (i64.load (memory $main) offset=160 (local.get $data_ptr))       ;; y=4
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
  (func $theta_d (export "theta_d")
    (local $w0           i32)
    (local $w1           i32)
    (local $w2           i32)
    (local $w3           i32)
    (local $w4           i32)
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 2))

    (call $log.fnEnter (local.get $debug_active) (i32.const 2))
    ;;@debug-end

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

    ;;@debug-start
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

    (call $log.fnExit (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Inner functionality of Theta D function -> $w0 XOR ROTL($w1, 1)
  ;; FIPS 202 §3.2.1: D[x] = C[x-1] XOR ROT(C[x+1], 1), where ROT(W,1)_z = W_(z-1 mod 64) = rotl(W, 1)
  (func $theta_d_inner
        (param $w0_ptr i32)
        (param $w1_ptr i32)
        (result i64)

    (local $w0           i64)
    (local $w1           i64)
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 3))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end

    (local.set $w0 (i64.load (memory $main) (local.get $w0_ptr)))
    (local.set $w1 (i64.load (memory $main) (local.get $w1_ptr)))

    ;; w0 XOR rotl(w1, 1) = w0 XOR ((w1 << 1) | (w1 >> 63))
    (i64.xor
      (local.get $w0)
      (i64.or
        (i64.shl   (local.get $w1) (i64.const 1))
        (i64.shr_u (local.get $w1) (i64.const 63))
      )
    )

    ;;@debug-start
    (call $log.fnExit (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; For each of the 5 i64 words at $THETA_D_OUT_PTR, XOR that word with the 5 successive i64s starting at
  ;; $THETA_A_BLK_PTR.  The output is written to $THETA_RESULT_PTR
  ;;
  ;; fn theta_xor_loop(d_fn_out: [i64; 5], a_blk: mut [i64; 25]) {
  ;;   for a_blk_idx in 0..24 {
  ;;     ;; STATE_IDX_TAB groups by y; within each group x follows [2,3,4,0,1]
  ;;     ;; so x = (a_blk_idx % 5 + 2) % 5
  ;;     a_blk[a_blk_idx] = d_fn_out[(a_blk_idx % 5 + 2) % 5] XOR a_blk[a_blk_idx]
  ;;   }
  ;; }
  ;;
  ;; Matrix access must follow the indexing convention where (0,0) is the centre of the 5 * 5 matrix
  (func $theta_xor_loop (export "theta_xor_loop")
    (local $a_blk_idx    i32)
    (local $a_blk_offset i32)
    (local $a_blk_ptr    i32)
    (local $a_blk_word   i64)
    (local $d_fn_word    i64)
    (local $xor_result   i64)
    (local $result_ptr   i32)
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 4))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))

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
    ;;@debug-end

    (loop $xor_loop
      (local.set $d_fn_word
        (i64.load
          (memory $main)
          (i32.add
            (global.get $THETA_D_OUT_PTR)
            ;; D[x] byte offset looked up directly from THETA_XOR_D_OFFSET_TAB[a_blk_idx]
            (i32.load8_u
              (memory $main)
              (i32.add (global.get $THETA_XOR_D_OFFSET_TAB) (local.get $a_blk_idx))
            )
          )
        )
      )

      ;; The offset of the n'th A block word is picked up from the state index table.
      ;; This offset is then added to $THETA_A_BLK_PTR to pick up the correct word
      ;;
      ;; $a_blk_offset = $STATE_IDX_TAB + ($a_blk_idx * 4)
      ;; $a_blk_ptr = $THETA_A_BLK_PTR + $a_blk_offset
      ;;@debug-start
      (call $log.singleDec (local.get $debug_active) (local.get $fn_id) (i32.const 2) (local.get $a_blk_idx))
      ;;@debug-end

      (local.set $a_blk_offset
        (i32.load
          (memory $main)
          (i32.add (global.get $STATE_IDX_TAB) (i32.shl (local.get $a_blk_idx) (i32.const 2)))
        )
      )
      ;;@debug-start
      (call $log.singleDec (local.get $debug_active) (local.get $fn_id) (i32.const 3) (local.get $a_blk_offset))
      ;;@debug-end

      ;; The offset of the input word and the result word should be the same
      (local.set $result_ptr (i32.add (global.get $THETA_RESULT_PTR) (local.get $a_blk_offset)))
      (local.set $a_blk_ptr  (i32.add (global.get $THETA_A_BLK_PTR)  (local.get $a_blk_offset)))
      (local.set $a_blk_word (i64.load (memory $main) (local.get $a_blk_ptr)))
      (local.set $xor_result (i64.xor (local.get $d_fn_word) (local.get $a_blk_word)))

      ;;@debug-start
      (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 0) (local.get $d_fn_word))
      (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 1) (local.get $a_blk_word))
      (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 4) (local.get $xor_result))
      ;;@debug-end

      (i64.store (memory $main) (local.get $result_ptr) (local.get $xor_result))

      (local.set $a_blk_idx (i32.add (local.get $a_blk_idx) (i32.const 1)))

      ;; Quit once all 5 words in the D block have been XOR'ed with successive words in the A block
      (br_if $xor_loop (i32.lt_u (local.get $a_blk_idx) (i32.const 25)))
    )

    ;;@debug-start
    (call $log.fnExit (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
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
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 5))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end

    (local.set $rot_ptr (global.get $RHOTATION_TABLE))

    (loop $rho_loop
      (local.set $rot_amt (i64.extend_i32_u (i32.load (memory $main) (local.get $rot_ptr))))
      ;;@debug-start
      (call $log.singleBigInt (local.get $debug_active) (local.get $fn_id) (i32.const 2) (local.get $rot_amt))
      ;;@debug-end

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

      ;; FIPS 202 §3.2.2: A'[x,y,z] = A[x,y,(z-r) mod 64] = rotl(A[x,y], r)
      (local.set $w0
        (i64.rotl
          (i64.load (memory $main) (local.get $theta_ptr))
          (local.get $rot_amt)
        )
      )
      ;;@debug-start
      (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 1) (local.get $w0))
      ;;@debug-end

      (i64.store (memory $main) (local.get $result_ptr) (local.get $w0))
      (local.set $rot_ptr (i32.add (local.get $rot_ptr) (i32.const 4)))

      ;; Quit once all 25 words in the theta result block have been rotated
      (br_if $rho_loop
        (i32.lt_u
          (local.tee $theta_idx (i32.add (local.get $theta_idx) (i32.const 1)))
          (i32.const 25)
        )
      )
    )

    ;;@debug-start
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

    (call $log.fnExit (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
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
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 6))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end

    ;; FIPS 202 §3.2.3: A'[x,y] = A[(x+3y) mod 5, x]  offset(x,y) = y*40 + x*8
    (i64.store (memory $main) offset=0   (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=0   (global.get $RHO_RESULT_PTR))) ;; A'[0,0] <- A[0,0]
    (i64.store (memory $main) offset=8   (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=48  (global.get $RHO_RESULT_PTR))) ;; A'[1,0] <- A[1,1]
    (i64.store (memory $main) offset=16  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=96  (global.get $RHO_RESULT_PTR))) ;; A'[2,0] <- A[2,2]
    (i64.store (memory $main) offset=24  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=144 (global.get $RHO_RESULT_PTR))) ;; A'[3,0] <- A[3,3]
    (i64.store (memory $main) offset=32  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=192 (global.get $RHO_RESULT_PTR))) ;; A'[4,0] <- A[4,4]
    (i64.store (memory $main) offset=40  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=24  (global.get $RHO_RESULT_PTR))) ;; A'[0,1] <- A[3,0]
    (i64.store (memory $main) offset=48  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=72  (global.get $RHO_RESULT_PTR))) ;; A'[1,1] <- A[4,1]
    (i64.store (memory $main) offset=56  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=80  (global.get $RHO_RESULT_PTR))) ;; A'[2,1] <- A[0,2]
    (i64.store (memory $main) offset=64  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=128 (global.get $RHO_RESULT_PTR))) ;; A'[3,1] <- A[1,3]
    (i64.store (memory $main) offset=72  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=176 (global.get $RHO_RESULT_PTR))) ;; A'[4,1] <- A[2,4]
    (i64.store (memory $main) offset=80  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=8   (global.get $RHO_RESULT_PTR))) ;; A'[0,2] <- A[1,0]
    (i64.store (memory $main) offset=88  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=56  (global.get $RHO_RESULT_PTR))) ;; A'[1,2] <- A[2,1]
    (i64.store (memory $main) offset=96  (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=104 (global.get $RHO_RESULT_PTR))) ;; A'[2,2] <- A[3,2]
    (i64.store (memory $main) offset=104 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=152 (global.get $RHO_RESULT_PTR))) ;; A'[3,2] <- A[4,3]
    (i64.store (memory $main) offset=112 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=160 (global.get $RHO_RESULT_PTR))) ;; A'[4,2] <- A[0,4]
    (i64.store (memory $main) offset=120 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=32  (global.get $RHO_RESULT_PTR))) ;; A'[0,3] <- A[4,0]
    (i64.store (memory $main) offset=128 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=40  (global.get $RHO_RESULT_PTR))) ;; A'[1,3] <- A[0,1]
    (i64.store (memory $main) offset=136 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=88  (global.get $RHO_RESULT_PTR))) ;; A'[2,3] <- A[1,2]
    (i64.store (memory $main) offset=144 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=136 (global.get $RHO_RESULT_PTR))) ;; A'[3,3] <- A[2,3]
    (i64.store (memory $main) offset=152 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=184 (global.get $RHO_RESULT_PTR))) ;; A'[4,3] <- A[3,4]
    (i64.store (memory $main) offset=160 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=16  (global.get $RHO_RESULT_PTR))) ;; A'[0,4] <- A[2,0]
    (i64.store (memory $main) offset=168 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=64  (global.get $RHO_RESULT_PTR))) ;; A'[1,4] <- A[3,1]
    (i64.store (memory $main) offset=176 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=112 (global.get $RHO_RESULT_PTR))) ;; A'[2,4] <- A[4,2]
    (i64.store (memory $main) offset=184 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=120 (global.get $RHO_RESULT_PTR))) ;; A'[3,4] <- A[0,3]
    (i64.store (memory $main) offset=192 (global.get $PI_RESULT_PTR) (i64.load (memory $main) offset=168 (global.get $RHO_RESULT_PTR))) ;; A'[4,4] <- A[1,4]

    ;;@debug-start
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
    (call $log.fnExit (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
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
  ;; FIPS 202 §3.2.4: A'[x,y] = A[x,y] XOR (NOT(A[x+1,y]) AND A[x+2,y])
  ;;
  ;; This algorithm however simply performs a static mapping, so the transformation can be hardcoded rather than calculated
  (func $chi (export "chi")
    (local $col           i32)
    (local $row           i32)
    (local $col+1         i32)
    (local $col+2         i32)
    (local $result_ptr    i32)
    (local $result_offset i32)
    (local $w0            i64)
    (local $w1            i64)
    (local $w2            i64)
    (local $chi_result    i64)
    ;;@debug-start
    (local $debug_active  i32)
    (local $fn_id         i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 7))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))

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
    ;;@debug-end

    (loop $row_loop
      ;; Reset $col counter
      (local.set $col (i32.const 0))

      (loop $col_loop
        ;; Calculate the next two column indices (mod 5) for the x-axis neighbourhood
        (local.set $col+1 (i32.rem_u (i32.add (local.get $col) (i32.const 1)) (i32.const 5)))
        (local.set $col+2 (i32.rem_u (i32.add (local.get $col) (i32.const 2)) (i32.const 5)))

        ;;@debug-start
        (call $log.coords (local.get $debug_active) (local.get $fn_id) (i32.const 0) (local.get $col)   (local.get $row))
        (call $log.coords (local.get $debug_active) (local.get $fn_id) (i32.const 1) (local.get $col+1) (local.get $row))
        (call $log.coords (local.get $debug_active) (local.get $fn_id) (i32.const 2) (local.get $col+2) (local.get $row))
        ;;@debug-end

        (local.set $result_offset (call $xy_to_state_offset (local.get $row) (local.get $col)))
        (local.set $result_ptr (i32.add (global.get $CHI_RESULT_PTR) (local.get $result_offset)))

        (local.set $w0
          (i64.load
            (memory $main)
            (i32.add (global.get $PI_RESULT_PTR) (local.get $result_offset))
          )
        )
        (local.set $w1
          (i64.load
            (memory $main)
            (i32.add (global.get $PI_RESULT_PTR) (call $xy_to_state_offset (local.get $row) (local.get $col+1)))
          )
        )
        (local.set $w2
          (i64.load
            (memory $main)
            (i32.add (global.get $PI_RESULT_PTR) (call $xy_to_state_offset (local.get $row) (local.get $col+2)))
          )
        )

        ;;@debug-start
        (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 3) (local.get $w0))
        (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 4) (local.get $w1))
        (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 5) (local.get $w2))
        ;;@debug-end

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
        ;;@debug-start
        (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 6) (local.get $chi_result))
        ;;@debug-end

        (i64.store (memory $main) (local.get $result_ptr) (local.get $chi_result))

        (br_if $col_loop
          (i32.lt_u
            (local.tee $col (i32.add (local.get $col) (i32.const 1)))
            (i32.const 5)
          )
        )
      )

      (br_if $row_loop
        (i32.lt_u
          (local.tee $row (i32.add (local.get $row) (i32.const 1)))
          (i32.const 5)
        )
      )
    )

    ;; Dump state after transformation
    ;;@debug-start
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
    (call $log.fnExit (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; XOR in place the i64 at $CHI_RESULT_PTR with the supplied round constant.
  ;; FIPS 202 §3.2.5: A'[0,0] = A[0,0] XOR RC[round]
  ;; A[0,0] lives at offset 0 of CHI_RESULT_PTR; round constants are stored little-endian.
  (func $iota (export "iota")
        (param $round i32)

    (local $w0           i64)
    (local $rnd_const    i64)
    (local $xor_result   i64)
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 8))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))
    (call $log.singleDec (local.get $debug_active) (local.get $fn_id) (i32.const 0) (local.get $round))

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
    ;;@debug-end

    (local.set $rnd_const
      (i64.load
        (memory $main)
        (i32.add
          (global.get $KECCAK_ROUND_CONSTANTS_PTR)
          (i32.shl (local.get $round) (i32.const 3)) ;; Convert the round number to an i64 offset
        )
      )
    )
    ;;@debug-start
    (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 1) (local.get $rnd_const))
    ;;@debug-end

    (local.set $w0 (i64.load (memory $main) (global.get $CHI_RESULT_PTR)))
    ;;@debug-start
    (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 2) (local.get $w0))
    ;;@debug-end

    (local.set $xor_result (i64.xor (local.get $rnd_const) (local.get $w0)))
    ;;@debug-start
    (call $log.singleI64 (local.get $debug_active) (local.get $fn_id) (i32.const 3) (local.get $xor_result))
    ;;@debug-end

    (i64.store
      (memory $main)
      (global.get $CHI_RESULT_PTR)
      (local.get $xor_result)
    )

    ;;@debug-start
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
    (call $log.fnExit (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end
  )
)
