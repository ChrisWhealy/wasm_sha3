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

  ;;@debug-start
  ;; Build with "npm build:dev" to include debug messages.
  ;; $DEBUG_ACTIVE must also be set to 1 in order for step function trace statements to become visible
  (global $DEBUG_ACTIVE       i32 (i32.const 0))
  ;;@debug-end

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
  ;; 0x0000038C     200   i64x25  Entropy pool (fixed at 200 bytes, subdivided into rate and capacity)
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
  ;; STATE_PTR/RATE_PTR alias BUF_0: state lives permanently in the permutation working buffer
  (global $STATE_PTR    (export "STATE_PTR")    i32 (i32.const 0x0000012C))  ;; BUF_0 alias — 200 bytes
  (global $DATA_PTR     (export "DATA_PTR")     i32 (i32.const 0x00000454))  ;; length = rate bytes (varies with digest size)

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

  (global $DIGEST_LEN     (mut i32) (i32.const 256))  ;; Set by _start; default 256

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Error messages
  (global $ASCII_SPACES        i32 (i32.const 0x00000AE4))  ;; Length = 2
  (data (memory $main) (i32.const 0x00000AE4) "  ")

  (global $ERR_MSG_PREFIX      i32 (i32.const 0x00000AE7))  ;; Length = 5
  (data (memory $main) (i32.const 0x00000AE7) "Err: ")

  (global $ERR_MSG_BAD_ARGS    i32 (i32.const 0x00000AEC))  ;; Length = 63
  (data (memory $main) (i32.const 0x00000AEC) "Bad args. Expected one of 224, 256, 384, or 512 plus <filename>")

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

  ;;@debug-start
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Debug messages
  (global $DBG_MSG_ARGC        i32 (i32.const 0x00000C90))  ;; Length = 6
  (data (memory $main) (i32.const 0x00000C90) "argc: ")

  (global $DBG_MSG_ARGV_LEN    i32 (i32.const 0x00000CA0))  ;; Length = 14
  (data (memory $main) (i32.const 0x00000CA0) "argv_buf_len: ")

  (global $DBG_STEP            i32 (i32.const 0x00000CB0))  ;; Length = 6
  (data (memory $main) (i32.const 0x00000CB0) "Step: ")

  (global $DBG_RETURN_CODE     i32 (i32.const 0x00000CB8))  ;; Length = 13
  (data (memory $main) (i32.const 0x00000CB8) "Return code: ")

  (global $DBG_MSG_BLK_COUNT   i32 (i32.const 0x00000CD0))  ;; Length = 15
  (data (memory $main) (i32.const 0x00000CD0) "msg_blk_count: ")

  (global $DBG_FILE_SIZE       i32 (i32.const 0x00000CE0))  ;; Length = 19
  (data (memory $main) (i32.const 0x00000CE0) "File size (bytes): ")

  (global $DBG_BYTES_READ      i32 (i32.const 0x00000D00))  ;; Length = 28
  (data (memory $main) (i32.const 0x00000D00) "Bytes read by wasi.fd_read: ")

  (global $DBG_READ_COUNT      i32 (i32.const 0x00000D20))  ;; Length = 20
  (data (memory $main) (i32.const 0x00000D20) "wasi.fd_read count: ")

  (global $DBG_COPY_MEM_TO     i32 (i32.const 0x00000D40))  ;; Length = 18
  (data (memory $main) (i32.const 0x00000D40) "Copy to new addr: ")

  (global $DBG_COPY_MEM_LEN    i32 (i32.const 0x00000D60))  ;; Length = 18
  (data (memory $main) (i32.const 0x00000D60) "Copy length     : ")

  (global $DBG_MEM_GROWN       i32 (i32.const 0x00000D80))  ;; Length = 30
  (data (memory $main) (i32.const 0x00000D80) "Allocated extra memory pages: ")

  (global $DBG_NO_MEM_ALLOC    i32 (i32.const 0x00000DB0))  ;; Length = 27
  (data (memory $main) (i32.const 0x00000DB0) "No memory allocation needed")

  (global $DBG_MEM_SIZE        i32 (i32.const 0x00000DD0))  ;; Length = 32
  (data (memory $main) (i32.const 0x00000DD0) "Current memory page allocation: ")

  (global $DBG_CHUNK_SIZE      i32 (i32.const 0x00000DF0))  ;; Length = 25
  (data (memory $main) (i32.const 0x00000DF0) "wasi.fd_read chunk size: ")

  (global $DBG_FULL_BUFFER     i32 (i32.const 0x00000E10))  ;; Length = 22
  (data (memory $main) (i32.const 0x00000E10) "Processing full buffer")

  (global $DBG_EOF_PARTIAL     i32 (i32.const 0x00000E30))  ;; Length = 19
  (data (memory $main) (i32.const 0x00000E30) "Hit EOF (Partial): ")

  (global $DBG_EOF_ZERO        i32 (i32.const 0x00000E60))  ;; Length = 16
  (data (memory $main) (i32.const 0x00000E60) "Hit EOF (Zero): ")

  (global $DBG_EMPTY_MSG_BLK   i32 (i32.const 0x00000E70))  ;; Length = 22
  (data (memory $main) (i32.const 0x00000E70) "Building empty msg blk")

  (global $DBG_FILE_SIZE_BITS  i32 (i32.const 0x00000E90))  ;; Length = 18
  (data (memory $main) (i32.const 0x00000E90) "File size (bits): ")

  (global $DBG_EOB_DISTANCE    i32 (i32.const 0x00000EB0))  ;; Length = 17
  (data (memory $main) (i32.const 0x00000EB0) "Distance to EOB: ")

  (global $DBG_EOD_OFFSET      i32 (i32.const 0x00000ED0))  ;; Length = 12
  (data (memory $main) (i32.const 0x00000ED0) "EOD offset: ")

  (global $DBG_SHA_ARG         i32 (i32.const 0x00000EE0))  ;; Length = 9
  (data (memory $main) (i32.const 0x00000EE0) "SHA arg: ")
  ;;@debug-end

  (global $STR_WRITE_BUF_PTR   i32 (i32.const 0x00001DE4))

  ;; $main Memory Map: Pages 2-33
  (global $READ_BUFFER_PTR     i32 (i32.const 0x00010000))  ;; Start of memory page 2
  (global $READ_BUFFER_SIZE    i32 (i32.const 0x00200000))  ;; fd_read buffer size = 2Mb

  ;; If you change the value of $READ_BUFFER_SIZE, you must manually update $MSG_BLKS_PER_BUFFER!
  (global $MSG_BLKS_PER_BUFFER i32 (i32.const 0x00008000))  ;; $READ_BUFFER_SIZE / 64

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Entry point.  Called automatically by the WASI runtime.
  ;;
  ;; Expects two command line arguments:
  ;;   <digest-bits>  one of 224, 256, 384, or 512
  ;;   <file>         path to the file to hash
  ;;
  ;; Reads the file in 2 MB chunks, absorbs each rate-sized block into the Keccak state, applies SHA3
  ;; padding (FIPS 202 §B.2), squeezes the first digest_bytes bytes from the state, and writes the
  ;; result as "<hex>  <filename>\n" to stdout.
  (func (export "_start")
    (local $argc            i32)
    (local $argv_buf_len    i32)
    (local $hash_len_ptr    i32)
    (local $hash_len_val    i32)  ;; 4-byte LE load of the digest-bits argument
    (local $digest_len      i32)  ;; 224 | 256 | 384 | 512
    (local $digest_bytes    i32)  ;; digest_len / 8
    (local $rate_bytes      i32)  ;; RATE * 8
    (local $filename_ptr    i32)
    (local $filename_len    i32)
    (local $file_fd         i32)
    (local $return_code     i32)
    (local $bytes_read      i32)
    (local $src_ptr         i32)
    (local $partial_bytes   i32)  ;; bytes accumulated in DATA_PTR for the current partial block
    (local $fill_amount     i32)
    (local $byte_offset     i32)
    ;;@debug-start
    (local $step            i32)
    ;;@debug-end

    (block $exit
      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 0: Fetch argument count and total buffer size
      ;;@debug-start
      (local.set $step (i32.add (local.get $step) (i32.const 1)))
      ;;@debug-end
      (drop
        (call $wasi.args_sizes_get (global.get $ARGS_COUNT_PTR) (global.get $ARGV_BUF_LEN_PTR))
      )

      (local.set $argc         (i32.load (memory $main) (global.get $ARGS_COUNT_PTR)))
      (local.set $argv_buf_len (i32.load (memory $main) (global.get $ARGV_BUF_LEN_PTR)))

      ;; Avoid buffer overrun
      (if (i32.gt_u (local.get $argv_buf_len) (i32.const 256))
        (then
          ;;@debug-start
          (call $write_step (i32.const 1) (local.get $step) (i32.const 4))
          ;;@debug-end
          (call $writeln (i32.const 2) (global.get $ERR_ARGV_TOO_LONG) (i32.const 25))
          (br $exit)
        )
      )

      ;; Must be at least 2 arguments: digest-bits and filename
      (if (i32.lt_u (local.get $argc) (i32.const 2))
        (then
          ;;@debug-start
          (call $write_step (i32.const 1) (local.get $step) (i32.const 4))
          ;;@debug-end
          (call $writeln (i32.const 2) (global.get $ERR_MSG_BAD_ARGS) (i32.const 63))
          (br $exit)
        )
      )

      ;;@debug-start
      (call $write_step (i32.const 1) (local.get $step) (i32.const 0))
      ;;@debug-end

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 1: Parse and validate the digest-bits argument (second-to-last)
      ;;@debug-start
      (local.set $step (i32.add (local.get $step) (i32.const 1)))
      ;;@debug-end
      (drop
        (call $wasi.args_get (global.get $ARGV_PTRS_PTR) (global.get $ARGV_BUF_PTR))
      )

      ;;@debug-start
      (call $write_args)
      ;;@debug-end

      (drop ;; Don't care about the returned length
        (local.set $hash_len_ptr (call $fetch_arg_n (i32.sub (local.get $argc) (i32.const 1))))
      )

      ;; Load 4 bytes so the null terminator is included; compare as a little-endian i32
      (local.set $hash_len_val (i32.load (memory $main) (local.get $hash_len_ptr)))

      (block $algo_ok
        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00343232)) ;; ASCII "224\0"
          (then (local.set $digest_len (i32.const 224)) (br $algo_ok))
        )
        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00363532)) ;; ASCII "256\0"
          (then (local.set $digest_len (i32.const 256)) (br $algo_ok))
        )
        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00343833)) ;; ASCII "384\0"
          (then (local.set $digest_len (i32.const 384)) (br $algo_ok))
        )
        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00323135)) ;; ASCII "512\0"
          (then (local.set $digest_len (i32.const 512)) (br $algo_ok))
        )
        ;;@debug-start
        (call $write_step (i32.const 1) (local.get $step) (i32.const 4))
        ;;@debug-end
        (call $writeln (i32.const 2) (global.get $ERR_MSG_BAD_ARGS) (i32.const 63))
        (br $exit)
      )

      ;;@debug-start
      (call $write_step (i32.const 1) (local.get $step) (i32.const 0))
      ;;@debug-end

      (global.set $DIGEST_LEN  (local.get $digest_len))
      (local.set $digest_bytes (i32.shr_u (local.get $digest_len) (i32.const 3)))

      ;; rate_words = (1600 - digest_len * 2) / 64
      (global.set $RATE
        (i32.shr_u
          (i32.sub (i32.const 1600) (i32.shl (local.get $digest_len) (i32.const 1)))
          (i32.const 6)
        )
      )
      ;; rate_bytes = rate_words * 8
      (local.set $rate_bytes (i32.shl (global.get $RATE) (i32.const 3)))

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 2: Extract filename (last arg) and open the file
      ;;@debug-start
      (local.set $step (i32.add (local.get $step) (i32.const 1)))
      ;;@debug-end
      ;; fetch_arg_n leaves two values on the stack
      (local.set $filename_len
        (local.set $filename_ptr
          (call $fetch_arg_n (local.get $argc))
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

      (if
        (then
          ;;@debug-start
          (call $write_step (i32.const 1) (local.get $step) (local.get $return_code))
          ;;@debug-end
          (br $exit)
        )
      )

      ;;@debug-start
      (call $write_step (i32.const 1) (local.get $step) (i32.const 0))
      ;;@debug-end

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 3: Initialise Keccak state
      ;;@debug-start
      (local.set $step (i32.add (local.get $step) (i32.const 1)))
      ;;@debug-end
      (global.set $CAPACITY     (i32.sub (i32.const 25) (global.get $RATE)))
      (global.set $CAPACITY_PTR (i32.add (global.get $STATE_PTR) (i32.shl (global.get $RATE) (i32.const 3))))

      (memory.fill (memory $main) (global.get $STATE_PTR) (i32.const 0) (i32.const 200))

      ;;@debug-start
      (call $write_step (i32.const 1) (local.get $step) (i32.const 0))
      ;;@debug-end

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 4: Read file in 2 MB chunks and absorb into the sponge
      ;;@debug-start
      (local.set $step (i32.add (local.get $step) (i32.const 1)))
      ;;@debug-end
      (i32.store (memory $main) (global.get $IOVEC_READ_BUF_PTR) (global.get $READ_BUFFER_PTR))
      (i32.store (memory $main)
        (i32.add (global.get $IOVEC_READ_BUF_PTR) (i32.const 4))
        (global.get $READ_BUFFER_SIZE)
      )

      (block $eof
        (loop $read_chunk
          (local.tee $return_code
            (call $wasi.fd_read
              (local.get $file_fd)
              (global.get $IOVEC_READ_BUF_PTR)
              (i32.const 1)
              (global.get $NREAD_PTR)
            )
          )

          (if ;; $return_code > 0
            (then
              ;;@debug-start
              (call $write_step (i32.const 1) (local.get $step) (local.get $return_code))
              ;;@debug-end
              (call $writeln (i32.const 2) (global.get $ERR_READING_FILE) (i32.const 18))
              (br $exit)
            )
          )

          (if ;; fd_read returned 0 bytes, we're done
            (i32.eqz (local.tee $bytes_read (i32.load (memory $main) (global.get $NREAD_PTR))))
            (then
              (br $eof)
            )
          )

          (local.set $src_ptr (global.get $READ_BUFFER_PTR))

          ;; Complete any partial rate-block left over from the previous iteration
          (if (local.get $partial_bytes)
            (then
              (local.set $fill_amount (i32.sub (local.get $rate_bytes) (local.get $partial_bytes)))
              (if (i32.gt_u (local.get $fill_amount) (local.get $bytes_read))
                (then (local.set $fill_amount (local.get $bytes_read)))
              )
              (memory.copy (memory $main) (memory $main)
                (i32.add (global.get $DATA_PTR) (local.get $partial_bytes))
                (local.get $src_ptr)
                (local.get $fill_amount)
              )
              (local.set $partial_bytes (i32.add (local.get $partial_bytes) (local.get $fill_amount)))
              (local.set $src_ptr       (i32.add (local.get $src_ptr)       (local.get $fill_amount)))
              (local.set $bytes_read    (i32.sub (local.get $bytes_read)    (local.get $fill_amount)))

              (if (i32.eq (local.get $partial_bytes) (local.get $rate_bytes))
                (then
                  (call $xor_data_with_rate (global.get $RATE) (global.get $DATA_PTR))
                  (call $run_permutation)
                  (local.set $partial_bytes (i32.const 0))
                )
              )
            )
          )

          ;; Absorb complete rate-blocks directly from the read buffer
          (block $no_full_blocks
            (loop $full_blocks
              (br_if $no_full_blocks (i32.lt_u (local.get $bytes_read) (local.get $rate_bytes)))

              (call $xor_data_with_rate (global.get $RATE) (local.get $src_ptr))
              (call $run_permutation)

              (local.set $src_ptr    (i32.add (local.get $src_ptr)    (local.get $rate_bytes)))
              (local.set $bytes_read (i32.sub (local.get $bytes_read) (local.get $rate_bytes)))
              (br $full_blocks)
            )
          )

          ;; Save any leftover bytes into DATA_PTR for the next iteration
          (if (local.get $bytes_read)
            (then
              (memory.copy (memory $main) (memory $main)
                (global.get $DATA_PTR)
                (local.get $src_ptr)
                (local.get $bytes_read)
              )
              (local.set $partial_bytes (local.get $bytes_read))
            )
          )

          (br $read_chunk)
        )
      )

      ;;@debug-start
      (call $write_step (i32.const 1) (local.get $step) (i32.const 0))
      ;;@debug-end

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 5: Apply SHA3 padding — pad10*1 with domain byte 0x06 (FIPS 202 §B.2)
      ;;@debug-start
      (local.set $step (i32.add (local.get $step) (i32.const 1)))
      ;;@debug-end
      ;;
      ;; DATA_PTR[0..partial_bytes-1] already holds the final partial block.
      ;; Zero the remainder of the rate block, then:
      ;;   DATA_PTR[partial_bytes]       |= 0x06   (domain + start bit)
      ;;   DATA_PTR[rate_bytes - 1]      |= 0x80   (end bit)
      ;; When partial_bytes == rate_bytes-1 both writes target the same byte → 0x86
      (memory.fill (memory $main)
        (i32.add (global.get $DATA_PTR) (local.get $partial_bytes))
        (i32.const 0)
        (i32.sub (local.get $rate_bytes) (local.get $partial_bytes))
      )
      (i32.store8 (memory $main)
        (i32.add (global.get $DATA_PTR) (local.get $partial_bytes))
        (i32.const 0x06)
      )
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
      (call $run_permutation)

      ;;@debug-start
      (call $write_step (i32.const 1) (local.get $step) (i32.const 0))
      ;;@debug-end

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 6: Close the file
      ;;@debug-start
      (local.set $step (i32.add (local.get $step) (i32.const 1)))
      ;;@debug-end
      (local.set $return_code (call $wasi.fd_close (local.get $file_fd)))

      ;;@debug-start
      (call $write_step (i32.const 1) (local.get $step) (local.get $return_code))
      ;;@debug-end

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 7: Squeeze — convert the first digest_bytes bytes of state to hex ASCII
      ;;@debug-start
      (local.set $step (i32.add (local.get $step) (i32.const 1)))
      ;;@debug-end
      (loop $output_byte
        (call $to_asc_pair
          (i32.load8_u (memory $main) (i32.add (global.get $STATE_PTR) (local.get $byte_offset)))
          (i32.add (global.get $ASCII_HASH_PTR) (i32.shl (local.get $byte_offset) (i32.const 1)))
        )
        (br_if $output_byte
          (i32.lt_u
            (local.tee $byte_offset (i32.add (local.get $byte_offset) (i32.const 1)))
            (local.get $digest_bytes)
          )
        )
      )

      ;;@debug-start
      (call $write_step (i32.const 1) (local.get $step) (i32.const 0))
      ;;@debug-end

      ;; Write "<hex>  <filename>\n" to stdout
      (call $write
        (global.get $FD_STDOUT)
        (global.get $ASCII_HASH_PTR)
        (i32.shl (local.get $digest_bytes) (i32.const 1))
      )
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
  ;; Open the file at $path_offset/$path_len inside the preopened directory $fd_dir.
  ;;
  ;; Returns: (return_code: i32, file_fd: i32)
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
  (func $run_permutation
    (local $round i32)

    (loop $next_round
      (call $keccak (local.get $round))
      (br_if $next_round
        (i32.lt_u
          (local.tee $round (i32.add (local.get $round) (i32.const 1)))
          (i32.const 24)
        )
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $prepare_state
        (export "prepare_state")
        (param $init_mem   i32) ;; Initialise state memory?
        (param $digest_len i32) ;; Defaults to 256

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
    (call $xor_data_with_rate (global.get $RATE) (global.get $DATA_PTR))

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
        (param $src_ptr    i32)

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
          (i64.load (memory $main) (i32.add (local.get $src_ptr) (i32.shl (local.get $data_idx) (i32.const 3))))
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
  (func $theta_c
        (export "theta_c")
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
  ;;
  ;; For the purposes of runtime efficiency, this loop has been unrolled since the D-offset repeats the same pattern
  ;; across all 5 rows: [16,24,32,0,8] (D[2],D[3],D[4],D[0],D[1])
  (func $theta_xor_loop (export "theta_xor_loop")
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 4))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end

    ;; y=2 group: A[2,2], A[3,2], A[4,2], A[0,2], A[1,2]
    (i64.store (memory $main) offset=96
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=16 (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=96 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=104
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=24 (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=104(global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=112
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=32 (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=112(global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=80
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=0  (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=80 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=88
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=8  (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=88 (global.get $THETA_A_BLK_PTR))
      )
    )

    ;; y=3 group: A[2,3], A[3,3], A[4,3], A[0,3], A[1,3]
    (i64.store (memory $main) offset=136
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=16  (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=136 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=144
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=24  (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=144 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=152
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=32  (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=152 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=120
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=0   (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=120 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=128
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=8   (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=128 (global.get $THETA_A_BLK_PTR))
      )
    )

    ;; y=4 group: A[2,4], A[3,4], A[4,4], A[0,4], A[1,4]
    (i64.store (memory $main) offset=176
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=16  (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=176 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=184
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=24  (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=184 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=192
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=32  (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=192 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=160
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=0   (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=160 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=168
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=8   (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=168 (global.get $THETA_A_BLK_PTR))
      )
    )

    ;; y=0 group: A[2,0], A[3,0], A[4,0], A[0,0], A[1,0]
    (i64.store (memory $main) offset=16
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=16 (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=16 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=24
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=24 (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=24 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=32
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=32 (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=32 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=0
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=0 (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=0 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=8
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=8 (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=8 (global.get $THETA_A_BLK_PTR))
      )
    )

    ;; y=1 group: A[2,1], A[3,1], A[4,1], A[0,1], A[1,1]
    (i64.store (memory $main) offset=56
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=16 (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=56 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=64
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=24 (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=64 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=72
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=32 (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=72 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=40
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=0  (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=40 (global.get $THETA_A_BLK_PTR))
      )
    )
    (i64.store (memory $main) offset=48
      (global.get $THETA_RESULT_PTR)
      (i64.xor
        (i64.load (memory $main) offset=8  (global.get $THETA_D_OUT_PTR))
        (i64.load (memory $main) offset=48 (global.get $THETA_A_BLK_PTR))
      )
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
  ;; For the purposes of runtime efficiency, this loop has been unrolled and the rotation amounts have been hard coded
  ;; according to the values found in the $RHOTATION_TABLE.  This saves the need to perform modulo operations inside a
  ;; loop, as well as avoiding the need to perform 25 separate loads from the rotation table.
  (func $rho (export "rho")
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 5))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end

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
  ;; For the purposes of runtime efficiency, this loop has been unrolled. The final transformation can simply be
  ;; hardcoded since the algorithm results in a static reordering of the i64s.
  (func $pi (export "pi")
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 6))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))
    ;;@debug-end

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
  ;;
  ;; FIPS 202 §3.2.4: A'[x,y] = A[x,y] XOR (NOT(A[x+1,y]) AND A[x+2,y])
  ;;
  ;; For the purposes of runtime efficiency, this loop has been unrolled as the algorithm simply performs a static
  ;; mapping
  (func $chi (export "chi")
    ;;@debug-start
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 7))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))

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

  ;;@debug-start
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Run the absorb and squeeze phases of the sponge function
  ;; Used as a helper for testing a variable number of rounds of the Keccak
  (func (export "sponge")
        (param $digest_len i32)
        (param $n          i32)

    (local $round        i32)
    (local $debug_active i32)
    (local $fn_id        i32)

    (local.set $debug_active (i32.const 0))
    (local.set $fn_id (i32.const 13))

    (call $log.fnEnter (local.get $debug_active) (local.get $fn_id))
    (call $prepare_state (i32.const 1) (local.get $digest_len))

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
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; This function does nothing unless either $DEBUG_ACTIVE is true or we're writing to stderr
  ;; Write a debug/trace message to the specified fd
  ;; Returns: None
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $write_msg
        (param $fd      i32)  ;; Write to this file descriptor
        (param $msg_ptr i32)  ;; Pointer to error message text
        (param $msg_len i32)  ;; Length of error message

    (local $buf_ptr i32)

    (if
      (i32.or
        (global.get $DEBUG_ACTIVE)
        (i32.eq (local.get $fd) (i32.const 2))
      )
      (then
        (local.set $buf_ptr (global.get $STR_WRITE_BUF_PTR))

        ;; Write message text
        (memory.copy (memory $main) (memory $main) (local.get $buf_ptr) (local.get $msg_ptr) (local.get $msg_len))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (local.get $msg_len)))

        ;; Write LF
        (i32.store8 (memory $main) (local.get $buf_ptr) (i32.const 0x0A))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 1)))

        (call $write
          (local.get $fd)
          (global.get $STR_WRITE_BUF_PTR)
          (i32.sub (local.get $buf_ptr) (global.get $STR_WRITE_BUF_PTR)) ;; length = end address - start address
        )
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; This function does nothing unless either $DEBUG_ACTIVE is true or we're writing to stderr
  ;; Write a debug/trace message plus a value to the specified fd
  ;; Returns: None
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $write_msg_with_value
        (param $fd      i32)  ;; Write to this file descriptor
        (param $msg_ptr i32)  ;; Pointer to error message text
        (param $msg_len i32)  ;; Length of error message
        (param $msg_val i32)  ;; Some i32 value to be prefixed with "0x" then printed after the message text

    (local $buf_ptr i32)

    (if
      (i32.or
        (global.get $DEBUG_ACTIVE)
        (i32.eq (local.get $fd) (i32.const 2))
      )
      (then
        (local.set $buf_ptr (global.get $STR_WRITE_BUF_PTR))

        ;; Write message text
        (memory.copy (memory $main) (memory $main) (local.get $buf_ptr) (local.get $msg_ptr) (local.get $msg_len))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (local.get $msg_len)))

        ;; Write "0x"
        (i32.store16 (memory $main) (local.get $buf_ptr) (i32.const 0x7830)) ;; (little endian)
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))

        ;; Write i32 value as hex string
        (call $i32_to_hex_str (local.get $msg_val) (local.get $buf_ptr))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 8)))

        ;; Write LF
        (i32.store8 (memory $main) (local.get $buf_ptr) (i32.const 0x0A))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 1)))

        (call $write
          (local.get $fd)
          (global.get $STR_WRITE_BUF_PTR)
          (i32.sub (local.get $buf_ptr) (global.get $STR_WRITE_BUF_PTR)) ;; length = end address - start address
        )
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Write the return code of the current processing step to the specified fd
  ;; Returns: None
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $write_step
        (param $fd       i32)
        (param $step_no  i32)
        (param $ret_code i32)

    (local $buf_ptr i32)

    ;; Do nothing unless we are either writing to stderr or $DEBUG_ACTIVE is true
    (if
      (i32.or
        (global.get $DEBUG_ACTIVE)
        (i32.eq (local.get $fd) (i32.const 2))
      )
      (then
        (local.set $buf_ptr (global.get $STR_WRITE_BUF_PTR))

        ;; Write step text
        (memory.copy (memory $main) (memory $main) (local.get $buf_ptr) (global.get $DBG_STEP) (i32.const 6))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 6)))

        ;; Write "0x" prefix
        (i32.store16 (memory $main) (local.get $buf_ptr) (i32.const 0x7830)) ;; (little endian)
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))

        ;; Write step number as hex string
        (call $i32_to_hex_str (local.get $step_no) (local.get $buf_ptr))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 8)))

        ;; Write "  " padding
        (i32.store16 (memory $main) (local.get $buf_ptr) (i32.load16_u (memory $main) (global.get $ASCII_SPACES)))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))

        ;; Write return code text
        (memory.copy (memory $main) (memory $main) (local.get $buf_ptr) (global.get $DBG_RETURN_CODE) (i32.const 13))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 13)))

        ;; Write "0x" prefix
        (i32.store16 (memory $main) (local.get $buf_ptr) (i32.const 0x7830)) ;; (little endian)
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))

        ;; Write return code as hex string
        (call $i32_to_hex_str (local.get $ret_code) (local.get $buf_ptr))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 8)))

        ;; Write LF
        (i32.store8 (memory $main) (local.get $buf_ptr) (i32.const 0x0A))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 1)))

        (call $write
          (local.get $fd)
          (global.get $STR_WRITE_BUF_PTR)
          (i32.sub (local.get $buf_ptr) (global.get $STR_WRITE_BUF_PTR)) ;; length = end address - start address
        )
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Write argc and argv list to stdout
  ;; Returns: None
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $write_args
    (local $argc         i32)  ;; Argument count
    (local $argc_count   i32)  ;; Loop counter
    (local $argv_buf_len i32)  ;; Total length of argument string
    (local $arg_ptr      i32)  ;; Pointer to current cmd line argument
    (local $arg_len      i32)  ;; Length of current cmd line argument

    (local.set $argc         (i32.load (memory $main) (global.get $ARGS_COUNT_PTR)))
    (local.set $argv_buf_len (i32.load (memory $main) (global.get $ARGV_BUF_LEN_PTR)))

    (if (global.get $DEBUG_ACTIVE)
      (then
        ;; Write "argc: 0x" to output buffer followed by value of $argc
        (call $write_msg_with_value (i32.const 1) (global.get $DBG_MSG_ARGC) (i32.const 6) (local.get $argc))

        ;; Print "argv_buf_len: 0x" line followed by the value of argv_buf_len
        (call $write_msg_with_value (i32.const 1) (global.get $DBG_MSG_ARGV_LEN) (i32.const 14) (local.get $argv_buf_len))

        (local.set $argc_count (i32.const 1))

        ;; Write command lines args to output buffer
        (loop $arg_loop
          (local.set $arg_ptr (call $fetch_arg_n (local.get $argc_count)))
          (local.set $arg_len)

          (call $writeln (i32.const 1) (local.get $arg_ptr) (local.get $arg_len))

          ;; Repeat while argc_count <= argc
          (br_if $arg_loop
            (i32.le_u
              (local.tee $argc_count (i32.add (local.get $argc_count) (i32.const 1)))
              (local.get $argc)
            )
          )
        )
      )
    )
  )
  ;;@debug-end
)
