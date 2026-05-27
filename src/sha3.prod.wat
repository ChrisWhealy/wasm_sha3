;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
;; An implementation of the SHA3 algorithm based on NIST FIPS 202
;; https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
;;
;; The internal state is 1600 bits treated as a 5×5×64 matrix.  The state is split into a rate (r) and a capacity (c)
;; where r + c = 1600.  For SHA2 drop-in mode, the digest size d must be one of the SHA2 digest lengths and determines
;; the rate/capacity split: r = 1600 - 2d bits.
;;
;; Supported digest lengths and their rate/capacity partitions:
;;
;; +--------+--------------+--------------+
;; |        | Size in bits | Size in u64s |
;; | Digest +--------------|-------+------|
;; | Length |     r |    c |     r |    c |
;; +--------+-------+------+-------+------+
;; |    224 |  1152 |  448 |    18 |    7 |
;; |    256 |  1088 |  512 |    17 |    8 |
;; |    384 |   832 |  768 |    13 |   12 |
;; |    512 |   576 | 1024 |     9 |   16 |
;; +--------+-------+------+-------+------+
;;
;; In Extendible Output Function (XOF) mode (known as SHAKE128 or SHAKE256), the same state size is used but with
;; digest_len=128 or 256, giving rate=18 or 17 64-bit words respectively. The key difference here is that the output
;; length is unlimited and can be obtained by repeatedly performing the squeeze operation.
;;
;; The 5×5 state matrix is stored in the order described in FIPS 202 §3.1.2.  Lane (x,y) lives at byte offset
;; (5y + x) × 8 in linear memory.  The rate occupies the first r lanes (sequential byte order).
;;
;; This module follows the indexing convention described in FIPS 202 §3.1.2 of the above document
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
;;
;; V2 changes:
;;   - Although NIST FIPS 202 describes Rho and Pi as separate step functions, for the sake of runtime efficiency, they
;;     have been fused into a single rho_pi function.  This eliminates one full 200-byte buffer copy per Keccak round
;;     compared to executing the rho function followed by the pi function.
;;   - Chi now operates in-place on STATE.  Loading each row of 5 lanes into local variables before writing back avoids
;;     needing a second buffer.
;;   - Vestigial memory tables (rotation table, theta C/D scratch buffers, state index table, XOR-D offset table) have
;;     been removed, shrinking the static data footprint by just over 300 bytes.
;;   - Memory layout reorganised so all WASI i64 output targets are naturally 8-byte aligned.
;;   - All loops use test-to-continue rather than test-to-exit.  That is, the br_if at the end of the loop must succeed
;;     in order for the loop to repeat.  Failure causes the loop exit naturally.
;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

(module
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Function types
  (type $type_i32*1          (func (param i32)))
  (type $type_i32*2          (func (param i32 i32)))
  (type $type_i32*3          (func (param i32 i32 i32)))
  (type $type_i32*4          (func (param i32 i32 i32 i32)))
  (type $type_i32*3_i64      (func (param i32 i32 i32 i64)))
  (type $type_wasi_fd_close  (func (param i32)                                 (result i32)))
  (type $type_wasi_args      (func (param i32 i32)                             (result i32)))
  (type $type_wasi_path_open (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (type $type_wasi_fd_io     (func (param i32 i32 i32 i32)                     (result i32)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; WASI preview 1 imports
  (import "wasi_snapshot_preview1" "args_sizes_get" (func $wasi.args_sizes_get (type $type_wasi_args)))
  (import "wasi_snapshot_preview1" "args_get"       (func $wasi.args_get       (type $type_wasi_args)))
  (import "wasi_snapshot_preview1" "path_open"      (func $wasi.path_open      (type $type_wasi_path_open)))
  (import "wasi_snapshot_preview1" "fd_read"        (func $wasi.fd_read        (type $type_wasi_fd_io)))
  (import "wasi_snapshot_preview1" "fd_write"       (func $wasi.fd_write       (type $type_wasi_fd_io)))
  (import "wasi_snapshot_preview1" "fd_close"       (func $wasi.fd_close       (type $type_wasi_fd_close)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Page 1: algorithm state and IO metadata
  ;; Pages 2-33: 2 MB file read buffer
  (memory $main (export "memory") 33)

  (global $FD_STDOUT i32 (i32.const 1))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; $main Memory Map: Page 1
  ;;
  ;;     Offset  Length  Type    Description
  ;; 0x00000000     192  i64x24  ROUND_CONSTANTS: 24 Keccak round constants (RC[0]..RC[23])
  ;; 0x000000C0     200  i64x25  STATE (BUF_0): Keccak state — theta input, rho_pi output, chi/iota target
  ;; 0x00000188     200  i64x25  WORK  (BUF_1): theta output, rho_pi input
  ;; 0x00000250     168  bytes   PAD: rate-block staging buffer (max 168 bytes for SHAKE128)
  ;;
  ;; IO section — all WASI i64 output targets must be 8-byte aligned
  ;; 0x00000300       4  i32     file_fd
  ;; 0x00000304       4          (alignment padding)
  ;; 0x00000308       8  i64     nread — WASI fd_read byte-count output (8-byte aligned)
  ;; 0x00000310       8  i32×2   read_iovec  [ptr(4) | len(4)]
  ;; 0x00000318       8  i32×2   write_iovec [ptr(4) | len(4)]
  ;; 0x00000320       4  i32     argc
  ;; 0x00000324       4  i32     argv_buf_len
  ;; 0x00000328      64  i32×16  argv pointer array (supports up to 16 arguments)
  ;; 0x00000368     256  bytes   argv string buffer
  ;; 0x00000468     128  bytes   ascii_hash: hex-encoded digest (512 bits → 128 hex chars)
  ;; 0x000004E8      16  bytes   nybble_table: "0123456789abcdef"
  ;; 0x000004F8       2  bytes   ascii_spaces: "  "
  ;; 0x00000500     128  bytes   str_write_buf: scratch buffer for assembling output strings
  ;; 0x00000580      65  bytes   err_bad_args
  ;; 0x000005C4      25  bytes   err_noent
  ;; 0x000005E0      18  bytes   err_reading_file
  ;; 0x000005F8      48  bytes   err_not_dir_symlink
  ;; 0x00000630      19  bytes   err_bad_fd
  ;; 0x00000648      17  bytes   err_access
  ;; 0x00000660      23  bytes   err_not_permitted
  ;; 0x00000678      25  bytes   err_filename_too_long
  ;; 0x00000698      21  bytes   err_gen_io
  ;; 0x000006B0       5  bytes   err_prefix ("Err: ")
  ;; 0x000006B8      49  bytes   err_shake_bytes
  ;;
  ;; $main Memory Map: Pages 2-33
  ;; 0x00010000  0x200000  READ_BUFFER: 2 MB file read staging area
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  (global $ROUND_CONSTANTS_PTR i32 (i32.const 0x00000000))
  (data (memory $main) (i32.const 0x00000000)
    "\01\00\00\00\00\00\00\00" (; RC[ 0] ;) "\82\80\00\00\00\00\00\00" (; RC[ 1] ;)
    "\8a\80\00\00\00\00\00\80" (; RC[ 2] ;) "\00\80\00\80\00\00\00\80" (; RC[ 3] ;)
    "\8b\80\00\00\00\00\00\00" (; RC[ 4] ;) "\01\00\00\80\00\00\00\00" (; RC[ 5] ;)
    "\81\80\00\80\00\00\00\80" (; RC[ 6] ;) "\09\80\00\00\00\00\00\80" (; RC[ 7] ;)
    "\8a\00\00\00\00\00\00\00" (; RC[ 8] ;) "\88\00\00\00\00\00\00\00" (; RC[ 9] ;)
    "\09\80\00\80\00\00\00\00" (; RC[10] ;) "\0a\00\00\80\00\00\00\00" (; RC[11] ;)
    "\8b\80\00\80\00\00\00\00" (; RC[12] ;) "\8b\00\00\00\00\00\00\80" (; RC[13] ;)
    "\89\80\00\00\00\00\00\80" (; RC[14] ;) "\03\80\00\00\00\00\00\80" (; RC[15] ;)
    "\02\80\00\00\00\00\00\80" (; RC[16] ;) "\80\00\00\00\00\00\00\80" (; RC[17] ;)
    "\0a\80\00\00\00\00\00\00" (; RC[18] ;) "\0a\00\00\80\00\00\00\80" (; RC[19] ;)
    "\81\80\00\80\00\00\00\80" (; RC[20] ;) "\80\80\00\00\00\00\00\80" (; RC[21] ;)
    "\01\00\00\80\00\00\00\00" (; RC[22] ;) "\08\80\00\80\00\00\00\80" (; RC[23] ;)
  )

  ;; Keccak state buffers
  (global $STATE_PTR (export "STATE_PTR") i32 (i32.const 0x000000C0))  ;; BUF_0: 200 bytes
  (global $WORK_PTR  (export "WORK_PTR")  i32 (i32.const 0x00000188))  ;; BUF_1: 200 bytes

  ;; Aliases used by the JS test harness for backward-compatible export names
  (global $RATE_PTR          (export "RATE_PTR")          i32 (i32.const 0x000000C0))
  (global $THETA_RESULT_PTR  (export "THETA_RESULT_PTR")  i32 (i32.const 0x00000188))
  (global $RHO_PI_RESULT_PTR (export "RHO_PI_RESULT_PTR") i32 (i32.const 0x000000C0))
  (global $CHI_RESULT_PTR    (export "CHI_RESULT_PTR")    i32 (i32.const 0x000000C0))

  ;; Rate-block staging buffer
  (global $PAD_PTR (export "PAD_PTR") i32 (i32.const 0x00000250))

  ;; IO metadata
  (global $FILE_FD_PTR         i32 (i32.const 0x00000300))
  (global $NREAD_PTR           i32 (i32.const 0x00000308))  ;; 8-byte aligned for WASI i64 output
  (global $IOVEC_READ_BUF_PTR  i32 (i32.const 0x00000310))
  (global $IOVEC_WRITE_BUF_PTR i32 (i32.const 0x00000318))
  (global $ARGS_COUNT_PTR      i32 (i32.const 0x00000320))
  (global $ARGV_BUF_LEN_PTR    i32 (i32.const 0x00000324))
  (global $ARGV_PTRS_PTR       i32 (i32.const 0x00000328))
  (global $ARGV_BUF_PTR        i32 (i32.const 0x00000368))
  (global $ASCII_HASH_PTR      i32 (i32.const 0x00000468))
  (global $NYBBLE_TABLE        i32 (i32.const 0x000004E8))
  (global $ASCII_SPACES        i32 (i32.const 0x000004F8))
  (global $STR_WRITE_BUF_PTR   i32 (i32.const 0x00000500))

  (data (memory $main) (i32.const 0x000004E8) "0123456789abcdef")
  (data (memory $main) (i32.const 0x000004F8) "  ")

  ;; Error messages
  (global $ERR_BAD_ARGS        i32 (i32.const 0x00000580)) ;; Length = 65
  (data  (memory $main)            (i32.const 0x00000580) "Bad args: 224|256|384|512 <file>  or  shake128|256 <bytes> <file>")

  (global $ERR_NOENT           i32 (i32.const 0x000005C4)) ;; Length = 25
  (data  (memory $main)            (i32.const 0x000005C4) "No such file or directory")

  (global $ERR_READING_FILE    i32 (i32.const 0x000005E0)) ;; Length = 18
  (data  (memory $main)            (i32.const 0x000005E0) "Error reading file")

  (global $ERR_NOT_DIR_SYMLINK i32 (i32.const 0x000005F8)) ;; Length = 48
  (data  (memory $main)            (i32.const 0x000005F8) "Neither a directory nor a symlink to a directory")

  (global $ERR_BAD_FD          i32 (i32.const 0x00000630)) ;; Length = 19
  (data  (memory $main)            (i32.const 0x00000630) "Bad file descriptor")

  (global $ERR_ACCESS          i32 (i32.const 0x00000648)) ;; Length = 17
  (data  (memory $main)            (i32.const 0x00000648) "Permission denied")

  (global $ERR_NOT_PERMITTED   i32 (i32.const 0x00000660)) ;; Length = 23
  (data  (memory $main)            (i32.const 0x00000660) "Operation not permitted")

  (global $ERR_FILENAME_LONG   i32 (i32.const 0x00000678)) ;; Length = 25
  (data  (memory $main)            (i32.const 0x00000678) "Filename too long (>=256)")

  (global $ERR_GEN_IO          i32 (i32.const 0x00000698)) ;; Length = 21
  (data  (memory $main)            (i32.const 0x00000698) "IO error opening file")

  (global $ERR_PREFIX          i32 (i32.const 0x000006B0)) ;; Length = 5
  (data  (memory $main)            (i32.const 0x000006B0) "Err: ")

  (global $ERR_SHAKE_BYTES     i32 (i32.const 0x000006B8)) ;; Length = 49
  (data  (memory $main)            (i32.const 0x000006B8) "SHAKE byte count must be in the range 1..16777216")

  ;; 2 MB file read buffer (pages 2-33)
  (global $READ_BUFFER_PTR  (export "READ_BUFFER_PTR")  i32 (i32.const 0x00010000))
  (global $READ_BUFFER_SIZE (export "READ_BUFFER_SIZE") i32 (i32.const 0x00200000))

  ;; Domain suffix bytes (FIPS 202 §6.1 and §6.2)
  (global $DOMAIN_SHA3     (export "DOMAIN_SHA3")   i32 (i32.const 0x06))
  (global $DOMAIN_SHAKE    (export "DOMAIN_SHAKE")  i32 (i32.const 0x1f))

  ;; Mutable sponge state
  (global $RATE            (export "RATE")     (mut i32) (i32.const 17))
  (global $CAPACITY        (export "CAPACITY") (mut i32) (i32.const 8))
  (global $DIGEST_LEN                          (mut i32) (i32.const 256))
  (global $DOMAIN_BYTE                         (mut i32) (i32.const 0x06))
  (global $PARTIAL_BYTES                       (mut i32) (i32.const 0))
  (global $SQUEEZE_OFFSET                      (mut i32) (i32.const 0))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Entry point for standalone WASI runtime execution (E.G. from wasmtime or wasmer).
  ;;
  ;; Usage depends on the mode in which the module is operating:
  ;;   SHA2 Drop-in Replacement Mode:        <cmd> 224|256|384|512 <file>
  ;;   SHA3 Extensible Output Function Mode: <cmd> shake128|shake256 <bytes> <file>
  ;;
  ;; Since the runtime may prepend its own argv items (E.G. --dev for development mode), all arguments are addressed
  ;; from the end.
  ;;
  ;; Steps:
  ;;   0) Parse argc/argv — validate argument count and buffer length.
  ;;   1) Identify mode (SHA3 or SHAKE) from the second- or third-last arguments.
  ;;   2) Open the target file from the directory preopened by the WASI runtime (will be fd 3).
  ;;   3) Initialise the sponge state.
  ;;   4) Read the file in 2 MB chunks, absorbing each chunk.
  ;;   5) Repeat step 4 until we hit EOF, at which point we finalize the internal state.
  ;;   6) Close the file.
  ;;   7) Squeeze the digest zero or more times and write the required length of data to stdout.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "_start")
    (local $argc          i32)
    (local $argv_buf_len  i32)
    (local $hash_len_ptr  i32)
    (local $hash_len_val  i32)
    (local $digest_len    i32)
    (local $digest_bytes  i32)
    (local $domain_byte   i32)
    (local $filename_ptr  i32)
    (local $filename_len  i32)
    (local $file_fd       i32)
    (local $return_code   i32)
    (local $bytes_read    i32)
    (local $remaining     i32)
    (local $chunk         i32)
    (local $byte_offset   i32)

    (block $exit
      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 0: Fetch argument count and total buffer length
      (drop (call $wasi.args_sizes_get (global.get $ARGS_COUNT_PTR) (global.get $ARGV_BUF_LEN_PTR)))

      (local.set $argc         (i32.load (memory $main) (global.get $ARGS_COUNT_PTR)))
      (local.set $argv_buf_len (i32.load (memory $main) (global.get $ARGV_BUF_LEN_PTR)))

      (if (i32.gt_u (local.get $argv_buf_len) (i32.const 256))
        (then (call $writeln (i32.const 2) (global.get $ERR_FILENAME_LONG) (i32.const 25)) (br $exit))
      )

      ;; Need at least: module-name + hash-variant + filename = 3 items; argc must be >= 2 user args
      (if (i32.lt_u (local.get $argc) (i32.const 2))
        (then (call $writeln (i32.const 2) (global.get $ERR_BAD_ARGS) (i32.const 65)) (br $exit))
      )

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 1: Identify algorithm from the end of argv
      (drop (call $wasi.args_get (global.get $ARGV_PTRS_PTR) (global.get $ARGV_BUF_PTR)))

      (block $args_ok
        ;; XOF (SHAKE) detection
        ;; Look for "shak" as the first four bytes of the third-last argument
        (if (i32.ge_u (local.get $argc) (i32.const 3))
          (then
            (drop
              (local.set $hash_len_ptr (call $fetch_arg_n (i32.sub (local.get $argc) (i32.const 2))))
            )
            (if
              (i32.eq
                (i32.load (memory $main) (local.get $hash_len_ptr))
                (i32.const 0x6B616873) ;; ASCII "shak" in LE format
              )
              (then
                (block $shake_ok
                  (if ;; Have we found "shake128"?
                    (i32.eq
                      (i32.load (memory $main) (i32.add (local.get $hash_len_ptr) (i32.const 4)))
                      (i32.const 0x38323165) ;; ASCII "e128" in LE format
                    )
                    (then
                      (local.set $digest_len  (i32.const 128))
                      (local.set $domain_byte (global.get $DOMAIN_SHAKE))
                      (br $shake_ok)
                    )
                  )
                  (if ;; Have we found "shake256"?
                    (i32.eq
                      (i32.load (memory $main) (i32.add (local.get $hash_len_ptr) (i32.const 4)))
                      (i32.const 0x36353265) ;; ASCII "e256" in LE format
                    )
                    (then
                      (local.set $digest_len  (i32.const 256))
                      (local.set $domain_byte (global.get $DOMAIN_SHAKE))
                      (br $shake_ok)
                    )
                  )
                  ;; Nope, so some other value has been received.
                  ;; Write error message and exit
                  (call $writeln (i32.const 2) (global.get $ERR_BAD_ARGS) (i32.const 65))
                  (br $exit)
                )

                ;; Parse output byte count from second-last arg
                (local.set $hash_len_val
                  (local.set $hash_len_ptr (call $fetch_arg_n (i32.sub (local.get $argc) (i32.const 1))))
                )
                (local.set $digest_bytes (call $parse_decimal (local.get $hash_len_ptr) (local.get $hash_len_val)))

                ;; Check that 0 < $digest_bytes < 16 Mb
                ;; This is an arbitrary sanity limit to prevent infinite overrun in the squeeze loop
                (if
                  (i32.or
                    (i32.eqz  (local.get $digest_bytes))
                    (i32.gt_u (local.get $digest_bytes) (i32.const 0x01000000))
                  )
                  (then
                    (call $writeln (i32.const 2) (global.get $ERR_SHAKE_BYTES) (i32.const 49))
                    (br $exit)
                  )
                )
                (br $args_ok) ;; SHAKE args OK, so no further parsing needed
              )
            )
          )
        )

        ;; SHA2 Drop-in replacement mode
        ;; The second-last argument should contain the digest length in bits
        (drop (local.set $hash_len_ptr (call $fetch_arg_n (i32.sub (local.get $argc) (i32.const 1)))))
        (local.set $hash_len_val (i32.load (memory $main) (local.get $hash_len_ptr)))

        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00343232)) ;; ASCII "224\0" in LE format
          (then
            (local.set $digest_len  (i32.const 224))
            (local.set $domain_byte (global.get $DOMAIN_SHA3))
            (br $args_ok)
          )
        )
        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00363532)) ;; ASCII "256\0" in LE format
          (then
            (local.set $digest_len  (i32.const 256))
            (local.set $domain_byte (global.get $DOMAIN_SHA3))
            (br $args_ok)
          )
        )
        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00343833)) ;; ASCII "384\0" in LE format
          (then
            (local.set $digest_len  (i32.const 384))
            (local.set $domain_byte (global.get $DOMAIN_SHA3))
            (br $args_ok)
          )
        )
        (if (i32.eq (local.get $hash_len_val) (i32.const 0x00323135)) ;; ASCII "512\0" in LE format
          (then
            (local.set $digest_len  (i32.const 512))
            (local.set $domain_byte (global.get $DOMAIN_SHA3))
            (br $args_ok)
          )
        )

        ;; If we get to here, an invalid value has been received for the digest length.
        ;; Write error message and exit
        (call $writeln (i32.const 2) (global.get $ERR_BAD_ARGS) (i32.const 65))
        (br $exit)
      ) ;; $args_ok

      ;; For SHA2 drop-in replacement mode, the output byte count equals digest_len / 8
      ;; SHAKE coding has already parsed it above
      (if (i32.ne (local.get $domain_byte) (global.get $DOMAIN_SHAKE))
        (then (local.set $digest_bytes (i32.shr_u (local.get $digest_len) (i32.const 3))))
      )

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 2: Open the file (last arg) from the preopened directory (fd 3)
      (local.set $filename_len
        (local.set $filename_ptr (call $fetch_arg_n (local.get $argc)))
      )

      (local.tee $return_code
        (local.set $file_fd
          (call $file_open (i32.const 3) (local.get $filename_ptr) (local.get $filename_len))
        )
      )
      (if (then (br $exit)))

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 3: Initialise sponge
      (call $init_state (local.get $digest_len) (local.get $domain_byte))

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 4: Read the file in 2 MB chunks, absorbing each chunk
      (i32.store (memory $main) (global.get $IOVEC_READ_BUF_PTR) (global.get $READ_BUFFER_PTR))
      (i32.store (memory $main)
        (i32.add (global.get $IOVEC_READ_BUF_PTR) (i32.const 4))
        (global.get $READ_BUFFER_SIZE)
      )

      (loop $read_chunk
        (local.tee $return_code
          (call $wasi.fd_read
            (local.get $file_fd)
            (global.get $IOVEC_READ_BUF_PTR)
            (i32.const 1)
            (global.get $NREAD_PTR)
          )
        )
        (if (then (call $writeln (i32.const 2) (global.get $ERR_READING_FILE) (i32.const 18)) (br $exit)))

        (local.set $bytes_read (i32.load (memory $main) (global.get $NREAD_PTR)))

        (if (local.get $bytes_read)
          (then (call $absorb (global.get $READ_BUFFER_PTR) (local.get $bytes_read)))
        )
        (br_if $read_chunk (local.get $bytes_read))
      )

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 5: Finalise
      (call $finalize)

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 6: Close the file
      (drop (call $wasi.fd_close (local.get $file_fd)))

      ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
      ;; Step 7: Squeeze the digest in 64-byte chunks, hex-encode, and write to stdout
      (local.set $remaining (local.get $digest_bytes))

      (loop $hex_chunk
        (local.set $chunk
          (if (result i32) (i32.lt_u (local.get $remaining) (i32.const 64))
            (then (local.get $remaining))
            (else (i32.const 64))
          )
        )
        (call $squeeze (global.get $PAD_PTR) (local.get $chunk))

        (local.set $byte_offset (i32.const 0))
        (loop $to_hex
          (call $to_hex_pair
            (i32.load8_u (memory $main) (i32.add (global.get $PAD_PTR) (local.get $byte_offset)))
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
        (br_if $hex_chunk (local.get $remaining))
      )

      ;; In SHA2 drop-in replacement mode, additionally print "  <filename>\n"
      ;; In XOF mode, just print a newline
      (if (i32.eq (local.get $domain_byte) (global.get $DOMAIN_SHA3))
        (then
          (call $write   (global.get $FD_STDOUT) (global.get $ASCII_SPACES) (i32.const 2))
          (call $writeln (global.get $FD_STDOUT)
            (local.get $filename_ptr)
            (local.get $filename_len)
          )
        )
        (else
          ;; Write a LF by telling $writeln() to write a zero length string
          (call $writeln (global.get $FD_STDOUT) (global.get $ASCII_SPACES) (i32.const 0))
        )
      )
    ) ;; $exit
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Initialise the sponge for a new computation.
  ;;   * Sets RATE, CAPACITY, DOMAIN_BYTE
  ;;   * Zeros the Keccak state
  ;;   * Resets the absorb and squeeze cursors
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $init_state (export "init_state")
        (param $digest_len  i32)  ;; SHA3: 224|256|384|512; SHAKE: 128 (SHAKE128) or 256 (SHAKE256)
        (param $domain_byte i32)  ;; 0x06 = SHA3, 0x1f = SHAKE
    (global.set $DOMAIN_BYTE    (local.get $domain_byte))
    (global.set $DIGEST_LEN     (local.get $digest_len))
    (global.set $PARTIAL_BYTES  (i32.const 0))
    (global.set $SQUEEZE_OFFSET (i32.const 0))
    (global.set $RATE
      (i32.shr_u (i32.sub (i32.const 1600) (i32.shl (local.get $digest_len) (i32.const 1))) (i32.const 6))
    )
    (global.set $CAPACITY (i32.sub (i32.const 25) (global.get $RATE)))

    (memory.fill (memory $main) (global.get $STATE_PTR) (i32.const 0) (i32.const 200))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Absorb $src_len bytes at $src_ptr into the sponge.
  ;; Accumulates partial rate-blocks across calls;
  ;; When file IO hits EOF, call finalize() instead of absorb().
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $absorb (export "absorb")
        (param $src_ptr  i32)
        (param $src_len  i32)

    (local $rate       i32)
    (local $rate_bytes i32)
    (local $fill_len   i32)
    ;; Cache RATE into a local so the optimiser can hoist it out of loops
    (local.set $rate       (global.get $RATE))
    (local.set $rate_bytes (i32.shl (local.get $rate) (i32.const 3)))

    ;; Complete any partial rate-block carried over from a previous absorb() call
    (if (global.get $PARTIAL_BYTES)
      (then
        (local.set $fill_len
          (if (result i32) (i32.lt_u (local.get $src_len)
                             (i32.sub (local.get $rate_bytes) (global.get $PARTIAL_BYTES)))
            (then (local.get $src_len))
            (else (i32.sub (local.get $rate_bytes) (global.get $PARTIAL_BYTES)))
          )
        )
        (memory.copy (memory $main) (memory $main)
          (i32.add (global.get $PAD_PTR) (global.get $PARTIAL_BYTES))
          (local.get $src_ptr)
          (local.get $fill_len)
        )
        (global.set $PARTIAL_BYTES (i32.add (global.get $PARTIAL_BYTES) (local.get $fill_len)))
        (local.set $src_ptr        (i32.add (local.get $src_ptr)        (local.get $fill_len)))
        (local.set $src_len        (i32.sub (local.get $src_len)        (local.get $fill_len)))

        (if (i32.eq (global.get $PARTIAL_BYTES) (local.get $rate_bytes))
          (then
            (call $xor_block_into_state (local.get $rate) (global.get $PAD_PTR))
            (call $keccak24)
            (global.set $PARTIAL_BYTES (i32.const 0))
          )
        )
      )
    )

    ;; Absorb complete rate-blocks directly from the source buffer
    (if (i32.ge_u (local.get $src_len) (local.get $rate_bytes))
      (then
        (loop $full_blocks
          (call $xor_block_into_state (local.get $rate) (local.get $src_ptr))
          (call $keccak24)
          (local.set $src_ptr (i32.add (local.get $src_ptr) (local.get $rate_bytes)))
          (local.set $src_len (i32.sub (local.get $src_len) (local.get $rate_bytes)))
          (br_if $full_blocks (i32.ge_u (local.get $src_len) (local.get $rate_bytes)))
        )
      )
    )

    ;; Save any leftover bytes for the next absorb() call or for finalize()
    (if (local.get $src_len)
      (then
        (memory.copy (memory $main) (memory $main)
          (global.get $PAD_PTR)
          (local.get $src_ptr)
          (local.get $src_len)
        )
        (global.set $PARTIAL_BYTES (local.get $src_len))
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Complete the absorb phase:
  ;;
  ;; 1) Apply the pad10*1 padding function (FIPS 202 §5.1)
  ;; 2) Terminate the data in the current rate block:
  ;;    2.1) Write the appropriate domain separator (0x06 = SHA3, 0x1f = SHAKE) after the last data byte
  ;;    2.2) In the last byte in the rate block, set the senior bit to 1
  ;; 3) Run the final Keccak round
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $finalize (export "finalize")
    (local $rate_bytes i32)
    (local.set $rate_bytes (i32.shl (global.get $RATE) (i32.const 3)))

    ;; Zero the portion of PAD_PTR that follows the last absorbed byte
    (memory.fill (memory $main)
      (i32.add (global.get $PAD_PTR) (global.get $PARTIAL_BYTES))
      (i32.const 0)
      (i32.sub (local.get $rate_bytes) (global.get $PARTIAL_BYTES))
    )

    ;; Write domain separator immediately after the last absorbed byte
    (i32.store8 (memory $main)
      (i32.add (global.get $PAD_PTR) (global.get $PARTIAL_BYTES))
      (global.get $DOMAIN_BYTE)
    )

    ;; Set the high bit of the last byte in the rate block (pad10*1 closing bit)
    (i32.store8 (memory $main)
      (i32.add (global.get $PAD_PTR) (i32.sub (local.get $rate_bytes) (i32.const 1)))
      (i32.or
        (i32.load8_u (memory $main)
          (i32.add (global.get $PAD_PTR) (i32.sub (local.get $rate_bytes) (i32.const 1)))
        )
        (i32.const 0x80) ;; Set the high bit
      )
    )

    ;; Absorb the final block and run the last Keccak round
    (call $xor_block_into_state (global.get $RATE) (global.get $PAD_PTR))
    (call $keccak24)
    (global.set $SQUEEZE_OFFSET (i32.const 0))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Squeeze $len bytes from the sponge state into the buffer at $out_ptr.
  ;; If $len exceeds the number of bytes remaining in the current rate block, an additional Keccak permutation is
  ;; performed and squeezing continues from the start of the rate block.
  ;;
  ;; When using SHAKE128 or SHAKE256, the squeeze function can be called an unlimited number of times to generate an
  ;; arbitrary-length output stream of psuedo-random data
  ;;
  ;; When SHA3 is used as a SHA2 drop-in replacement, the squeeze function does not need to be called since after
  ;; calling finalise(), the first DIGEST_LEN bytes of the state already contain the required hash value
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $squeeze (export "squeeze")
        (param $out_ptr i32)
        (param $len     i32)

    (local $rate_bytes i32)
    (local $available  i32)
    (local $copy_len   i32)
    (local.set $rate_bytes (i32.shl (global.get $RATE) (i32.const 3)))

    (if (local.get $len)
      (then
        (loop $squeeze_loop
          (local.set $available (i32.sub (local.get $rate_bytes) (global.get $SQUEEZE_OFFSET)))
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

          (br_if $squeeze_loop (local.get $len))
        )
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Run all 24 Keccak rounds on the state at STATE_PTR.
  ;; Loop has been unrolled to improve optimization
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $keccak24 (export "keccak24")
    (call $keccak (i32.const  0)) (call $keccak (i32.const  1)) (call $keccak (i32.const  2))
    (call $keccak (i32.const  3)) (call $keccak (i32.const  4)) (call $keccak (i32.const  5))
    (call $keccak (i32.const  6)) (call $keccak (i32.const  7)) (call $keccak (i32.const  8))
    (call $keccak (i32.const  9)) (call $keccak (i32.const 10)) (call $keccak (i32.const 11))
    (call $keccak (i32.const 12)) (call $keccak (i32.const 13)) (call $keccak (i32.const 14))
    (call $keccak (i32.const 15)) (call $keccak (i32.const 16)) (call $keccak (i32.const 17))
    (call $keccak (i32.const 18)) (call $keccak (i32.const 19)) (call $keccak (i32.const 20))
    (call $keccak (i32.const 21)) (call $keccak (i32.const 22)) (call $keccak (i32.const 23))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Execute one round of the Keccak step functions.
  ;; State lives in STATE (BUF_0) before and after the round.
  ;; Function $theta reads the data at STATE (buf_0) then writes it to WORK (buf_1)
  ;; Function $rho_pi reads the data at WORK (buf_1) then writes it back to STATE (buf_0)
  ;; Functions $chi and $iota modify the data at STATE in-place.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $keccak (export "keccak")
        (param $round i32)
    (call $theta)
    (call $rho_pi)
    (call $chi)
    (call $iota (local.get $round))

  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Theta: column-parity mixing (FIPS 202 §3.2.1)
  ;;
  ;; C[x] = Collapse all 5 lanes in column x down to a single i64 by XORing them together.
  ;; D[x] = C[x-1] XOR rotl(C[x+1], 1).
  ;; A'[x,y] = A[x,y] XOR D[x], stored to WORK_PTR.
  ;;
  ;; C and D are held in local i64s to avoid the THETA_C/D_OUT memory round-trips present in V1.
  ;; The 25 output writes are grouped by D-value used (D2, D3, D4, D0, D1 per group) so that each D is live when
  ;; the compiler processes the group, enabling better register allocation.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $theta (export "theta")
    (local $c0 i64) (local $c1 i64) (local $c2 i64) (local $c3 i64) (local $c4 i64)
    (local $d0 i64) (local $d1 i64) (local $d2 i64) (local $d3 i64) (local $d4 i64)

    ;; C[x] = lane(x,0) XOR lane(x,1) XOR lane(x,2) XOR lane(x,3) XOR lane(x,4)
    ;; Row stride = 40 bytes (5 lanes × 8 bytes)
    (local.set $c0
      (i64.xor (i64.xor (i64.xor (i64.xor
        (i64.load (memory $main) offset=0   (global.get $STATE_PTR))
        (i64.load (memory $main) offset=40  (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=80  (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=120 (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=160 (global.get $STATE_PTR))
      )
    )
    (local.set $c1
      (i64.xor (i64.xor (i64.xor (i64.xor
        (i64.load (memory $main) offset=8   (global.get $STATE_PTR))
        (i64.load (memory $main) offset=48  (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=88  (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=128 (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=168 (global.get $STATE_PTR))
      )
    )
    (local.set $c2
      (i64.xor (i64.xor (i64.xor (i64.xor
        (i64.load (memory $main) offset=16  (global.get $STATE_PTR))
        (i64.load (memory $main) offset=56  (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=96  (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=136 (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=176 (global.get $STATE_PTR))
      )
    )
    (local.set $c3
      (i64.xor (i64.xor (i64.xor (i64.xor
        (i64.load (memory $main) offset=24  (global.get $STATE_PTR))
        (i64.load (memory $main) offset=64  (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=104 (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=144 (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=184 (global.get $STATE_PTR))
      )
    )
    (local.set $c4
      (i64.xor (i64.xor (i64.xor (i64.xor
        (i64.load (memory $main) offset=32  (global.get $STATE_PTR))
        (i64.load (memory $main) offset=72  (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=112 (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=152 (global.get $STATE_PTR)))
        (i64.load (memory $main) offset=192 (global.get $STATE_PTR))
      )
    )

    ;; D[x] = C[x-1] XOR rotl(C[x+1], 1) — indices mod 5
    (local.set $d0 (i64.xor (local.get $c4) (i64.rotl (local.get $c1) (i64.const 1))))
    (local.set $d1 (i64.xor (local.get $c0) (i64.rotl (local.get $c2) (i64.const 1))))
    (local.set $d2 (i64.xor (local.get $c1) (i64.rotl (local.get $c3) (i64.const 1))))
    (local.set $d3 (i64.xor (local.get $c2) (i64.rotl (local.get $c4) (i64.const 1))))
    (local.set $d4 (i64.xor (local.get $c3) (i64.rotl (local.get $c0) (i64.const 1))))

    ;; A'[x,y] = A[x,y] XOR D[x].  Grouped by D value; within each group the y-row order matches the traversal pattern
    ;; so adjacent writes share the same D local.

    ;; D2 group: columns x=2 across all rows (offsets 16, 56, 96, 136, 176)
    (i64.store (memory $main) offset=16  (global.get $WORK_PTR)(i64.xor (local.get $d2) (i64.load (memory $main) offset=16  (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=56  (global.get $WORK_PTR)(i64.xor (local.get $d2) (i64.load (memory $main) offset=56  (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=96  (global.get $WORK_PTR)(i64.xor (local.get $d2) (i64.load (memory $main) offset=96  (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=136 (global.get $WORK_PTR)(i64.xor (local.get $d2) (i64.load (memory $main) offset=136 (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=176 (global.get $WORK_PTR)(i64.xor (local.get $d2) (i64.load (memory $main) offset=176 (global.get $STATE_PTR))))

    ;; D3 group: columns x=3 across all rows (offsets 24, 64, 104, 144, 184)
    (i64.store (memory $main) offset=24  (global.get $WORK_PTR) (i64.xor (local.get $d3) (i64.load (memory $main) offset=24  (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=64  (global.get $WORK_PTR) (i64.xor (local.get $d3) (i64.load (memory $main) offset=64  (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=104 (global.get $WORK_PTR) (i64.xor (local.get $d3) (i64.load (memory $main) offset=104 (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=144 (global.get $WORK_PTR) (i64.xor (local.get $d3) (i64.load (memory $main) offset=144 (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=184 (global.get $WORK_PTR) (i64.xor (local.get $d3) (i64.load (memory $main) offset=184 (global.get $STATE_PTR))))

    ;; D4 group: columns x=4 across all rows (offsets 32, 72, 112, 152, 192)
    (i64.store (memory $main) offset=32  (global.get $WORK_PTR) (i64.xor (local.get $d4) (i64.load (memory $main) offset=32  (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=72  (global.get $WORK_PTR) (i64.xor (local.get $d4) (i64.load (memory $main) offset=72  (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=112 (global.get $WORK_PTR) (i64.xor (local.get $d4) (i64.load (memory $main) offset=112 (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=152 (global.get $WORK_PTR) (i64.xor (local.get $d4) (i64.load (memory $main) offset=152 (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=192 (global.get $WORK_PTR) (i64.xor (local.get $d4) (i64.load (memory $main) offset=192 (global.get $STATE_PTR))))

    ;; D0 group: columns x=0 across all rows (offsets 0, 40, 80, 120, 160)
    (i64.store (memory $main) offset=0   (global.get $WORK_PTR) (i64.xor (local.get $d0) (i64.load (memory $main) offset=0   (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=40  (global.get $WORK_PTR) (i64.xor (local.get $d0) (i64.load (memory $main) offset=40  (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=80  (global.get $WORK_PTR) (i64.xor (local.get $d0) (i64.load (memory $main) offset=80  (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=120 (global.get $WORK_PTR) (i64.xor (local.get $d0) (i64.load (memory $main) offset=120 (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=160 (global.get $WORK_PTR) (i64.xor (local.get $d0) (i64.load (memory $main) offset=160 (global.get $STATE_PTR))))

    ;; D1 group: columns x=1 across all rows (offsets 8, 48, 88, 128, 168)
    (i64.store (memory $main) offset=8   (global.get $WORK_PTR) (i64.xor (local.get $d1) (i64.load (memory $main) offset=8   (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=48  (global.get $WORK_PTR) (i64.xor (local.get $d1) (i64.load (memory $main) offset=48  (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=88  (global.get $WORK_PTR) (i64.xor (local.get $d1) (i64.load (memory $main) offset=88  (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=128 (global.get $WORK_PTR) (i64.xor (local.get $d1) (i64.load (memory $main) offset=128 (global.get $STATE_PTR))))
    (i64.store (memory $main) offset=168 (global.get $WORK_PTR) (i64.xor (local.get $d1) (i64.load (memory $main) offset=168 (global.get $STATE_PTR))))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Implement the rho and pi step functions (FIPS 202 §3.2.2 and §3.2.3) as a fused pair
  ;;
  ;; Rho rotates each of the 25 lanes by a lane-specific constant.
  ;; Pi then permutes the lanes using a fixed calculation whose outcome can be hardcoded: A'[x,y] = A[(x+3y) mod 5][x].
  ;;
  ;; Instead of executing them in sequence (each requiring a full 200-byte buffer copy), both transforms are applied in
  ;; a single pass: for each destination position d, the correct source lane s is read from WORK_PTR, rhotated (😃) by
  ;; fixed, pre-calculated amount for that source lane, then written directly to d in STATE_PTR.
  ;;
  ;; The mapping table (dst_offset ← rotl(WORK[src_offset], rho_amount)) grouped by destination row:
  ;;
  ;;  Dst row y=0:  STATE[0]   ←       WORK[0]        Dst row y=1:  STATE[40]  ← rotl(WORK[24],  28)
  ;;                STATE[8]   ← rotl(WORK[48],  44)                STATE[48]  ← rotl(WORK[72],  20)
  ;;                STATE[16]  ← rotl(WORK[96],  43)                STATE[56]  ← rotl(WORK[80],   3)
  ;;                STATE[24]  ← rotl(WORK[144], 21)                STATE[64]  ← rotl(WORK[128], 45)
  ;;                STATE[32]  ← rotl(WORK[192], 14)                STATE[72]  ← rotl(WORK[176], 61)
  ;;
  ;;  Dst row y=2:  STATE[80]  ←  rotl(WORK[8],    1) Dst row y=3:  STATE[120] ← rotl(WORK[32],  27)
  ;;                STATE[88]  ←  rotl(WORK[56],   6)               STATE[128] ← rotl(WORK[40],  36)
  ;;                STATE[96]  ←  rotl(WORK[104], 25)               STATE[136] ← rotl(WORK[88],  10)
  ;;                STATE[104] ←  rotl(WORK[152],  8)               STATE[144] ← rotl(WORK[136], 15)
  ;;                STATE[112] ←  rotl(WORK[160], 18)               STATE[152] ← rotl(WORK[184], 56)
  ;;
  ;;  Dst row y=4:  STATE[160] ← rotl(WORK[16],  62)
  ;;                STATE[168] ← rotl(WORK[64],  55)
  ;;                STATE[176] ← rotl(WORK[112], 39)
  ;;                STATE[184] ← rotl(WORK[120], 41)
  ;;                STATE[192] ← rotl(WORK[168],  2)
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $rho_pi (export "rho_pi")
    ;; Row y=0
    (i64.store (memory $main) offset=0   (global.get $STATE_PTR)            (i64.load (memory $main) offset=0   (global.get $WORK_PTR)))
    (i64.store (memory $main) offset=8   (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=48  (global.get $WORK_PTR)) (i64.const 44)))
    (i64.store (memory $main) offset=16  (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=96  (global.get $WORK_PTR)) (i64.const 43)))
    (i64.store (memory $main) offset=24  (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=144 (global.get $WORK_PTR)) (i64.const 21)))
    (i64.store (memory $main) offset=32  (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=192 (global.get $WORK_PTR)) (i64.const 14)))

    ;; Row y=1
    (i64.store (memory $main) offset=40  (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=24  (global.get $WORK_PTR)) (i64.const 28)))
    (i64.store (memory $main) offset=48  (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=72  (global.get $WORK_PTR)) (i64.const 20)))
    (i64.store (memory $main) offset=56  (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=80  (global.get $WORK_PTR)) (i64.const  3)))
    (i64.store (memory $main) offset=64  (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=128 (global.get $WORK_PTR)) (i64.const 45)))
    (i64.store (memory $main) offset=72  (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=176 (global.get $WORK_PTR)) (i64.const 61)))

    ;; Row y=2
    (i64.store (memory $main) offset=80  (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=8   (global.get $WORK_PTR)) (i64.const  1)))
    (i64.store (memory $main) offset=88  (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=56  (global.get $WORK_PTR)) (i64.const  6)))
    (i64.store (memory $main) offset=96  (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=104 (global.get $WORK_PTR)) (i64.const 25)))
    (i64.store (memory $main) offset=104 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=152 (global.get $WORK_PTR)) (i64.const  8)))
    (i64.store (memory $main) offset=112 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=160 (global.get $WORK_PTR)) (i64.const 18)))

    ;; Row y=3
    (i64.store (memory $main) offset=120 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=32  (global.get $WORK_PTR)) (i64.const 27)))
    (i64.store (memory $main) offset=128 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=40  (global.get $WORK_PTR)) (i64.const 36)))
    (i64.store (memory $main) offset=136 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=88  (global.get $WORK_PTR)) (i64.const 10)))
    (i64.store (memory $main) offset=144 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=136 (global.get $WORK_PTR)) (i64.const 15)))
    (i64.store (memory $main) offset=152 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=184 (global.get $WORK_PTR)) (i64.const 56)))

    ;; Row y=4
    (i64.store (memory $main) offset=160 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=16  (global.get $WORK_PTR)) (i64.const 62)))
    (i64.store (memory $main) offset=168 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=64  (global.get $WORK_PTR)) (i64.const 55)))
    (i64.store (memory $main) offset=176 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=112 (global.get $WORK_PTR)) (i64.const 39)))
    (i64.store (memory $main) offset=184 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=120 (global.get $WORK_PTR)) (i64.const 41)))
    (i64.store (memory $main) offset=192 (global.get $STATE_PTR) (i64.rotl  (i64.load (memory $main) offset=168 (global.get $WORK_PTR)) (i64.const  2)))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Chi: non-linear mixing (FIPS 202 §3.2.4)
  ;;
  ;; A'[x,y] = A[x,y] XOR (NOT A[x+1 mod 5, y] AND A[x+2 mod 5, y])
  ;;
  ;; Operates in-place on the data at STATE_PTR.
  ;; Each of the five lanes in a row are loaded into locals before any writes, so original values are preserved for the
  ;; duration of the row computation without the need for a second buffer.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $chi (export "chi")
    (local $a0 i64) (local $a1 i64) (local $a2 i64) (local $a3 i64) (local $a4 i64)
    ;; Row y=0 (offsets 0..32)
    (local.set $a0 (i64.load (memory $main) offset=0  (global.get $STATE_PTR)))
    (local.set $a1 (i64.load (memory $main) offset=8  (global.get $STATE_PTR)))
    (local.set $a2 (i64.load (memory $main) offset=16 (global.get $STATE_PTR)))
    (local.set $a3 (i64.load (memory $main) offset=24 (global.get $STATE_PTR)))
    (local.set $a4 (i64.load (memory $main) offset=32 (global.get $STATE_PTR)))

    (i64.store (memory $main) offset=0  (global.get $STATE_PTR) (i64.xor (local.get $a0) (i64.and (i64.xor (local.get $a1) (i64.const -1)) (local.get $a2))))
    (i64.store (memory $main) offset=8  (global.get $STATE_PTR) (i64.xor (local.get $a1) (i64.and (i64.xor (local.get $a2) (i64.const -1)) (local.get $a3))))
    (i64.store (memory $main) offset=16 (global.get $STATE_PTR) (i64.xor (local.get $a2) (i64.and (i64.xor (local.get $a3) (i64.const -1)) (local.get $a4))))
    (i64.store (memory $main) offset=24 (global.get $STATE_PTR) (i64.xor (local.get $a3) (i64.and (i64.xor (local.get $a4) (i64.const -1)) (local.get $a0))))
    (i64.store (memory $main) offset=32 (global.get $STATE_PTR) (i64.xor (local.get $a4) (i64.and (i64.xor (local.get $a0) (i64.const -1)) (local.get $a1))))

    ;; Row y=1 (offsets 40..72)
    (local.set $a0 (i64.load (memory $main) offset=40  (global.get $STATE_PTR)))
    (local.set $a1 (i64.load (memory $main) offset=48  (global.get $STATE_PTR)))
    (local.set $a2 (i64.load (memory $main) offset=56  (global.get $STATE_PTR)))
    (local.set $a3 (i64.load (memory $main) offset=64  (global.get $STATE_PTR)))
    (local.set $a4 (i64.load (memory $main) offset=72  (global.get $STATE_PTR)))

    (i64.store (memory $main) offset=40  (global.get $STATE_PTR) (i64.xor (local.get $a0) (i64.and (i64.xor (local.get $a1) (i64.const -1)) (local.get $a2))))
    (i64.store (memory $main) offset=48  (global.get $STATE_PTR) (i64.xor (local.get $a1) (i64.and (i64.xor (local.get $a2) (i64.const -1)) (local.get $a3))))
    (i64.store (memory $main) offset=56  (global.get $STATE_PTR) (i64.xor (local.get $a2) (i64.and (i64.xor (local.get $a3) (i64.const -1)) (local.get $a4))))
    (i64.store (memory $main) offset=64  (global.get $STATE_PTR) (i64.xor (local.get $a3) (i64.and (i64.xor (local.get $a4) (i64.const -1)) (local.get $a0))))
    (i64.store (memory $main) offset=72  (global.get $STATE_PTR) (i64.xor (local.get $a4) (i64.and (i64.xor (local.get $a0) (i64.const -1)) (local.get $a1))))

    ;; Row y=2 (offsets 80..112)
    (local.set $a0 (i64.load (memory $main) offset=80  (global.get $STATE_PTR)))
    (local.set $a1 (i64.load (memory $main) offset=88  (global.get $STATE_PTR)))
    (local.set $a2 (i64.load (memory $main) offset=96  (global.get $STATE_PTR)))
    (local.set $a3 (i64.load (memory $main) offset=104 (global.get $STATE_PTR)))
    (local.set $a4 (i64.load (memory $main) offset=112 (global.get $STATE_PTR)))

    (i64.store (memory $main) offset=80  (global.get $STATE_PTR) (i64.xor (local.get $a0) (i64.and (i64.xor (local.get $a1) (i64.const -1)) (local.get $a2))))
    (i64.store (memory $main) offset=88  (global.get $STATE_PTR) (i64.xor (local.get $a1) (i64.and (i64.xor (local.get $a2) (i64.const -1)) (local.get $a3))))
    (i64.store (memory $main) offset=96  (global.get $STATE_PTR) (i64.xor (local.get $a2) (i64.and (i64.xor (local.get $a3) (i64.const -1)) (local.get $a4))))
    (i64.store (memory $main) offset=104 (global.get $STATE_PTR) (i64.xor (local.get $a3) (i64.and (i64.xor (local.get $a4) (i64.const -1)) (local.get $a0))))
    (i64.store (memory $main) offset=112 (global.get $STATE_PTR) (i64.xor (local.get $a4) (i64.and (i64.xor (local.get $a0) (i64.const -1)) (local.get $a1))))

    ;; Row y=3 (offsets 120..152)
    (local.set $a0 (i64.load (memory $main) offset=120 (global.get $STATE_PTR)))
    (local.set $a1 (i64.load (memory $main) offset=128 (global.get $STATE_PTR)))
    (local.set $a2 (i64.load (memory $main) offset=136 (global.get $STATE_PTR)))
    (local.set $a3 (i64.load (memory $main) offset=144 (global.get $STATE_PTR)))
    (local.set $a4 (i64.load (memory $main) offset=152 (global.get $STATE_PTR)))

    (i64.store (memory $main) offset=120 (global.get $STATE_PTR) (i64.xor (local.get $a0) (i64.and (i64.xor (local.get $a1) (i64.const -1)) (local.get $a2))))
    (i64.store (memory $main) offset=128 (global.get $STATE_PTR) (i64.xor (local.get $a1) (i64.and (i64.xor (local.get $a2) (i64.const -1)) (local.get $a3))))
    (i64.store (memory $main) offset=136 (global.get $STATE_PTR) (i64.xor (local.get $a2) (i64.and (i64.xor (local.get $a3) (i64.const -1)) (local.get $a4))))
    (i64.store (memory $main) offset=144 (global.get $STATE_PTR) (i64.xor (local.get $a3) (i64.and (i64.xor (local.get $a4) (i64.const -1)) (local.get $a0))))
    (i64.store (memory $main) offset=152 (global.get $STATE_PTR) (i64.xor (local.get $a4) (i64.and (i64.xor (local.get $a0) (i64.const -1)) (local.get $a1))))

    ;; Row y=4 (offsets 160..192)
    (local.set $a0 (i64.load (memory $main) offset=160 (global.get $STATE_PTR)))
    (local.set $a1 (i64.load (memory $main) offset=168 (global.get $STATE_PTR)))
    (local.set $a2 (i64.load (memory $main) offset=176 (global.get $STATE_PTR)))
    (local.set $a3 (i64.load (memory $main) offset=184 (global.get $STATE_PTR)))
    (local.set $a4 (i64.load (memory $main) offset=192 (global.get $STATE_PTR)))

    (i64.store (memory $main) offset=160 (global.get $STATE_PTR) (i64.xor (local.get $a0) (i64.and (i64.xor (local.get $a1) (i64.const -1)) (local.get $a2))))
    (i64.store (memory $main) offset=168 (global.get $STATE_PTR) (i64.xor (local.get $a1) (i64.and (i64.xor (local.get $a2) (i64.const -1)) (local.get $a3))))
    (i64.store (memory $main) offset=176 (global.get $STATE_PTR) (i64.xor (local.get $a2) (i64.and (i64.xor (local.get $a3) (i64.const -1)) (local.get $a4))))
    (i64.store (memory $main) offset=184 (global.get $STATE_PTR) (i64.xor (local.get $a3) (i64.and (i64.xor (local.get $a4) (i64.const -1)) (local.get $a0))))
    (i64.store (memory $main) offset=192 (global.get $STATE_PTR) (i64.xor (local.get $a4) (i64.and (i64.xor (local.get $a0) (i64.const -1)) (local.get $a1))))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Iota: round constant injection (FIPS 202 §3.2.5)
  ;; XORs the round constant RC[$round] into lane A[0,0] at STATE_PTR offset 0.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $iota (export "iota")
        (param $round i32)
    (i64.store (memory $main) offset=0 (global.get $STATE_PTR)
      (i64.xor
        (i64.load (memory $main) offset=0 (global.get $STATE_PTR))
        (i64.load (memory $main) (i32.add (global.get $ROUND_CONSTANTS_PTR) (i32.shl (local.get $round) (i32.const 3))))
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; XOR $rate_words i64 lanes of data at $src_ptr (I.E. read from file) with the first $rate_words lanes of the data at
  ;; STATE_PTR.
  ;; FIPS 202 §3.1.2: lane (x,y) is at sequential byte offset (5y+x)×8; absorb follows this order.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $xor_block_into_state (export "xor_block_into_state")
        (param $rate_words i32)
        (param $src_ptr    i32)

    (local $state_ptr    i32)
    (local.set $state_ptr (global.get $STATE_PTR))

    (loop $xor_loop
      (i64.store (memory $main) (local.get $state_ptr)
        (i64.xor
          (i64.load (memory $main) (local.get $state_ptr))
          (i64.load (memory $main) (local.get $src_ptr))
        )
      )
      (local.set $state_ptr  (i32.add (local.get $state_ptr)  (i32.const 8)))
      (local.set $src_ptr    (i32.add (local.get $src_ptr)    (i32.const 8)))

      (br_if $xor_loop
        (local.tee $rate_words (i32.sub (local.get $rate_words) (i32.const 1)))
      )
    )
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
      (call $wasi.fd_write (local.get $fd) (global.get $IOVEC_WRITE_BUF_PTR) (i32.const 1) (global.get $NREAD_PTR))
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Assemble an optional "Err: " prefix followed by $str_len bytes into STR_WRITE_BUF_PTR.
  ;; Returns the address one byte past the last byte written.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $format_msg
        (param $fd      i32)
        (param $str_ptr i32)
        (param $str_len i32)
        (result i32)

    (local $buf_ptr i32)
    (local.set $buf_ptr (global.get $STR_WRITE_BUF_PTR))

    ;; If writing to stderr, prefix the message with "Err: "
    (if (i32.eq (local.get $fd) (i32.const 2))
      (then
        (memory.copy (memory $main) (memory $main) (local.get $buf_ptr) (global.get $ERR_PREFIX) (i32.const 5))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 5)))
      )
    )
    (memory.copy (memory $main) (memory $main) (local.get $buf_ptr) (local.get $str_ptr) (local.get $str_len))
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
    (local.set $buf_ptr (call $format_msg (local.get $fd) (local.get $str_ptr) (local.get $str_len)))
    (i32.store8 (memory $main) (local.get $buf_ptr) (i32.const 0x0A))  ;; Line feed
    (call $write
      (local.get $fd)
      (global.get $STR_WRITE_BUF_PTR)
      (i32.sub (i32.add (local.get $buf_ptr) (i32.const 1)) (global.get $STR_WRITE_BUF_PTR))
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Write message followed by " 0x<hex_val>\n"; prefix with "Err: " when writing to stderr
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $writeln_with_value
        (param $fd      i32)
        (param $str_ptr i32)
        (param $str_len i32)
        (param $val     i32)

    (local $buf_ptr i32)

    ;; Write message into buffer
    (local.set $buf_ptr (call $format_msg (local.get $fd) (local.get $str_ptr) (local.get $str_len)))

    (i32.store8   (memory $main) (local.get $buf_ptr) (i32.const 0x20))   ;; ASCII space
    (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 1)))     ;; Bump pointer past space
    (i32.store16  (memory $main) (local.get $buf_ptr) (i32.const 0x7830)) ;; ASCII "0x" in LE format
    (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))     ;; Bump pointer past "0x"
    (call $i32_to_hex_str (local.get $val) (local.get $buf_ptr))          ;; Convert to 8 ASCII hex chars and write
    (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 8)))     ;; Bump pointer past hex string
    (i32.store8  (memory $main) (local.get $buf_ptr) (i32.const 0x0A))    ;; Line feed
    (call $write
      (local.get $fd)
      (global.get $STR_WRITE_BUF_PTR)
      (i32.sub (i32.add (local.get $buf_ptr) (i32.const 1)) (global.get $STR_WRITE_BUF_PTR))
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Convert one byte to two hex ASCII characters and write them to $out_ptr
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $to_hex_pair
        (param $byte    i32)
        (param $out_ptr i32)

    ;; Senior nybble
    (i32.store8 (memory $main) (local.get $out_ptr)
      (i32.load8_u (memory $main) (i32.add (global.get $NYBBLE_TABLE) (i32.shr_u (local.get $byte) (i32.const 4))))
    )
    ;; Junior nybble
    (i32.store8 (memory $main) (i32.add (local.get $out_ptr) (i32.const 1))
      (i32.load8_u (memory $main) (i32.add (global.get $NYBBLE_TABLE) (i32.and (local.get $byte) (i32.const 0x0F))))
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Convert an i32 to 8 ASCII hex characters in big-endian order and write to $str_ptr
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $i32_to_hex_str
        (param $val     i32)
        (param $str_ptr i32)

    ;; First byte (0xFF000000)
    (call $to_hex_pair
      (i32.shr_u (local.get $val) (i32.const 24))
      (local.get $str_ptr)
    )

    ;; Second byte (0x00FF0000)
    (call $to_hex_pair
      (i32.and (i32.shr_u (local.get $val) (i32.const 16)) (i32.const 0xFF))
      (i32.add (local.get $str_ptr) (i32.const 2))
    )

    ;; Third byte (0x0000FF00)
    (call $to_hex_pair
      (i32.and (i32.shr_u (local.get $val) (i32.const 8)) (i32.const 0xFF))
      (i32.add (local.get $str_ptr) (i32.const 4))
    )

    ;; Fourth byte (0x000000FF)
    (call $to_hex_pair
      (i32.and (local.get $val) (i32.const 0xFF))
      (i32.add (local.get $str_ptr) (i32.const 6))
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Return (ptr: i32, len: i32) for the n'th (1-based) command line argument.
  ;; wasi.args_get must have been called before this function.
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
        (if (result i32) (i32.eq (local.get $arg_num) (local.get $argc))
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
        (i32.const 1)
      )
    )

    (local.get $arg_n_ptr)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Parse an ASCII decimal string at $ptr/$len into an i32 (stops at first non-digit byte)
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $parse_decimal
        (param $ptr i32)
        (param $len i32)
        (result i32)

    (local $result i32)
    (local $idx    i32)
    (local $digit  i32)

    (if (local.get $len)
      (then
        (loop $digits
          (local.set $digit
            (i32.sub (i32.load8_u (memory $main) (i32.add (local.get $ptr) (local.get $idx))) (i32.const 48))
          )
          (if (i32.gt_u (local.get $digit) (i32.const 9))
            (then (return (local.get $result)))
          )
          (local.set $result (i32.add (i32.mul (local.get $result) (i32.const 10)) (local.get $digit)))
          (local.set $idx    (i32.add          (local.get $idx)    (i32.const 1)))
          (br_if $digits (i32.lt_u (local.get $idx) (local.get $len)))
        )
      )
    )

    (local.get $result)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Open the file at $path_offset/$path_len in the preopened directory $fd_dir.
  ;; Returns: (return_code: i32, file_fd: i32) — return_code 0 = success, else WASI errno
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
          (i32.const 0)
          (local.get $path_offset)
          (local.get $path_len)
          (i32.const 0)
          (i64.const 2)   ;; rights: FD_READ
          (i64.const 0)
          (i32.const 0)
          (global.get $FILE_FD_PTR)
        )
      )
      (if
        (then
          (block $error_handled
            (if (i32.eq (local.get $return_code) (i32.const 0x02)) ;; Permission denied
              (then
                (call $writeln (i32.const 2) (global.get $ERR_ACCESS) (i32.const 17))
                (br $error_handled)
              )
            )
            (if (i32.eq (local.get $return_code) (i32.const 0x08)) ;; Bad file descriptor
              (then
                (call $writeln (i32.const 2) (global.get $ERR_BAD_FD) (i32.const 19))
                (br $error_handled)
              )
            )
            (if (i32.eq (local.get $return_code) (i32.const 0x2C)) ;; No such file or directory
              (then
                (call $writeln (i32.const 2) (global.get $ERR_NOENT) (i32.const 25))
                (br $error_handled)
              )
            )
            (if (i32.eq (local.get $return_code) (i32.const 0x36)) ;; Not a directory
              (then
                (call $writeln (i32.const 2) (global.get $ERR_NOT_DIR_SYMLINK) (i32.const 48))
                (br $error_handled)
              )
            )
            (if (i32.eq (local.get $return_code) (i32.const 0x3F)) ;; Filename too long
              (then
                (call $writeln (i32.const 2) (global.get $ERR_NOT_PERMITTED)(i32.const 23))
                (br $error_handled)
              )
            )

            ;; Generic IO error message for all other error values
            (call $writeln_with_value (i32.const 2) (global.get $ERR_GEN_IO) (i32.const 21) (local.get $return_code))
          )
          (br $exit)
        )
      )

      (local.set $file_fd (i32.load (memory $main) (global.get $FILE_FD_PTR)))
    )

    (local.get $return_code)
    (local.get $file_fd)
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test-only: prepare STATE for a Keccak test by optionally zeroing it, computing RATE/CAPACITY for $digest_len,
  ;; and XORing the first rate-block from PAD_PTR into STATE.
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $prepare_state (export "prepare_state")
        (param $init_mem   i32)
        (param $digest_len i32)
    (block $digest_ok
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 224)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 256)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 384)))
      (br_if $digest_ok (i32.eq (local.get $digest_len) (i32.const 512)))
      ;; Default to $digest_len = 256 if invalid value received
      (local.set $digest_len (i32.const 256))
    )

    (if (local.get $init_mem)
      (then (memory.fill (memory $main) (global.get $STATE_PTR) (i32.const 0) (i32.const 200)))
    )

    (global.set $RATE
      (i32.shr_u (i32.sub (i32.const 1600) (i32.shl (local.get $digest_len) (i32.const 1))) (i32.const 6))
    )
    (global.set $CAPACITY (i32.sub (i32.const 25) (global.get $RATE)))

    (call $xor_block_into_state (global.get $RATE) (global.get $PAD_PTR))

  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Test-only: call prepare_state then run $n rounds starting from round index 0 (ascending order, matching v1).
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $sponge (export "sponge")
        (param $digest_len i32)
        (param $n          i32)

    (local $round i32)
    (call $prepare_state (i32.const 1) (local.get $digest_len))

    (if (local.get $n)
      (then
        (loop $rounds
          (call $keccak (local.get $round))
          (local.set $round (i32.add (local.get $round) (i32.const 1)))
          (br_if $rounds
            (local.tee $n (i32.sub (local.get $n) (i32.const 1)))
          )
        )
      )
    )

  )
)
