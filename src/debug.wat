(module
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Function types for WASI calls
  (type $type_wasi_fd_io (func (param i32 i32 i32 i32) (result i32)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Import OS system calls via WASI preview 2
  (import "wasi_snapshot_preview2" "fd_write" (func $wasi.fd_write (type $type_wasi_fd_io)))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (memory $memory (export "memory") 32)  ;; Incoming data should be written at offset 0

  (global $IOVEC_WRITE_BUF_PTR i32 (i32.const 0x00100000))  ;; Starts at 1Mb
  (global $NREAD_PTR           i32 (i32.const 0x00100010))
  (global $NYBBLE_TABLE        i32 (i32.const 0x00100020))  ;; Length = 16
  (global $IOVEC_WRITE_BUF     i32 (i32.const 0x00100100))

  (data (i32.const 0x00100020) "0123456789abcdef")

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Dummy start function (required when instantiating a module from WASI)
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "_start"))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; For debugging purposes only.
  ;; Write a memory block in hexdump -C format to stdout
  ;; Returns: None
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "hexdump")
        (param $fd      i32) ;; Write to this file descriptor
        (param $blk_ptr i32) ;; Pointer to 64 byte block in exported memory
        (param $length  i32) ;; Length of data - must be a multiple of 16

    (local $buf_ptr    i32)
    (local $asc_ptr    i32)
    (local $byte_count i32)
    (local $this_byte  i32)

    (local.set $buf_ptr (global.get $IOVEC_WRITE_BUF))

    (loop $lines
      ;; Write memory address (8 hex chars)
      (call $i32_to_hex_str (local.get $blk_ptr) (local.get $buf_ptr))
      (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 8)))

      ;; Two spaces
      (i32.store16 (local.get $buf_ptr) (i32.const 0x2020))
      (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))

      ;; Pre-set $asc_ptr to the ASCII section start:
      ;; 8x3 (lo hex) + 1 (gap) + 8x3 (hi hex) + 2 (" |") = 51 bytes ahead
      (local.set $asc_ptr (i32.add (local.get $buf_ptr) (i32.const 51)))

      ;; Bytes 0-7: hex pairs + space delimiter, ASCII char written simultaneously
      (local.set $byte_count (i32.const 0))
      (loop $hex_chars_lo
        (local.set $this_byte (i32.load8_u (memory $memory) (local.get $blk_ptr)))

        (call $to_asc_pair (local.get $this_byte) (local.get $buf_ptr))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))

        (i32.store8 (local.get $buf_ptr) (i32.const 0x20))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 1)))

        (i32.store8
          (local.get $asc_ptr)
          (select
            (i32.const 0x2E)
            (local.get $this_byte)
            (i32.or
              (i32.lt_u (local.get $this_byte) (i32.const 0x20))
              (i32.ge_u (local.get $this_byte) (i32.const 0x7F))
            )
          )
        )
        (local.set $asc_ptr  (i32.add (local.get $asc_ptr)  (i32.const 1)))
        (local.set $blk_ptr  (i32.add (local.get $blk_ptr)  (i32.const 1)))

        (br_if $hex_chars_lo
          (i32.lt_u
            (local.tee $byte_count (i32.add (local.get $byte_count) (i32.const 1)))
            (i32.const 8)
          )
        )
      )

      ;; Extra gap space between the two byte groups
      (i32.store8 (local.get $buf_ptr) (i32.const 0x20))
      (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 1)))

      ;; Bytes 8-15: hex pairs + space delimiter, ASCII char written simultaneously
      (local.set $byte_count (i32.const 0))
      (loop $hex_chars_hi
        (local.set $this_byte (i32.load8_u (memory $memory) (local.get $blk_ptr)))

        (call $to_asc_pair (local.get $this_byte) (local.get $buf_ptr))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))

        (i32.store8 (local.get $buf_ptr) (i32.const 0x20))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 1)))

        (i32.store8
          (local.get $asc_ptr)
          (select
            (i32.const 0x2E)       ;; Substitute a '.' for non-printable chars
            (local.get $this_byte)
            (i32.or
              (i32.lt_u (local.get $this_byte) (i32.const 0x20))
              (i32.ge_u (local.get $this_byte) (i32.const 0x7F))
            )
          )
        )
        (local.set $asc_ptr  (i32.add (local.get $asc_ptr)  (i32.const 1)))
        (local.set $blk_ptr  (i32.add (local.get $blk_ptr)  (i32.const 1)))

        (br_if $hex_chars_hi
          (i32.lt_u
            (local.tee $byte_count (i32.add (local.get $byte_count) (i32.const 1)))
            (i32.const 8)
          )
        )
      )

      ;; Write " |" — $buf_ptr has landed exactly at the ASCII section start
      (i32.store16 (local.get $buf_ptr) (i32.const 0x7C20))

      ;; Write "|\n" — $asc_ptr has advanced 16 bytes past the ASCII section start
      (i32.store16 (local.get $asc_ptr) (i32.const 0x0A7C))

      ;; Advance $buf_ptr to end of completed line
      (local.set $buf_ptr (i32.add (local.get $asc_ptr) (i32.const 2)))

      (br_if $lines
        (i32.gt_s
          (local.tee $length (i32.sub (local.get $length) (i32.const 16)))
          (i32.const 0)
        )
      )
    )

    (call $write (local.get $fd) (global.get $IOVEC_WRITE_BUF)
      (i32.sub (local.get $buf_ptr) (global.get $IOVEC_WRITE_BUF))
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Convert a single byte to a pair of hexadecimal ASCII characters
  ;; Returns: None
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $to_asc_pair
        (param $byte    i32)
        (param $out_ptr i32)

    ;; High nybble
    (i32.store8 (local.get $out_ptr)
      (i32.load8_u (i32.add (global.get $NYBBLE_TABLE) (i32.shr_u (local.get $byte) (i32.const 4))))
    )

    ;; Low nybble
    (i32.store8 offset=1 (local.get $out_ptr)
      (i32.load8_u (i32.add (global.get $NYBBLE_TABLE) (i32.and (local.get $byte) (i32.const 0x0F))))
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Convert an i32 into an 8 character ASCII hex string in network byte order
  ;; Returns:
  ;;   Indirect -> Writes output to specified location
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $i32_to_hex_str
        (param $i32_val i32)  ;; i32 to be converted
        (param $str_ptr i32)  ;; Write the ASCII characters here

    (call $to_asc_pair
      (i32.shr_u (local.get $i32_val) (i32.const 24))
                 (local.get $str_ptr)
    )
    (call $to_asc_pair
      (i32.and (i32.shr_u (local.get $i32_val) (i32.const 16)) (i32.const 0xFF))
      (i32.add            (local.get $str_ptr) (i32.const 2))
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
  ;; Write data to the console on either stdout or stderr
  ;; Returns: None
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $write
        (param $fd      i32)  ;; fd of stdout (1) or stderr (2)
        (param $str_ptr i32)  ;; Pointer to string
        (param $str_len i32)  ;; String length

    ;; Prepare iovec buffer write values: data offset + length
    (i32.store          (global.get $IOVEC_WRITE_BUF_PTR)                (local.get $str_ptr))
    (i32.store (i32.add (global.get $IOVEC_WRITE_BUF_PTR) (i32.const 4)) (local.get $str_len))

    (drop ;; Don't care about the number of bytes written
      (call $wasi.fd_write ;; Write data to console
        (local.get $fd)
        (global.get $IOVEC_WRITE_BUF_PTR) ;; Location of string data's offset/length
        (i32.const 1)                     ;; Number of iovec buffers to write
        (global.get $NREAD_PTR)           ;; Bytes written
      )
    )
  )
)
