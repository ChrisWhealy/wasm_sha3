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
  (global $ASCII_SPACES        i32 (i32.const 0x00100020))  ;; Length = 2
  (global $IOVEC_WRITE_BUF     i32 (i32.const 0x00100100))

  (data (i32.const 0x00100020) "  ")

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Dummy start function (required when instantiating a module from WASI)
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "_start"))

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; For debugging purposes only.
  ;; Write a 64-byte message block in hexdump -C format
  ;; Returns: None
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func (export "hexdump")
        (param $fd      i32) ;; Write to this file descriptor
        (param $blk_ptr i32) ;; Pointer to 64 byte block in exported memory

    (local $buf_ptr    i32)
    (local $buf_len    i32)
    (local $byte_count i32)
    (local $line_count i32)
    (local $this_byte  i32)

    (local.set $buf_ptr (global.get $IOVEC_WRITE_BUF))

    (loop $lines
      ;; Write memory address
      (call $i32_to_hex_str (local.get $blk_ptr) (local.get $buf_ptr))
      (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 8)))
      (local.set $buf_len (i32.add (local.get $buf_len) (i32.const 8)))

      ;; Two ASCI spaces
      (i32.store16 (local.get $buf_ptr) (i32.load16_u (global.get $ASCII_SPACES)))
      (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))
      (local.set $buf_len (i32.add (local.get $buf_len) (i32.const 2)))

      ;; Write the next 16 bytes as space delimited hex character pairs
      (local.set $byte_count (i32.const 0))
      (loop $hex_chars
        ;; Fetch the next character
        (local.set $this_byte (i32.load8_u (memory $memory) (local.get $blk_ptr)))

        ;; Write the current byte as two ASCII characters
        (call $to_asc_pair (local.get $this_byte) (local.get $buf_ptr))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))
        (local.set $buf_len (i32.add (local.get $buf_len) (i32.const 2)))

        ;; Write a space delimiter
        (i32.store8 (local.get $buf_ptr) (i32.const 0x20))
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 1)))
        (local.set $buf_len (i32.add (local.get $buf_len) (i32.const 1)))

        (if ;; we've just written the 8th byte
          (i32.eq (local.get $byte_count) (i32.const 7))
          (then
            ;; Write an extra space
            (i32.store8 (local.get $buf_ptr) (i32.const 0x20))
            (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 1)))
            (local.set $buf_len (i32.add (local.get $buf_len) (i32.const 1)))
          )
        )

        (local.set $byte_count (i32.add (local.get $byte_count) (i32.const 1)))
        (local.set $blk_ptr    (i32.add (local.get $blk_ptr)    (i32.const 1)))

        (br_if $hex_chars (i32.lt_u (local.get $byte_count) (i32.const 16)))
      )

      ;; Write " |"
      (i32.store16 (local.get $buf_ptr) (i32.const 0x7C20)) ;; space + pipe (little endian)
      (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 2)))
      (local.set $buf_len (i32.add (local.get $buf_len) (i32.const 2)))

      ;; Move $blk_ptr back 16 characters and output the same 16 bytes as ASCII characters
      (local.set $blk_ptr (i32.sub (local.get $blk_ptr) (i32.const 16)))
      (local.set $byte_count (i32.const 0))
      (loop $ascii_chars
        ;; Fetch the next character
        (local.set $this_byte (i32.load8_u (memory $memory) (local.get $blk_ptr)))

        (i32.store8
          (local.get $buf_ptr)
          ;; Only print bytes in the 7-bit ASCII range (32 <= &this_byte < 128)
          (select
            (i32.const 0x2E)       ;; Substitute a '.'
            (local.get $this_byte) ;; Character is printable
            (i32.or
              (i32.lt_u (local.get $this_byte) (i32.const 0x20))
              (i32.ge_u (local.get $this_byte) (i32.const 0x80))
            )
          )
        )

        ;; Bump all the counters etc
        (local.set $buf_ptr (i32.add (local.get $buf_ptr) (i32.const 1)))
        (local.set $buf_len (i32.add (local.get $buf_len) (i32.const 1)))
        (local.set $blk_ptr (i32.add (local.get $blk_ptr) (i32.const 1)))

        (br_if $ascii_chars
          (i32.lt_u
            (local.tee $byte_count (i32.add (local.get $byte_count) (i32.const 1)))
            (i32.const 16)
          )
        )
      )

      ;; Write "|\n"
      (i32.store16 (local.get $buf_ptr) (i32.const 0x0A7C)) ;; pipe + LF (little endian)
      (local.set $buf_ptr    (i32.add (local.get $buf_ptr)    (i32.const 2)))
      (local.set $buf_len    (i32.add (local.get $buf_len)    (i32.const 2)))
      (local.set $line_count (i32.add (local.get $line_count) (i32.const 1)))

      (br_if $lines (i32.lt_u (local.get $line_count) (i32.const 4)))
    )

    (call $write (local.get $fd) (global.get $IOVEC_WRITE_BUF) (local.get $buf_len))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Convert a nybble to its corresponding ASCII value
  ;; Returns: i32
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $nybble_to_asc
        (param $nybble i32)
        (result i32)

    (i32.add
      (local.get $nybble)
      ;; If nybble < 10 add 0x30 -> ASCII "0" to "9", else add 0x57 -> ASCII "a" to "f"
      (select (i32.const 0x30) (i32.const 0x57)
        (i32.lt_u (local.get $nybble) (i32.const 0x0A))
      )
    )
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Convert a single byte to a pair of hexadecimal ASCII characters
  ;; Returns: None
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $to_asc_pair
        (param $byte    i32)  ;; Convert this byte
        (param $out_ptr i32)  ;; Write ASCII character pair here
    (i32.store8          (local.get $out_ptr) (call $nybble_to_asc (i32.shr_u (local.get $byte) (i32.const 4))))
    (i32.store8 offset=1 (local.get $out_ptr) (call $nybble_to_asc (i32.and   (local.get $byte) (i32.const 0x0F))))
  )

  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ;; Convert the i32 pointed to by arg1 into an 8 character ASCII hex string in network byte order
  ;; Returns:
  ;;   Indirect -> Writes output to specified location
  ;; - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  (func $i32_ptr_to_hex_str
        (param $i32_ptr i32)  ;; Pointer to the i32 to be converted
        (param $str_ptr i32)  ;; Write the ASCII characters here

    (call $i32_to_hex_str (i32.load (local.get $i32_ptr)) (local.get $str_ptr))
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

    ;; Write data to console
    (call $wasi.fd_write
      (local.get $fd)
      (global.get $IOVEC_WRITE_BUF_PTR) ;; Location of string data's offset/length
      (i32.const 1)                     ;; Number of iovec buffers to write
      (global.get $NREAD_PTR)           ;; Bytes written
    )

    drop  ;; Don't care about the number of bytes written
  )
)
