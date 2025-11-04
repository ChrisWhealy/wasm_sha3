const U64_MASK = (1n << 64n) - 1n
const binToHexStr = len => val => val.toString(16).padStart(len >>> 2, "0")
const unsignedBinToHexStr = len => val => {
  const v = (typeof val === 'bigint' ? val : BigInt(val)) & U64_MASK
  const hex = v.toString(16).padStart(len >>> 2, "0")

  return (bytes => !bytes ? '' : bytes.reverse().join(' '))(hex.match(/.{2}/g))
}

const swapI32Endianness = i32 =>
  (i32 & 0x000000FF) << 24 |
  (i32 & 0x0000FF00) << 8 |
  (i32 & 0x00FF0000) >>> 8 |
  (i32 & 0xFF000000) >>> 24

const swapI64Endianness = i64 =>
  (i64 & 0x00000000000000FFn) << 56n |
  (i64 & 0x000000000000FF00n) << 40n |
  (i64 & 0x0000000000FF0000n) << 24n |
  (i64 & 0x00000000FF000000n) << 8n |
  (i64 & 0x000000FF00000000n) >> 8n |
  (i64 & 0x0000FF0000000000n) >> 24n |
  (i64 & 0x00FF000000000000n) >> 40n |
  (i64 & 0xFF00000000000000n) >> 56n

export const chunksOf = bytesPerChunk => size => Math.floor(size / bytesPerChunk) + (size % bytesPerChunk > 0)

const u8AsHexStr = binToHexStr(8)
const i32AsHexStr = binToHexStr(32)
const i32AsFmtHexStr = i32 => `0x${i32AsHexStr(i32)}`
const i64AsHexStr = binToHexStr(64)
const u64AsHexStr = unsignedBinToHexStr(64)
const u32AsHexStr = unsignedBinToHexStr(32)

const encoder = new TextEncoder()

const writeStringToArrayBuffer = memory =>
  (str, offset) =>
    encoder.encodeInto(
      str,
      new Uint8Array(
        memory.buffer,
        offset === undefined ? 0 : offset,
        str.length
      )
    )

const i32FromArrayBuffer = memory => {
  let wasmMem8 = new Uint8Array(memory.buffer)
  return offset => wasmMem8[offset] || wasmMem8[offset + 1] << 8 || wasmMem8[offset + 2] << 16 || wasmMem8[offset + 3] << 32
}

export {
  swapI32Endianness,
  swapI64Endianness,
  u8AsHexStr,
  i32AsHexStr,
  i32AsFmtHexStr,
  i32FromArrayBuffer,
  i64AsHexStr,
  u64AsHexStr,
  u32AsHexStr,
  writeStringToArrayBuffer,
}
