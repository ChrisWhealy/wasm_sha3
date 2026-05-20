#!/usr/bin/env node

// Suppress ExperimentalWarning message when importing WASI
process.removeAllListeners('warning')
process.on('warning', w => w.name === 'ExperimentalWarning' ? {} : console.warn(w.name, w.message))

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Wrapper for using the SHA3 WASM module in XOF (extendable-output) mode from JavaScript.
//
// Key difference from sha3sum.mjs: this uses wasi.initialize() instead of wasi.start().
//
// wasi.start() calls _start after which the WASM module terminates , the process exits and the internal state is lost.
// However wasi.initialize() sets up the WASI import object and leaves control with the caller, thus preserving the
// internal sponge state between calls to absorb(), finalize(), and squeeze().
//
// squeeze() can now be called multiple times to extract as many output bytes as needed
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
import { WASI } from 'wasi'
import { readFileSync } from 'fs'
import * as log from './utils/logging.mjs'

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
export class SHA3Sponge {
  #exports          // raw WASM exports
  #readBufPtr       // address of the read/output staging buffer in WASM linear memory
  #readBufSize      // capacity of that buffer in bytes
  #validDigestLens  // { domainByte → Set<digestLen> }, keyed by values read from exports
  #devMode          // true when instantiated with the debug module wired in

  static #genBinPath(isProd, isOpt) {
    return `./bin/sha3.${isProd ? 'prod' : 'dev'}${isOpt ? '.opt' : ''}.wasm`
  }

  static #genDebugPath(isOpt) {
    return `./bin/debug${isOpt ? '.opt' : ''}.wasm`
  }

  constructor(instance, devMode = false) {
    this.#exports     = instance.exports
    this.#readBufPtr  = instance.exports.READ_BUFFER_PTR.value
    this.#readBufSize = instance.exports.READ_BUFFER_SIZE.value
    this.#devMode     = devMode

    const sha3  = instance.exports.DOMAIN_SHA3.value
    const shake = instance.exports.DOMAIN_SHAKE.value
    this.#validDigestLens = {
      [sha3]:  new Set([224, 256, 384, 512]),
      [shake]: new Set([128, 256]),
    }
  }

  get DOMAIN_SHA3()  { return this.#exports.DOMAIN_SHA3.value  }
  get DOMAIN_SHAKE() { return this.#exports.DOMAIN_SHAKE.value }
  get devMode()      { return this.#devMode                    }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Return a fresh Uint8Array view of WASM linear memory.
  // Must be re-read on every access since if memory.grow is ever called, the old ArrayBuffer is detached and any cached
  // view silently reads zeros.
  get #mem() {
    return new Uint8Array(this.#exports.memory.buffer)
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Initialise the sponge for a new computation.
  //
  //   digestLen   SHA3: 224 | 256 | 384 | 512
  //               SHAKE128: 128
  //               SHAKE256: 256
  //   domainByte  0x06 = SHA3 (drop-in for SHA2)
  //               0x1f = SHAKE (XOF)
  //
  // Returns `this` for chaining.
  init(digestLen, domainByte) {
    domainByte ??= this.DOMAIN_SHA3

    if (!this.#validDigestLens[domainByte]?.has(digestLen))
      throw new RangeError(
        `SHA3Sponge.init: invalid combination digestLen=${digestLen}, domainByte=0x${domainByte.toString(16).padStart(2, '0')}. ` +
        'Valid: SHA3/0x06 → {224,256,384,512}; SHAKE/0x1f → {128,256}'
      )
    this.#exports.init_state(digestLen, domainByte)

    return this
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Feed input bytes into the sponge.
  // May be called any number of times followed by a single invocation of finalize().
  // Accepts any ArrayBuffer-backed type (Uint8Array, Buffer, ArrayBuffer, etc.)
  //
  // Returns `this` for chaining.
  absorb(data) {
    const src = ArrayBuffer.isView(data)
    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    : new Uint8Array(data)

    const mem = this.#mem
    let offset = 0

    while (offset < src.length) {
      const chunkLen = Math.min(src.length - offset, this.#readBufSize)
      mem.set(src.subarray(offset, offset + chunkLen), this.#readBufPtr)
      this.#exports.absorb(this.#readBufPtr, chunkLen)
      offset += chunkLen
    }

    return this
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Finish the absorb phase by applying the relevant domain suffix and then running the final Keccak permutation.
  // Must be called exactly once, after all input has been absorbed and before the first squeeze().
  //
  // Returns `this` for chaining.
  finalize() {
    this.#exports.finalize()
    return this
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Extract `numBytes` bytes from the sponge state.
  //
  // May be called any number of times after finalize(); each call continues from where the previous one left off (the
  // position is tracked by $SQUEEZE_OFFSET in the WASM module).
  //
  // Returns a Uint8Array containing the requested bytes.
  squeeze(outLen) {
    if (outLen < 1 || outLen > this.#readBufSize) {
      throw new RangeError(
        `SHA3Sponge.squeeze: output_length = ${outLen}.  Must be between 1 and ${this.#readBufSize}.\n` +
        `            For larger output, call squeeze() multiple times.`
      )
    }

    // Since finalize() must have been called before calling squeeze(), we can reuse the read buffer as the output area
    this.#exports.squeeze(this.#readBufPtr, outLen)
    return this.#mem.slice(this.#readBufPtr, this.#readBufPtr + outLen)
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  // Instantiate the WASM module and return a SHA3Sponge ready for use.
  //
  // isProd  true  → sha3.prod[.opt].wasm  (no debug imports)
  //         false → sha3.dev[.opt].wasm   (debug module instantiated and wired in)
  // isOpt   true  → optimised binary (.opt); false → unoptimised (default: true)
  //
  // Dev mode requires `npm run build:dev` to have been run first.
  static async create(isProd = true, isOpt = true) {
    const wasi      = new WASI({ version: 'unstable' })
    const importObj = { wasi_snapshot_preview1: wasi.wasiImport }

    // If we're running in dev mode, create a debug WASM instance and wire in its exports to the main module's imports
    // so that the hexdump() function is available for logging internal state.
    if (!isProd) {
      console.log(`Loading SHA3 WASM module: ${isOpt ? '' : 'un'}optimised ${isProd ? 'production' : 'development'} build`)

      const debugWasi   = new WASI({ version: 'unstable' })
      const debugModule = await WebAssembly.instantiate(
        new Uint8Array(readFileSync(SHA3Sponge.#genDebugPath(isOpt))),
        { wasi_snapshot_preview1: debugWasi.wasiImport },
      )
      debugWasi.start(debugModule.instance)

      importObj['debug'] = {
        memory:  debugModule.instance.exports.memory,
        hexdump: debugModule.instance.exports.hexdump,
      }
      importObj['log'] = log
    }

    const wasmModule = await WebAssembly.instantiate(
      new Uint8Array(readFileSync(SHA3Sponge.#genBinPath(isProd, isOpt))),
      importObj,
    )

    return new SHA3Sponge(wasmModule.instance, !isProd)
  }
}
