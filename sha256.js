const assert = require('nanoassert')

module.exports = Sha256
const SHA256_BYTES = module.exports.SHA256_BYTES = 32
const BLOCKSIZE = 64

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

function expand (a, b, c, d) {
  var a_ = ((a >>> 17) | (a << 15)) ^ ((a >>> 19) | (a << 13)) ^ (a >>> 10)
  var b_ = a_ + b
  var c_ = ((c >>> 7) | (c << 25)) ^ ((c >>> 18) | (c << 14)) ^ (c >>> 3)
  var d_ = c_ + d

  return (b_ + d_) & 0xffffffff
}

function compress (state, words) {
  // initialise registers
  var r = new Uint32Array(8)
  for (let i = 0; i < 8; i++) r[i] = state[i]

  // expand message schedule
  const w = new Uint32Array(64)
  for (let i = 0; i < 16; i++) w[i] = words[i]
  for (let i = 16; i < 64; i++) w[i] = expand(w[i - 2], w[i - 7], w[i - 15], w[i - 16])

  for (let i = 0; i < 64; i++) round(i)

  for (let i = 0; i < 8; i++) state[i] = state[i] + r[i]

  function round (n) {
    var [a, b, c, d, e, f, g, h] = r

    var ch = (e & f) ^ (~e & g)
    var maj = (a & b) ^ (a & c) ^ (b & c)

    var bigSig0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))
    var bigSig1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))

    var T1 = (h + ch + bigSig1 + w[n] + K[n]) & 0xffffffff
    var T2 = (bigSig0 + maj) & 0xffffffff

    r[7] = r[6]
    r[6] = r[5]
    r[5] = r[4]
    r[4] = r[3] + T1
    r[3] = r[2]
    r[2] = r[1]
    r[1] = r[0]
    r[0] = T1 + T2
  }
}

function Sha256 () {
  if (!(this instanceof Sha256)) return new Sha256()

  this.buffer = new ArrayBuffer(64)
  this.bytesRead = 0
  this.pos = 0
  this.digestLength = SHA256_BYTES
  this.finalised = false

  this.load = new Uint8Array(this.buffer)
  this.words = new Uint32Array(this.buffer)
  this.state = new Uint32Array([
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
  ])

  return this
}

Sha256.prototype.update = function (input) {
  assert(this.finalised === false, 'Hash instance finalised')

  var len = input.byteLength

  var start = this.bytesRead & 0x3f
  this.bytesRead += len

  while (len > 0) {
    loadReverseEndian(this.load, input, BLOCKSIZE - this.pos, this.pos)
    len -= BLOCKSIZE - start
    if (len < 0) break

    this.pos = 0
    compress(this.state, this.words)
  }

  this.pos = this.bytesRead & 0x3f

  return this
}

Sha256.prototype.digest = function (input) {
  assert(this.finalised === false, 'Hash instance finalised')

  this.finalised = true
  this.words[this.pos >> 2] = this.words[this.pos >> 2] | (0x80 << ((3 - this.pos & 3) << 3))

  if (this.pos > 0x38) {
    this.words.fill(0, ((this.pos >>> 2) + 1) << 2)
    compress(this.state, this.words)
    this.pos = 0
  }

  this.words.fill(0, ((this.pos >>> 2) + 1) << 2)

  const view = new DataView(this.buffer)
  view.setUint32(56, this.bytesRead / 2 ** 29, true)
  view.setUint32(60, this.bytesRead << 3, true)

  compress(this.state, this.words)

  return this.state.buffer
}

function signedInt (n) {
  return n < 0 ? 2 ** 32 + n : n
}

function loadReverseEndian (out, input, len, offset) {
  console.log(arguments)
  for (let i = 0; i < Math.min(input.byteLength, len); i += 4) {
    for (let j = 3; j >= 0; j--) {
      out[offset + i + 3 - j] = input[i + j]
    }
  }
}
