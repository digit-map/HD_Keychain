import crypto from 'crypto'
import { ec as EC } from 'elliptic'
import BN from 'bn.js'

const EMPTY_BUFFER = new Uint8Array()
const HARDENED_INDEX_BASE = 0x80000000

const ec = new EC('secp256k1')

export const privKeyToPubKey = (privKey: Uint8Array) => {
  if (privKey.length !== 32) {
    throw new Error('Invalid private key')
  }

  return Buffer.from(ec.keyFromPrivate(privKey).getPublic(true, 'hex'), 'hex')
}

export const hash160 = (data: Uint8Array) => {
  const sha256 = crypto
    .createHash('sha256')
    .update(data)
    .digest()
  const res = crypto
    .createHash('ripemd160')
    .update(sha256)
    .digest()
  return res
}

export const derivePrivKey = (privKey: Uint8Array, il: Uint8Array) => {
  const result = new BN(il)
  result.iadd(new BN(privKey))
  if (result.cmp(ec.curve.n) >= 0) {
    result.isub(ec.curve.n)
  }
  return result.toArrayLike(Buffer, 'be', 32)
}

export const derivePubKey = (pubKey: Uint8Array, il: Uint8Array) => {
  const x = new BN(pubKey.slice(1)).toRed(ec.curve.red)
  // fixed to bn.js 4.11.8
  let y = x
    .redSqr()
    .redIMul(x)
    .redIAdd(ec.curve.b)
    .redSqrt()
  if ((pubKey[0] === 0x03) !== y.isOdd()) {
    y = y.redNeg()
  }
  const point = ec.curve.g.mul(new BN(il)).add({ x, y })
  return Buffer.from(point.encode(true, true))
}

export class HDKeychain {
  privKey: Uint8Array = EMPTY_BUFFER
  pubKey: Uint8Array = EMPTY_BUFFER
  chainCode: Uint8Array = EMPTY_BUFFER
  index: number = 0
  depth: number = 0
  identifier: Uint8Array = EMPTY_BUFFER
  fingerprint: number = 0
  parentFingerprint: number = 0
  public static fromPubKey = (pubKey: Uint8Array, chainCode: Uint8Array, path: string): HDKeychain => {
    const keychain = new HDKeychain(EMPTY_BUFFER, chainCode)
    keychain.pubKey = pubKey
    keychain.calculateFingerprint()

    const pathComponents = path.split('/')
    keychain.depth = pathComponents.length - 1
    keychain.index = parseInt(pathComponents[pathComponents.length - 1], 10)

    return keychain
  }

  constructor(privKey: Uint8Array, chainCode: Uint8Array) {
    this.privKey = privKey
    this.chainCode = chainCode
    if (!this.isNeutered()) {
      this.pubKey = privKeyToPubKey(this.privKey)
    }
  }

  public isNeutered = () => {
    return this.privKey === EMPTY_BUFFER
  }

  public calculateFingerprint = () => {
    this.fingerprint = hash160(this.pubKey)
      .slice(0, 4)
      .readUInt32BE(0)
  }

  public deriveChild = (index: number = 0, hardened: boolean = false) => {
    let data = EMPTY_BUFFER
    const indexBuffer = Buffer.allocUnsafe(4)
    if (hardened) {
      const privKey = Buffer.concat([Buffer.alloc(1, 0), this.privKey])
      indexBuffer.writeUInt32BE(index + HARDENED_INDEX_BASE, 0)
      data = Buffer.concat([privKey, indexBuffer])
    } else {
      indexBuffer.writeUInt32BE(index, 0)
      data = Buffer.concat([this.pubKey, indexBuffer])
    }

    const i = crypto
      .createHmac('sha512', this.chainCode)
      .update(data)
      .digest()
    const il = i.slice(0, 32)
    const ir = i.slice(32)

    let child
    if (this.isNeutered()) {
      child = new HDKeychain(EMPTY_BUFFER, ir)
      child.pubKey = derivePubKey(this.pubKey, il)
      child.calculateFingerprint()
    } else {
      const privKey = derivePrivKey(this.privKey, il)
      child = new HDKeychain(privKey, ir)
      child.calculateFingerprint()
    }

    child.index = index
    child.depth = this.depth + 1
    child.parentFingerprint = this.fingerprint
    return child
  }

  public deriveFromPath = (path: string) => {
    const master = [`m`, `/`, ``]
    if (master.includes(path)) {
      return this
    }

    let derived: HDKeychain = this
    let entries = path.split('/')
    if (entries[0] === `m`) {
      entries = entries.slice(1)
    }
    entries.forEach(c => {
      const childIndex = parseInt(c, 10)
      const hardened = c.length > 1 && c.endsWith(`'`)
      derived = derived.deriveChild(childIndex, hardened)
    })
    return derived
  }
}

export default HDKeychain
