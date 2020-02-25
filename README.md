# HD_Keychain

![npm (scoped)](https://img.shields.io/npm/v/@digit-map/hd-keychain)

HD Keychain for HD wallets comply with BIP32, BIP39

## Usage

Test cases are the best examples

```js
describe('hd keychain', () => {
  const sk = '50042f5964c94d1ccfd901a7d780d81a79acdbd7463859376d8ab706d7a29d60'
  const chainCode = '20d9541c0ac213e693dc4181001dad78a61c09c18ee49e07ac7299269f0ee7a8'
  test('init', () => {
    const keychain = new HDKeychain(Buffer.from(sk, 'hex'), Buffer.from(chainCode, 'hex'))
    expect(Buffer.from(keychain.privKey).toString('hex')).toBe(sk)
    expect(Buffer.from(keychain.chainCode).toString('hex')).toBe(chainCode)
    expect(keychain.index).toBe(0)
    expect(keychain.depth).toBe(0)
  })

  test('derive the second hardened child', () => {
    const keychain = new HDKeychain(Buffer.from(sk, 'hex'), Buffer.from(chainCode, 'hex'))
    const child = keychain.deriveChild(1, true)
    expect(Buffer.from(child.privKey).toString('hex')).toBe(
      '666b9474a10a9f17249fadf45d2debb7ae3344018937bc9a89fb6b54450274f6',
    )
    expect(Buffer.from(child.pubKey).toString('hex')).toBe(
      '023cc402755004c3402a5ca30784548d01d97385703f0f2101b9ceee2a24886237',
    )
    expect(child.fingerprint).toBe(2411857829)
    expect(child.index).toBe(1)
    expect(child.depth).toBe(1)
  })

  test('derive the second normal child', () => {
    const keychain = new HDKeychain(Buffer.from(sk, 'hex'), Buffer.from(chainCode, 'hex'))
    const child = keychain.deriveChild(1, false)
    expect(Buffer.from(child.privKey).toString('hex')).toBe(
      '113a66642c476af1540f9607d307620832e488b1ce39ab3360e5ad4655dffb46',
    )
    expect(Buffer.from(child.pubKey).toString('hex')).toBe(
      '0228c1521e32351327dcc27fd37c95b1a7052bcad315b08fff48935ba380b518c8',
    )
    expect(child.fingerprint).toBe(1328773167)
    expect(child.index).toBe(1)
    expect(child.depth).toBe(1)
  })

  test('derive from root path', () => {
    const keychain = new HDKeychain(Buffer.from(sk, 'hex'), Buffer.from(chainCode, 'hex'))
    const child = keychain.deriveFromPath('m')
    expect(child).toEqual(child)
  })

  test("derive from path m/1'/2/3", () => {
    const keychain = new HDKeychain(Buffer.from(sk, 'hex'), Buffer.from(chainCode, 'hex'))
    const child = keychain.deriveFromPath(`m/1'/2/3`)

    expect(Buffer.from(child.privKey).toString('hex')).toBe(
      'e7042a908f3ec1ad12f01fbc209d714c63180f907726db2692b1347901405b0c',
    )
    expect(Buffer.from(child.pubKey).toString('hex')).toBe(
      '034aa6838267c3835ec714436eaf1962535be49e1d337e843fcb8b7cef5eddedc4',
    )
    expect(child.fingerprint).toBe(849527305)
    expect(child.index).toBe(3)
    expect(child.depth).toBe(3)
  })

  test('from public key', () => {
    const pk = '034aa6838267c3835ec714436eaf1962535be49e1d337e843fcb8b7cef5eddedc4'
    const chainCode = '23448739bdcd29856ecd04ed8dc08293f434ebd014a48f66ecde3ca014ee398e'
    const keychain = HDKeychain.fromPubKey(Buffer.from(pk, 'hex'), Buffer.from(chainCode, 'hex'), `m/1'/2/3`)
    const child = keychain.deriveChild(0, false)
    expect(Buffer.from(child.privKey).toString('hex')).toBe('')
    expect(Buffer.from(child.pubKey).toString('hex')).toBe(
      '033ab52b1ad3fe04d518891322388ee4e3f4f07be40d4c9c4cc06162781e46e1f5',
    )
    expect(child.fingerprint).toBe(3508961652)
    expect(child.index).toBe(0)
    expect(child.depth).toBe(4)
  })

  test('invalid private key should throw an error', () => {
    const sk = '50042f5964c94d1ccfd901a7d780d81a79acdbd7463859376d8ab706d7a29d6'
    const chainCode = '20d9541c0ac213e693dc4181001dad78a61c09c18ee49e07ac7299269f0ee7a8'

    expect(() => {
      new HDKeychain(Buffer.from(sk, 'hex'), Buffer.from(chainCode, 'hex'))
    }).toThrow()
  })
})
```
