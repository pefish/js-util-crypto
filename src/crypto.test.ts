import assert from "assert"
import CryptUtil from './crypto'

describe('CryptUtil', () => {


  before(async () => {

  })

  it('md5', async () => {
    try {
      // logger.error(CryptUtil.encrypt('', 30, 37))

      const result = CryptUtil.md5('test')
      // logger.error(result)
      assert.strictEqual(result, '098f6bcd4621d373cade4e832627b4f6')
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('encrypt decrypt', async () => {
    try {
      // logger.error(CryptUtil.encrypt('', 30, 37))

      const result = CryptUtil.encrypt('test', 30, 37)
      assert.strictEqual(result, '8ama3m91m8a')
      assert.strictEqual(CryptUtil.decrypt('8ama3m91m8a', 30, 37), 'test')
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('encodeBase64', async () => {
    try {
      const result = CryptUtil.encodeBase64('test:test')
      // logger.error(result)
      assert.strictEqual(result, 'dGVzdDp0ZXN0')
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('aesEncrypt', async () => {
    try {
      // logger.error(CryptUtil.aesEncrypt('73e9782662cb45324ed50dd062978699fe6d268ea23ac1f5b502bf9c8800c995', 'test'))

      const a = CryptUtil.aesEncrypt('da2a48a1b9fbade07552281143814b3cd7ba4b53a7de5241439417b9bb540e229c45a30b0ce32174aaccc80072df7cbdff24f0c0ae327cd5170d1f276b890173', 'test')
      // logger.error(a)
      assert.strictEqual(a, '8930fd05e94e1d306550b433c745324ce914c26f9dc22d50ffbb14162785e5c91c419f066f6a8d6ee6392b73e2182c638da5072dad89690652e86d8a964ed076b7ae4ee650d0bc138cb1137e37739d159060dccf2eb87ffce1b5df757575cb3b35fd682ea3e31502b7734c0d61cb3f4f06efda897e0f4af3f21377a372f4255623efa59686f5d657e78bccac3cec9271')
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('aesDecrypt', async () => {
    try {
      const a = CryptUtil.aesDecrypt('8930fd05e94e1d306550b433c745324ce914c26f9dc22d50ffbb14162785e5c91c419f066f6a8d6ee6392b73e2182c638da5072dad89690652e86d8a964ed076b7ae4ee650d0bc138cb1137e37739d159060dccf2eb87ffce1b5df757575cb3b35fd682ea3e31502b7734c0d61cb3f4f06efda897e0f4af3f21377a372f4255623efa59686f5d657e78bccac3cec9271', 'test')
      // logger.error(a)
      assert.strictEqual(a, 'da2a48a1b9fbade07552281143814b3cd7ba4b53a7de5241439417b9bb540e229c45a30b0ce32174aaccc80072df7cbdff24f0c0ae327cd5170d1f276b890173')
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('aesDecryptWithEcb', async () => {
    try {
      const a = CryptUtil.aesDecryptWithEcb(
        'bj7P4lrG3TyB8KBpCDyGqQ==',
        '1234567890123456'
      )
      // console.error(a)
      assert.strictEqual(a, `haha`)
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('aesEncryptWithCbc', async () => {
    try {
      const a = CryptUtil.aesEncryptWithCbc(
        'sjukiopolkjdhgstry567uyjhdty6g45sgg',
        'gdhyesyje5463uw53'
      )
      // console.error(a)
      assert.strictEqual(a, `Dll8y2ZRfTkkNy2pMJ+Po8D/VqmGGouKpgZ9dpTy2LLbDhgEwlt3mEma9QmWvOVe`)
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('aesDecryptWithCbc', async () => {
    try {
      const a = CryptUtil.aesDecryptWithCbc(
        'Dll8y2ZRfTkkNy2pMJ+Po8D/VqmGGouKpgZ9dpTy2LLbDhgEwlt3mEma9QmWvOVe',
        'gdhyesyje5463uw53'
      )
      // console.error(a)
      assert.strictEqual(a, `sjukiopolkjdhgstry567uyjhdty6g45sgg`)
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('aesEncryptWithEcb', async () => {
    try {
      const a = CryptUtil.aesEncryptWithEcb('haha', '1234567890123456')
      // console.error(a)
      assert.strictEqual(a, `bj7P4lrG3TyB8KBpCDyGqQ==`)
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('rc4Encrypt rc4Decrypt', async () => {
    try {
      const a = CryptUtil.rc4Encrypt('gdrthbdfgherthbe56whtynsthwhw54452hwFb', '123456')
      // console.error(a)
      // assert.strictEqual(a, `U2FsdGVkX18zEme0tkc0SJvpu+o=`)
      const b = CryptUtil.rc4Decrypt(a, '123456')
      assert.strictEqual(b, `gdrthbdfgherthbe56whtynsthwhw54452hwFb`)
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('aes256Encrypt aes256Decrypt', async () => {
    try {
      const result = CryptUtil.aes256Encrypt(`haha`, 'test')
      console.error(result)
      const b = CryptUtil.aes256Decrypt(result, 'test')
      assert.strictEqual(b, `haha`)
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('aes256Decrypt', async () => {
    try {
      // echo "haha" | openssl enc -aes-256-cbc -e -a -k test
      const b = CryptUtil.aes256Decrypt("U2FsdGVkX1+9fj4yETDqSRCsqIRcI0UGf8mF3vgTJ30=", 'test')
      assert.strictEqual(b, `haha\n`)
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('bcrypt', async () => {
    try {
      const hash = CryptUtil.bcrypt('111111')
      // console.error(hash)
      const result = CryptUtil.bcryptCompare('111111', hash)
      // console.error(result)
      assert.strictEqual(result, true)
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })

  it('bcryptCompare', async () => {
    try {
      const result = CryptUtil.bcryptCompare('111111', '$2a$04$vqjZQCe9Bj4rGE0YRxudcu/IFou0HPgSmJd4v0hwCHcwshZM1V1JW')
      // console.error(result)
      assert.strictEqual(result, true)
    } catch (err) {
      console.error(err)
      assert.throws(() => {}, err)
    }
  })
})
