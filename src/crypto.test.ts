import assert from "assert";
import CryptUtil from "./crypto";

describe("CryptUtil", () => {
  before(async () => {});

  it("md5", async () => {
    // logger.error(CryptUtil.encrypt('', 30, 37))

    const result = CryptUtil.md5("test");
    // logger.error(result)
    assert.strictEqual(result, "098f6bcd4621d373cade4e832627b4f6");
  });

  it("encrypt decrypt", async () => {
    // logger.error(CryptUtil.encrypt('', 30, 37))

    const result = CryptUtil.encrypt("test", 30, 37);
    assert.strictEqual(result, "8ama3m91m8a");
    assert.strictEqual(CryptUtil.decrypt("8ama3m91m8a", 30, 37), "test");
  });

  it("encodeBase64", async () => {
    const result = CryptUtil.encodeBase64("test:test");
    // logger.error(result)
    assert.strictEqual(result, "dGVzdDp0ZXN0");
  });

  it("aesDecryptWithEcb", async () => {
    const a = CryptUtil.aesDecryptWithEcb(
      "bj7P4lrG3TyB8KBpCDyGqQ==",
      "1234567890123456"
    );
    // console.error(a)
    assert.strictEqual(a, `haha`);
  });

  it("aesEncryptWithCbc", async () => {
    const a = CryptUtil.aesEncryptWithCbc(
      "sjukiopolkjdhgstry567uyjhdty6g45sgg",
      "gdhyesyje5463uw53"
    );
    // console.error(a)
    assert.strictEqual(
      a,
      `Dll8y2ZRfTkkNy2pMJ+Po8D/VqmGGouKpgZ9dpTy2LLbDhgEwlt3mEma9QmWvOVe`
    );
  });

  it("aesDecryptWithCbc", async () => {
    const a = CryptUtil.aesDecryptWithCbc(
      "Dll8y2ZRfTkkNy2pMJ+Po8D/VqmGGouKpgZ9dpTy2LLbDhgEwlt3mEma9QmWvOVe",
      "gdhyesyje5463uw53"
    );
    // console.error(a)
    assert.strictEqual(a, `sjukiopolkjdhgstry567uyjhdty6g45sgg`);
  });

  it("aesEncryptWithEcb", async () => {
    const a = CryptUtil.aesEncryptWithEcb("haha", "1234567890123456");
    // console.error(a)
    assert.strictEqual(a, `bj7P4lrG3TyB8KBpCDyGqQ==`);
  });

  it("rc4Encrypt rc4Decrypt", async () => {
    const a = CryptUtil.rc4Encrypt(
      "gdrthbdfgherthbe56whtynsthwhw54452hwFb",
      "123456"
    );
    // console.error(a)
    // assert.strictEqual(a, `U2FsdGVkX18zEme0tkc0SJvpu+o=`)
    const b = CryptUtil.rc4Decrypt(a, "123456");
    assert.strictEqual(b, `gdrthbdfgherthbe56whtynsthwhw54452hwFb`);
  });

  it("aes256Encrypt aes256Decrypt", async () => {
    const result = CryptUtil.aes256Encrypt(`haha`, "test");
    console.error(result);
    const b = CryptUtil.aes256Decrypt(result, "test");
    assert.strictEqual(b, `haha`);
  });

  it("aes256Decrypt", async () => {
    // echo "haha" | openssl enc -aes-256-cbc -e -a -k test
    const b = CryptUtil.aes256Decrypt(
      "U2FsdGVkX1+9fj4yETDqSRCsqIRcI0UGf8mF3vgTJ30=",
      "test"
    );
    assert.strictEqual(b, `haha\n`);
  });

  it("bcrypt", async () => {
    const hash = CryptUtil.bcrypt("111111");
    // console.error(hash)
    const result = CryptUtil.bcryptCompare("111111", hash);
    // console.error(result)
    assert.strictEqual(result, true);
  });

  it("bcryptCompare", async () => {
    const result = CryptUtil.bcryptCompare(
      "111111",
      "$2a$04$vqjZQCe9Bj4rGE0YRxudcu/IFou0HPgSmJd4v0hwCHcwshZM1V1JW"
    );
    // console.error(result)
    assert.strictEqual(result, true);
  });
});
