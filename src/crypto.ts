import Bcrypt from "bcrypt";
import crypto from "crypto";
import CryptoJs from "crypto-js";

declare global {
  namespace NodeJS {
    interface Global {
      logger: any;
    }
  }
}

/**
 * 加密工具类
 */
export default class CryptUtil {
  /**
   * 解密
   * @param str
   * @param xor
   * @param hex
   * @returns {string}
   */
  static encrypt(str: string, xor: number, hex: number) {
    let resultList = [];
    hex = hex <= 25 ? hex : hex % 25;
    for (let i = 0; i < str.length; i++) {
      // 提取字符串每个字符的ascll码
      let charCode = str.charCodeAt(i);
      // 进行异或加密
      charCode = charCode ^ xor;
      // 异或加密后的字符转成 hex 位数的字符串
      resultList.push(charCode.toString(hex));
    }

    let splitStr = String.fromCharCode(hex + 97);
    return resultList.join(splitStr);
  }

  /**
   * 加密
   * @param str
   * @param xor
   * @param hex
   * @returns {string}
   */
  static decrypt(str: string, xor: number, hex: number) {
    let strCharList = [],
      resultList = [];
    hex = hex <= 25 ? hex : hex % 25;
    // 解析出分割字符
    let splitStr = String.fromCharCode(hex + 97);
    // 分割出加密字符串的加密后的每个字符
    strCharList = str.split(splitStr);
    for (let i = 0; i < strCharList.length; i++) {
      // 将加密后的每个字符转成加密后的ascll码
      let charCode = parseInt(strCharList[i], hex);
      // 异或解密出原字符的ascll码
      charCode = charCode ^ xor;
      let strChar = String.fromCharCode(charCode);
      resultList.push(strChar);
    }
    return resultList.join("");
  }

  /**
   * sha256加密
   * @param str
   * @returns {buffer}
   */
  static sha256ToBuffer(str: string) {
    return crypto.createHash("sha256").update(str).digest();
  }

  /**
   * sha256加密
   * @param str
   * @returns {string}
   */
  static sha256ToHex(str: string) {
    return crypto.createHash("sha256").update(str).digest("hex");
  }

  static sha1ToBuffer(str: string) {
    return crypto.createHash("sha1").update(str).digest();
  }

  static sha1ToHex(str: string) {
    return crypto.createHash("sha1").update(str).digest("hex");
  }

  /**
   * hmacSha256加密
   * @param str
   * @param secret
   * @returns {buffer}
   */
  static hmacSha256ToBuffer(str: string, secret: string) {
    return crypto.createHmac("sha256", secret).update(str).digest();
  }

  /**
   * hmacSha256加密
   * @param str
   * @param secret
   * @returns {string}
   */
  static hmacSha256ToHex(str: string, secret: string) {
    return crypto.createHmac("sha256", secret).update(str).digest("hex");
  }

  static hmacSha1ToBuffer(str: string, secret: string) {
    return crypto.createHmac("sha1", secret).update(str).digest();
  }

  static hmacSha1ToHex(str: string, secret: string) {
    return crypto.createHmac("sha1", secret).update(str).digest("hex");
  }

  /**
   * base64编码
   * @param str
   */
  static encodeBase64(str: string) {
    return Buffer.from(str).toString("base64");
  }

  /**
   * base64解码
   * @param base64Str
   */
  static decodeBase64(base64Str: string) {
    return Buffer.from(base64Str, "base64").toString();
  }

  /**
   * url编码
   * @param str
   * @param encoding
   * @returns {*}
   */
  static encodeUri(str: string, encoding: string = "utf8") {
    const urlencode = require("urlencode");
    return urlencode(str, encoding);
  }

  /**
   * url解码
   * @param uri
   * @param encoding {string} default utf8
   * @returns {*}
   */
  static decodeUri(uri: string, encoding: string = "utf8") {
    const urlencode = require("urlencode");
    return urlencode.decode(uri, encoding);
  }

  /**
   * md5加密
   * @param str
   * @returns {string}
   */
  static md5(str: string) {
    return crypto.createHash("md5").update(str).digest("hex");
  }

  static aesEncryptWithEcb(data: string, secretKey: string): string {
    const length = secretKey.length;
    if (length <= 16) {
      secretKey = secretKey.padStart(16, `0`);
    } else if (length <= 24) {
      secretKey = secretKey.padStart(24, `0`);
    } else if (length <= 32) {
      secretKey = secretKey.padStart(32, `0`);
    } else {
      throw new Error(`length of secret key error`);
    }

    const cipherChunks = [];
    const cipher = crypto.createCipheriv(
      `aes-${secretKey.length * 8}-ecb`,
      secretKey,
      ``
    );
    cipher.setAutoPadding(true);

    cipherChunks.push(cipher.update(data, "utf8", "base64"));
    cipherChunks.push(cipher.final("base64"));

    return cipherChunks.join("");
  }

  static aesEncryptWithCbc(data: string, secretKey: string): string {
    const length = secretKey.length;
    if (length <= 16) {
      secretKey = secretKey.padStart(16, `0`);
    } else if (length <= 24) {
      secretKey = secretKey.padStart(24, `0`);
    } else if (length <= 32) {
      secretKey = secretKey.padStart(32, `0`);
    } else {
      throw new Error(`length of secret key error`);
    }

    const cipherChunks = [];
    const cipher = crypto.createCipheriv(
      `aes-${secretKey.length * 8}-cbc`,
      secretKey,
      Buffer.alloc(16)
    );
    cipher.setAutoPadding(true);

    cipherChunks.push(cipher.update(data, "utf8", "base64"));
    cipherChunks.push(cipher.final("base64"));

    return cipherChunks.join("");
  }

  // echo "U2FsdGVkX182JKRVOqZupdjBvUm5Z72gjF2h1FMA5q0=" | openssl enc -d -aes-256-cbc -k test -a
  static aes256Encrypt(data: string, secretKey: string): string {
    return CryptoJs.AES.encrypt(data, secretKey).toString();
  }

  // echo "haha" | openssl enc -aes-256-cbc -e -a -k test  会多加密一个回车符
  static aes256Decrypt(data: string, secretKey: string): string {
    const result = CryptoJs.enc.Utf8.stringify(
      CryptoJs.AES.decrypt(data, secretKey)
    );
    if (!result) {
      throw new Error(`secret error`);
    }
    return result;
  }

  // 每次加密的结果不一样
  static rc4Encrypt(data: string, secretKey: string): string {
    return CryptoJs.RC4.encrypt(data, secretKey).toString();
  }

  static rc4Decrypt(data: string, secretKey: string): string {
    return CryptoJs.enc.Utf8.stringify(CryptoJs.RC4.decrypt(data, secretKey));
  }

  static aesDecryptWithEcb(data: string, secretKey: string): string {
    const length = secretKey.length;
    if (length <= 16) {
      secretKey = secretKey.padStart(16, `0`);
    } else if (length <= 24) {
      secretKey = secretKey.padStart(24, `0`);
    } else if (length <= 32) {
      secretKey = secretKey.padStart(32, `0`);
    } else {
      throw new Error(`length of secret key error`);
    }

    const cipherChunks = [];
    const decipher = crypto.createDecipheriv(
      `aes-${secretKey.length * 8}-ecb`,
      secretKey,
      ``
    );
    decipher.setAutoPadding(true);

    cipherChunks.push(decipher.update(data, "base64", "utf8"));
    cipherChunks.push(decipher.final("utf8"));

    return cipherChunks.join("");
  }

  static aesDecryptWithCbc(data: string, secretKey: string): string {
    const length = secretKey.length;
    if (length <= 16) {
      secretKey = secretKey.padStart(16, `0`);
    } else if (length <= 24) {
      secretKey = secretKey.padStart(24, `0`);
    } else if (length <= 32) {
      secretKey = secretKey.padStart(32, `0`);
    } else {
      throw new Error(`length of secret key error`);
    }

    const cipherChunks = [];
    const decipher = crypto.createDecipheriv(
      `aes-${secretKey.length * 8}-cbc`,
      secretKey,
      Buffer.alloc(16)
    );
    decipher.setAutoPadding(true);

    cipherChunks.push(decipher.update(data, "base64", "utf8"));
    cipherChunks.push(decipher.final("utf8"));

    return cipherChunks.join("");
  }

  static bcrypt(password: string, saltRounds: number = 4): string {
    return Bcrypt.hashSync(password, saltRounds);
  }

  static bcryptCompare(password: string, hashedPassword: string): boolean {
    return Bcrypt.compareSync(password, hashedPassword);
  }
}
