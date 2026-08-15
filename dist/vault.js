// src/encoding.ts
function bytesToBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}
var BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;
function base64ToBytes(base64) {
  if (typeof Buffer !== "undefined") {
    if (base64.length % 4 !== 0 || !BASE64_PATTERN.test(base64)) {
      throw new Error("Invalid base64 input");
    }
    return new Uint8Array(Buffer.from(base64, "base64"));
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// src/aes-gcm.ts
function toArrayBuffer(bytes) {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  );
}
var IV_LENGTH = 12;
function encodeAad(additionalData) {
  if (additionalData === void 0) return void 0;
  if (typeof additionalData === "string") {
    return toArrayBuffer(new TextEncoder().encode(additionalData));
  }
  return toArrayBuffer(additionalData);
}
function assertIvLength(iv) {
  if (iv.length !== IV_LENGTH) {
    throw new Error(`Invalid AES-GCM IV length: ${iv.length}`);
  }
}
async function encryptUtf8(plaintext, key, options) {
  const iv = new Uint8Array(IV_LENGTH);
  crypto.getRandomValues(iv);
  const additionalData = encodeAad(options?.additionalData);
  const cipherBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      ...additionalData ? { additionalData } : {}
    },
    key,
    new TextEncoder().encode(plaintext)
  );
  return {
    ciphertext: bytesToBase64(new Uint8Array(cipherBuffer)),
    iv: bytesToBase64(iv)
  };
}
async function decryptUtf8(payload, key, options) {
  const iv = base64ToBytes(payload.iv);
  assertIvLength(iv);
  const ciphertext = base64ToBytes(payload.ciphertext);
  const additionalData = encodeAad(options?.additionalData);
  const plainBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      ...additionalData ? { additionalData } : {}
    },
    key,
    toArrayBuffer(ciphertext)
  );
  return new TextDecoder().decode(plainBuffer);
}

// src/argon2.ts
import { argon2id } from "@noble/hashes/argon2";

// src/passphrase.ts
var PASSPHRASE_HARD_MAX_BYTES = 1024;
function normalizePassphrase(passphrase) {
  return passphrase.normalize("NFC");
}
function preparePassphraseForKdf(passphrase) {
  const normalized = normalizePassphrase(passphrase);
  const byteLength = new TextEncoder().encode(normalized).byteLength;
  if (byteLength > PASSPHRASE_HARD_MAX_BYTES) {
    throw new Error("Passphrase is too long");
  }
  return normalized;
}

// src/argon2.ts
var ARGON2_MEMORY_KIB = 65536;
var ARGON2_ITERATIONS = 3;
var ARGON2_PARALLELISM = 4;
var ARGON2_KEY_LENGTH = 32;
var ARGON2_SALT_LENGTH = 16;
function toArrayBuffer2(bytes) {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  );
}
function deriveStretchedKeyBytes(password, salt) {
  const passwordBytes = new TextEncoder().encode(
    preparePassphraseForKdf(password)
  );
  return new Uint8Array(
    argon2id(passwordBytes, salt, {
      t: ARGON2_ITERATIONS,
      m: ARGON2_MEMORY_KIB,
      p: ARGON2_PARALLELISM,
      dkLen: ARGON2_KEY_LENGTH
    })
  );
}
async function deriveVaultKeyArgon2(password, salt) {
  const keyBytes = deriveStretchedKeyBytes(password, salt);
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer2(keyBytes),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
function randomSaltArgon2() {
  const salt = new Uint8Array(ARGON2_SALT_LENGTH);
  crypto.getRandomValues(salt);
  return salt;
}
function serializeArgon2Salt(salt) {
  return bytesToBase64(salt);
}
function deserializeArgon2Salt(encoded) {
  const salt = base64ToBytes(encoded);
  if (salt.length !== ARGON2_SALT_LENGTH) {
    throw new Error(`Invalid Argon2 salt length: ${salt.length}`);
  }
  return salt;
}

// src/hkdf.ts
var HKDF_INFO_AUTH = "heirvault-auth-v1";
var HKDF_INFO_VAULT_KEK = "heirvault-vault-kek-v1";
function toArrayBuffer3(bytes) {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  );
}
async function hkdfExpand(ikm, info, length = 32) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer3(ikm),
    "HKDF",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new ArrayBuffer(0),
      info: toArrayBuffer3(new TextEncoder().encode(info))
    },
    baseKey,
    length * 8
  );
  return new Uint8Array(bits);
}
async function deriveOpaquePassword(stretchedKey) {
  const authBytes = await hkdfExpand(stretchedKey, HKDF_INFO_AUTH);
  return bytesToBase64(authBytes);
}
async function deriveVaultKek(stretchedKey) {
  const kekBytes = await hkdfExpand(stretchedKey, HKDF_INFO_VAULT_KEK);
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer3(kekBytes),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// src/vault.ts
function toArrayBuffer4(bytes) {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  );
}
async function generateVaultDek() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt"
  ]);
}
async function exportDekRaw(dek) {
  const raw = await crypto.subtle.exportKey("raw", dek);
  return new Uint8Array(raw);
}
async function importDekFromRaw(raw, extractable = true) {
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer4(raw),
    { name: "AES-GCM", length: 256 },
    extractable,
    ["encrypt", "decrypt"]
  );
}
async function wrapDekWithKek(dek, kek, options) {
  const raw = await exportDekRaw(dek);
  return encryptUtf8(bytesToBase64(raw), kek, options);
}
async function unwrapDekWithKek(wrap, kek, options) {
  const rawB64 = await decryptUtf8(wrap, kek, options);
  return importDekFromRaw(base64ToBytes(rawB64));
}
async function createVaultCryptoV2(passphrase, options) {
  const accountSalt = options?.accountSaltB64 ? deserializeArgon2Salt(options.accountSaltB64) : randomSaltArgon2();
  const stretchedKey = deriveStretchedKeyBytes(passphrase, accountSalt);
  const vaultKek = await deriveVaultKek(stretchedKey);
  const opaquePassword = await deriveOpaquePassword(stretchedKey);
  const dek = await generateVaultDek();
  const wrap = await wrapDekWithKek(dek, vaultKek);
  const vaultCrypto = {
    version: 2,
    accountSalt: serializeArgon2Salt(accountSalt),
    kdf: "argon2id",
    memory: ARGON2_MEMORY_KIB,
    iterations: ARGON2_ITERATIONS,
    parallelism: ARGON2_PARALLELISM,
    vaultKeyWrap: {
      ciphertext: wrap.ciphertext,
      iv: wrap.iv
    }
  };
  return {
    accountSalt,
    stretchedKey,
    vaultKek,
    opaquePassword,
    vaultCrypto,
    dek
  };
}
function assertSupportedArgon2Params(cryptoBlob) {
  if (cryptoBlob.kdf !== "argon2id") {
    throw new Error("Unsupported vault crypto KDF");
  }
  if (cryptoBlob.memory !== void 0 && cryptoBlob.memory !== ARGON2_MEMORY_KIB) {
    throw new Error("Unsupported Argon2 memory parameter");
  }
  if (cryptoBlob.iterations !== void 0 && cryptoBlob.iterations !== ARGON2_ITERATIONS) {
    throw new Error("Unsupported Argon2 iterations parameter");
  }
  if (cryptoBlob.parallelism !== void 0 && cryptoBlob.parallelism !== ARGON2_PARALLELISM) {
    throw new Error("Unsupported Argon2 parallelism parameter");
  }
}
async function unlockVaultCryptoV2(passphrase, cryptoBlob) {
  assertSupportedArgon2Params(cryptoBlob);
  const accountSalt = deserializeArgon2Salt(cryptoBlob.accountSalt);
  const stretchedKey = deriveStretchedKeyBytes(passphrase, accountSalt);
  const vaultKek = await deriveVaultKek(stretchedKey);
  const opaquePassword = await deriveOpaquePassword(stretchedKey);
  const dek = await unwrapDekWithKek(cryptoBlob.vaultKeyWrap, vaultKek);
  return { dek, opaquePassword, vaultKek };
}
async function deriveOpaquePasswordFromPassphrase(passphrase, accountSaltB64) {
  const accountSalt = deserializeArgon2Salt(accountSaltB64);
  const stretchedKey = deriveStretchedKeyBytes(passphrase, accountSalt);
  return deriveOpaquePassword(stretchedKey);
}
async function rewrapDekWithPassphrase(dek, newPassphrase) {
  const accountSalt = randomSaltArgon2();
  const stretchedKey = deriveStretchedKeyBytes(newPassphrase, accountSalt);
  const vaultKek = await deriveVaultKek(stretchedKey);
  const opaquePassword = await deriveOpaquePassword(stretchedKey);
  const wrap = await wrapDekWithKek(dek, vaultKek);
  const vaultCrypto = {
    version: 2,
    accountSalt: serializeArgon2Salt(accountSalt),
    kdf: "argon2id",
    memory: ARGON2_MEMORY_KIB,
    iterations: ARGON2_ITERATIONS,
    parallelism: ARGON2_PARALLELISM,
    vaultKeyWrap: {
      ciphertext: wrap.ciphertext,
      iv: wrap.iv
    }
  };
  return {
    accountSalt,
    stretchedKey,
    vaultKek,
    opaquePassword,
    vaultCrypto,
    dek
  };
}
function parseVaultCrypto(encryptedVaultKey) {
  const parsed = JSON.parse(encryptedVaultKey);
  if (typeof parsed === "object" && parsed !== null && "version" in parsed && parsed.version === 2 && "vaultKeyWrap" in parsed && "accountSalt" in parsed) {
    return parsed;
  }
  throw new Error("Unsupported vault crypto format");
}
function serializeVaultCryptoV2(crypto2) {
  return JSON.stringify(crypto2);
}
function serializeKeyWrap(wrap) {
  return JSON.stringify(wrap);
}
function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}
function parseKeyWrap(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Invalid key wrap JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Invalid key wrap shape");
  }
  const wrap = parsed;
  if (!isNonEmptyString(wrap.salt) || typeof wrap.iterations !== "number" || !Number.isFinite(wrap.iterations) || wrap.kdf !== "argon2id" || !isNonEmptyString(wrap.ciphertext) || !isNonEmptyString(wrap.iv)) {
    throw new Error("Invalid key wrap fields");
  }
  if (wrap.memory !== void 0 && (typeof wrap.memory !== "number" || !Number.isFinite(wrap.memory))) {
    throw new Error("Invalid key wrap memory");
  }
  if (wrap.parallelism !== void 0 && (typeof wrap.parallelism !== "number" || !Number.isFinite(wrap.parallelism))) {
    throw new Error("Invalid key wrap parallelism");
  }
  return {
    salt: wrap.salt,
    iterations: wrap.iterations,
    kdf: "argon2id",
    memory: wrap.memory,
    parallelism: wrap.parallelism,
    ciphertext: wrap.ciphertext,
    iv: wrap.iv
  };
}
async function wrapDekWithSecret(dek, secret) {
  const salt = randomSaltArgon2();
  const kek = await deriveVaultKeyArgon2(secret, salt);
  const payload = await wrapDekWithKek(dek, kek);
  return {
    salt: serializeArgon2Salt(salt),
    iterations: ARGON2_ITERATIONS,
    kdf: "argon2id",
    memory: ARGON2_MEMORY_KIB,
    parallelism: ARGON2_PARALLELISM,
    ciphertext: payload.ciphertext,
    iv: payload.iv
  };
}
async function unwrapDekWithSecret(wrap, secret) {
  assertSupportedArgon2Params(wrap);
  const kek = await deriveVaultKeyArgon2(
    secret,
    deserializeArgon2Salt(wrap.salt)
  );
  return unwrapDekWithKek({ ciphertext: wrap.ciphertext, iv: wrap.iv }, kek);
}
async function encryptVaultSecret(plaintext, vaultKey) {
  return encryptUtf8(plaintext, vaultKey);
}
async function decryptVaultSecret(payload, vaultKey) {
  return decryptUtf8(payload, vaultKey);
}
export {
  assertSupportedArgon2Params,
  createVaultCryptoV2,
  decryptVaultSecret,
  deriveOpaquePasswordFromPassphrase,
  encryptVaultSecret,
  exportDekRaw,
  generateVaultDek,
  importDekFromRaw,
  parseKeyWrap,
  parseVaultCrypto,
  rewrapDekWithPassphrase,
  serializeKeyWrap,
  serializeVaultCryptoV2,
  unlockVaultCryptoV2,
  unwrapDekWithKek,
  unwrapDekWithSecret,
  wrapDekWithKek,
  wrapDekWithSecret
};
//# sourceMappingURL=vault.js.map