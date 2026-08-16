// src/recovery.ts
import { generateMnemonic, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

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
import { argon2id, argon2idAsync } from "@noble/hashes/argon2";

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
async function deriveStretchedKeyBytesAsync(password, salt) {
  const passwordBytes = new TextEncoder().encode(
    preparePassphraseForKdf(password)
  );
  return new Uint8Array(
    await argon2idAsync(passwordBytes, salt, {
      t: ARGON2_ITERATIONS,
      m: ARGON2_MEMORY_KIB,
      p: ARGON2_PARALLELISM,
      dkLen: ARGON2_KEY_LENGTH
    })
  );
}
async function deriveVaultKeyArgon2(password, salt, deriveStretchedKey = deriveStretchedKeyBytesAsync) {
  const keyBytes = await deriveStretchedKey(password, salt);
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
var HKDF_INFO_RECOVERY_AUTH = "heirvault-recovery-auth-v1";
function toArrayBuffer3(bytes) {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  );
}
async function hkdfExtractExpand(ikm, salt, info, length = 32) {
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
      salt: toArrayBuffer3(salt),
      info: toArrayBuffer3(new TextEncoder().encode(info))
    },
    baseKey,
    length * 8
  );
  return new Uint8Array(bits);
}

// src/vault.ts
function toArrayBuffer4(bytes) {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  );
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

// src/recovery.ts
function generateRecoveryPhrase(wordCount = 12) {
  const strength = wordCount / 3 * 32;
  return generateMnemonic(wordlist, strength);
}
function normalizeRecoveryPhrase(phrase) {
  return phrase.trim().toLowerCase().replace(/\s+/g, " ");
}
function isValidRecoveryPhrase(phrase) {
  return validateMnemonic(normalizeRecoveryPhrase(phrase), wordlist);
}
var RECOVERY_SALT_LENGTH = 16;
function randomRecoverySalt() {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(RECOVERY_SALT_LENGTH)));
}
async function deriveRecoveryOpaquePassword(phrase, recoverySaltB64) {
  const ikm = new TextEncoder().encode(normalizeRecoveryPhrase(phrase));
  const authBytes = await hkdfExtractExpand(
    ikm,
    base64ToBytes(recoverySaltB64),
    HKDF_INFO_RECOVERY_AUTH
  );
  return bytesToBase64(authBytes);
}
async function wrapDekWithRecoveryPhrase(dek, phrase, deriveStretchedKey) {
  const salt = randomSaltArgon2();
  const kek = await deriveVaultKeyArgon2(
    normalizeRecoveryPhrase(phrase),
    salt,
    deriveStretchedKey
  );
  const raw = await exportDekRaw(dek);
  const payload = await encryptUtf8(bytesToBase64(raw), kek);
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
async function unlockWithPhrase(phrase, wrap, salt, deriveStretchedKey) {
  const kek = await deriveVaultKeyArgon2(phrase, salt, deriveStretchedKey);
  const rawB64 = await decryptUtf8(
    { ciphertext: wrap.ciphertext, iv: wrap.iv },
    kek
  );
  return importDekFromRaw(base64ToBytes(rawB64));
}
async function unlockDekWithRecovery(phrase, wrap, deriveStretchedKey) {
  assertSupportedArgon2Params(wrap);
  const salt = deserializeArgon2Salt(wrap.salt);
  const normalized = normalizeRecoveryPhrase(phrase);
  try {
    return await unlockWithPhrase(normalized, wrap, salt, deriveStretchedKey);
  } catch (normalizedError) {
    if (phrase === normalized) {
      throw normalizedError;
    }
    try {
      return await unlockWithPhrase(phrase, wrap, salt, deriveStretchedKey);
    } catch {
      throw normalizedError;
    }
  }
}
export {
  RECOVERY_SALT_LENGTH,
  deriveRecoveryOpaquePassword,
  generateRecoveryPhrase,
  isValidRecoveryPhrase,
  normalizeRecoveryPhrase,
  randomRecoverySalt,
  unlockDekWithRecovery,
  wrapDekWithRecoveryPhrase
};
//# sourceMappingURL=recovery.js.map