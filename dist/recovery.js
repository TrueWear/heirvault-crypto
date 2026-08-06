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
function base64ToBytes(base64) {
  if (typeof Buffer !== "undefined") {
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
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  return salt;
}
function serializeArgon2Salt(salt) {
  return bytesToBase64(salt);
}
function deserializeArgon2Salt(encoded) {
  return base64ToBytes(encoded);
}

// src/vault.ts
function toArrayBuffer3(bytes) {
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
    toArrayBuffer3(raw),
    { name: "AES-GCM", length: 256 },
    extractable,
    ["encrypt", "decrypt"]
  );
}

// src/recovery.ts
function generateRecoveryPhrase(wordCount = 12) {
  const strength = wordCount / 3 * 32;
  return generateMnemonic(wordlist, strength);
}
function isValidRecoveryPhrase(phrase) {
  return validateMnemonic(
    phrase.trim().toLowerCase().replace(/\s+/g, " "),
    wordlist
  );
}
async function wrapDekWithRecoveryPhrase(dek, phrase) {
  const salt = randomSaltArgon2();
  const kek = await deriveVaultKeyArgon2(phrase, salt);
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
async function unlockDekWithRecovery(phrase, wrap) {
  if (wrap.kdf !== "argon2id") {
    throw new Error("Unsupported recovery wrap KDF");
  }
  const salt = deserializeArgon2Salt(wrap.salt);
  const kek = await deriveVaultKeyArgon2(phrase, salt);
  const rawB64 = await decryptUtf8(
    { ciphertext: wrap.ciphertext, iv: wrap.iv },
    kek
  );
  return importDekFromRaw(base64ToBytes(rawB64));
}
export {
  generateRecoveryPhrase,
  isValidRecoveryPhrase,
  unlockDekWithRecovery,
  wrapDekWithRecoveryPhrase
};
//# sourceMappingURL=recovery.js.map