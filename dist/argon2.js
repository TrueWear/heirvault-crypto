// src/argon2.ts
import { argon2id } from "@noble/hashes/argon2";

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
function toArrayBuffer(bytes) {
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
    toArrayBuffer(keyBytes),
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
export {
  ARGON2_ITERATIONS,
  ARGON2_KEY_LENGTH,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  deriveStretchedKeyBytes,
  deriveVaultKeyArgon2,
  deserializeArgon2Salt,
  randomSaltArgon2,
  serializeArgon2Salt
};
//# sourceMappingURL=argon2.js.map