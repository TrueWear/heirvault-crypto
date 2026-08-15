// src/vault-identity.ts
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";

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

// src/vault-identity.ts
function vaultIdentityAad(vaultId) {
  return `heirvault-vault-identity-v1|${vaultId}`;
}
function buildDekProofMessage(parts) {
  return JSON.stringify([
    "heirvault-dek-proof-v1",
    parts.purpose,
    parts.vaultId,
    parts.challengeId,
    parts.nonce
  ]);
}
function hashMessage(message) {
  return sha256(new TextEncoder().encode(message));
}
async function generateVaultIdentity(dek, options) {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = p256.getPublicKey(privateKey, true);
  const encryptedVaultIdentityKey = await encryptUtf8(
    bytesToBase64(privateKey),
    dek,
    { additionalData: options.aad }
  );
  return {
    dekPublicKey: bytesToBase64(publicKey),
    encryptedVaultIdentityKey
  };
}
async function unwrapIdentityPrivateKey(dek, encryptedVaultIdentityKey, aad) {
  const privB64 = await decryptUtf8(encryptedVaultIdentityKey, dek, {
    additionalData: aad
  });
  const priv = base64ToBytes(privB64);
  if (priv.length !== 32) {
    throw new Error("Invalid vault identity private key");
  }
  return priv;
}
async function signDekChallenge(dek, encryptedVaultIdentityKey, message, options) {
  const privateKey = await unwrapIdentityPrivateKey(
    dek,
    encryptedVaultIdentityKey,
    options.aad
  );
  const digest = hashMessage(message);
  const signature = p256.sign(digest, privateKey);
  return bytesToBase64(signature.toCompactRawBytes());
}
function verifyDekProof(dekPublicKey, message, signature) {
  try {
    const pub = base64ToBytes(dekPublicKey);
    const sig = base64ToBytes(signature);
    if (pub.length !== 33 && pub.length !== 65) return false;
    if (sig.length !== 64) return false;
    return p256.verify(sig, hashMessage(message), pub);
  } catch {
    return false;
  }
}
export {
  buildDekProofMessage,
  generateVaultIdentity,
  signDekChallenge,
  vaultIdentityAad,
  verifyDekProof
};
//# sourceMappingURL=vault-identity.js.map