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

// src/hkdf.ts
var HKDF_INFO_AUTH = "heirvault-auth-v1";
var HKDF_INFO_VAULT_KEK = "heirvault-vault-kek-v1";
var HKDF_INFO_DEVICE = "heirvault-device-wrap-v1";
function toArrayBuffer(bytes) {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  );
}
async function hkdfExpand(ikm, info, length = 32) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(ikm),
    "HKDF",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new ArrayBuffer(0),
      info: toArrayBuffer(new TextEncoder().encode(info))
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
    toArrayBuffer(kekBytes),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
function serializeKeyBytes(bytes) {
  return bytesToBase64(bytes);
}
function deserializeKeyBytes(encoded) {
  return base64ToBytes(encoded);
}
export {
  HKDF_INFO_AUTH,
  HKDF_INFO_DEVICE,
  HKDF_INFO_VAULT_KEK,
  deriveOpaquePassword,
  deriveVaultKek,
  deserializeKeyBytes,
  hkdfExpand,
  serializeKeyBytes
};
//# sourceMappingURL=hkdf.js.map