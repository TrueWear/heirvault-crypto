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
async function encryptBinary(plaintext, key, options) {
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
    toArrayBuffer(plaintext)
  );
  return {
    ciphertext: new Uint8Array(cipherBuffer),
    iv: bytesToBase64(iv)
  };
}
async function decryptBinary(ciphertext, ivBase64, key, options) {
  const iv = base64ToBytes(ivBase64);
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
  return new Uint8Array(plainBuffer);
}
function vaultFieldAad(parts) {
  return [
    parts.vaultId,
    parts.itemId,
    parts.field,
    parts.kind ?? ""
  ].join("|");
}
export {
  decryptBinary,
  decryptUtf8,
  encryptBinary,
  encryptUtf8,
  vaultFieldAad
};
//# sourceMappingURL=aes-gcm.js.map