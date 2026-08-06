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
function stringToUtf8Bytes(text) {
  return new TextEncoder().encode(text);
}
function utf8BytesToString(bytes) {
  return new TextDecoder().decode(bytes);
}
export {
  base64ToBytes,
  bytesToBase64,
  stringToUtf8Bytes,
  utf8BytesToString
};
//# sourceMappingURL=encoding.js.map