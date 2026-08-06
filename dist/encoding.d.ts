declare function bytesToBase64(bytes: Uint8Array): string;
declare function base64ToBytes(base64: string): Uint8Array;
declare function stringToUtf8Bytes(text: string): Uint8Array;
declare function utf8BytesToString(bytes: Uint8Array): string;

export { base64ToBytes, bytesToBase64, stringToUtf8Bytes, utf8BytesToString };
