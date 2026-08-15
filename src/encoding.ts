export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64')
  }
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/

export function base64ToBytes(base64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    // Buffer.from silently drops invalid characters instead of throwing;
    // reject malformed input up front so Node and browser (atob, which
    // throws) behave the same way for corrupted/short-pasted values.
    if (base64.length % 4 !== 0 || !BASE64_PATTERN.test(base64)) {
      throw new Error('Invalid base64 input')
    }
    return new Uint8Array(Buffer.from(base64, 'base64'))
  }
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

export function stringToUtf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

export function utf8BytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes)
}
