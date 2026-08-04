import { describe, expect, it } from 'vitest'
import {
  base64ToBytes,
  bytesToBase64,
  stringToUtf8Bytes,
  utf8BytesToString,
} from './encoding'

describe('encoding', () => {
  it('round-trips bytes through base64', () => {
    const bytes = new Uint8Array([0, 1, 2, 254, 255])
    expect(Array.from(base64ToBytes(bytesToBase64(bytes)))).toEqual(
      Array.from(bytes)
    )
  })

  it('round-trips utf8 strings', () => {
    const text = 'HeirVault — café 🔐'
    expect(utf8BytesToString(stringToUtf8Bytes(text))).toBe(text)
  })
})
