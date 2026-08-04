import { describe, expect, it } from 'vitest'
import { generateRecoveryPhrase, isValidRecoveryPhrase } from './recovery'

describe('recovery kit', () => {
  it('generates BIP39 phrases with the requested word count', () => {
    expect(generateRecoveryPhrase(12).split(' ')).toHaveLength(12)
    expect(generateRecoveryPhrase(24).split(' ')).toHaveLength(24)
  })

  it('validates generated phrases', () => {
    const phrase = generateRecoveryPhrase(12)
    expect(isValidRecoveryPhrase(phrase)).toBe(true)
    expect(
      isValidRecoveryPhrase('not a real mnemonic phrase at all here')
    ).toBe(false)
  })
})
