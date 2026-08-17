import { describe, expect, it } from 'vitest'
import {
  createVaultCrypto,
  decryptVaultSecret,
  encryptVaultSecret,
  unlockVaultCrypto,
} from './vault'

describe('vault crypto', () => {
  it('encrypts and decrypts with the same password-unlocked DEK', async () => {
    const password = 'correct-horse-battery-staple'
    const created = await createVaultCrypto(password)
    const secret = 'Beneficiary instructions for 2030'
    const encrypted = await encryptVaultSecret(secret, created.dek)
    const unlocked = await unlockVaultCrypto(password, created.vaultCrypto)
    const decrypted = await decryptVaultSecret(encrypted, unlocked.dek)
    expect(decrypted).toBe(secret)
  }, 90_000)

  it('fails decryption with wrong password-derived key', async () => {
    const created = await createVaultCrypto('alpha-password')
    const encrypted = await encryptVaultSecret('payload', created.dek)
    const other = await createVaultCrypto('beta-password')
    await expect(decryptVaultSecret(encrypted, other.dek)).rejects.toThrow()
  }, 90_000)
})
