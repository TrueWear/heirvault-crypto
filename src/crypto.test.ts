import { describe, expect, it } from 'vitest'
import {
  createVaultCryptoV2,
  decryptVaultSecret,
  encryptVaultSecret,
  unlockVaultCryptoV2,
} from './vault'

describe('vault crypto', () => {
  it('encrypts and decrypts with the same passphrase-unlocked DEK', async () => {
    const password = 'correct-horse-battery-staple'
    const created = await createVaultCryptoV2(password)
    const secret = 'Beneficiary instructions for 2030'
    const encrypted = await encryptVaultSecret(secret, created.dek)
    const unlocked = await unlockVaultCryptoV2(password, created.vaultCrypto)
    const decrypted = await decryptVaultSecret(encrypted, unlocked.dek)
    expect(decrypted).toBe(secret)
  }, 90_000)

  it('fails decryption with wrong passphrase-derived key', async () => {
    const created = await createVaultCryptoV2('alpha-passphrase')
    const encrypted = await encryptVaultSecret('payload', created.dek)
    const other = await createVaultCryptoV2('beta-passphrase')
    await expect(decryptVaultSecret(encrypted, other.dek)).rejects.toThrow()
  }, 90_000)
})
