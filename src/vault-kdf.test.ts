import { describe, expect, it } from 'vitest'
import {
  createVaultCrypto,
  decryptVaultSecret,
  encryptVaultSecret,
  unlockVaultCrypto,
} from './vault'

describe('vault KDF', () => {
  it('creates and unlocks with argon2id', async () => {
    const created = await createVaultCrypto('test-password-12')
    expect(created.vaultCrypto.kdf).toBe('argon2id')
    const unlocked = await unlockVaultCrypto(
      'test-password-12',
      created.vaultCrypto
    )
    const payload = await encryptVaultSecret('round-trip', unlocked.dek)
    const plain = await decryptVaultSecret(payload, created.dek)
    expect(plain).toBe('round-trip')
  }, 90_000)

  it('rejects wrong passphrase', async () => {
    const created = await createVaultCrypto('right-passphrase')
    await expect(
      unlockVaultCrypto('wrong-passphrase', created.vaultCrypto)
    ).rejects.toThrow()
  }, 90_000)
})
