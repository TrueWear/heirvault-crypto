import { describe, expect, it } from 'vitest'
import { deriveStretchedKeyBytes, randomSaltArgon2 } from './argon2'
import {
  deriveOpaquePassword,
  deriveVaultKek,
  HKDF_INFO_AUTH,
  HKDF_INFO_VAULT_KEK,
  hkdfExpand,
} from './hkdf'

describe('hkdf domain separation', () => {
  it('produces different outputs for auth vs vault-kek infos', async () => {
    const salt = randomSaltArgon2()
    const stretched = deriveStretchedKeyBytes('test-passphrase-12', salt)
    const auth = await hkdfExpand(stretched, HKDF_INFO_AUTH)
    const kek = await hkdfExpand(stretched, HKDF_INFO_VAULT_KEK)
    expect(auth).not.toEqual(kek)
    expect(auth.length).toBe(32)
    expect(kek.length).toBe(32)
  }, 90_000)

  it('derives opaque password and vault KEK from the same stretch', async () => {
    const salt = randomSaltArgon2()
    const stretched = deriveStretchedKeyBytes('another-long-pass', salt)
    const opaqueA = await deriveOpaquePassword(stretched)
    const opaqueB = await deriveOpaquePassword(stretched)
    expect(opaqueA).toBe(opaqueB)
    const vaultKek = await deriveVaultKek(stretched)
    expect(vaultKek.algorithm).toMatchObject({ name: 'AES-GCM' })
  }, 90_000)
})
