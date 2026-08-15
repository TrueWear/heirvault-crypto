import { describe, expect, it } from 'vitest'
import {
  buildDekProofMessage,
  generateVaultIdentity,
  signDekChallenge,
  vaultIdentityAad,
  verifyDekProof,
} from './vault-identity'

async function aesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ])
}

describe('vault-identity', () => {
  it('round-trips generate → sign → verify', async () => {
    const dek = await aesKey()
    const aad = vaultIdentityAad('vault_abc')
    const identity = await generateVaultIdentity(dek, { aad })
    const message = buildDekProofMessage({
      purpose: 'mint_kill_key',
      vaultId: 'vault_abc',
      challengeId: 'chal_1',
      nonce: 'nonce_b64',
    })
    const signature = await signDekChallenge(
      dek,
      identity.encryptedVaultIdentityKey,
      message,
      { aad }
    )
    expect(
      verifyDekProof(identity.dekPublicKey, message, signature)
    ).toBe(true)
  })

  it('signs and verifies clear_lockdown purpose', async () => {
    const dek = await aesKey()
    const aad = vaultIdentityAad('vault_abc')
    const identity = await generateVaultIdentity(dek, { aad })
    const message = buildDekProofMessage({
      purpose: 'clear_lockdown',
      vaultId: 'vault_abc',
      challengeId: 'chal_lockdown',
      nonce: 'nonce_lockdown',
    })
    const signature = await signDekChallenge(
      dek,
      identity.encryptedVaultIdentityKey,
      message,
      { aad }
    )
    expect(
      verifyDekProof(identity.dekPublicKey, message, signature)
    ).toBe(true)
  })

  it('rejects a tampered message', async () => {
    const dek = await aesKey()
    const aad = vaultIdentityAad('vault_abc')
    const identity = await generateVaultIdentity(dek, { aad })
    const message = buildDekProofMessage({
      purpose: 'mint_kill_key',
      vaultId: 'vault_abc',
      challengeId: 'chal_1',
      nonce: 'nonce_b64',
    })
    const signature = await signDekChallenge(
      dek,
      identity.encryptedVaultIdentityKey,
      message,
      { aad }
    )
    const tampered = buildDekProofMessage({
      purpose: 'allow_replace',
      vaultId: 'vault_abc',
      challengeId: 'chal_1',
      nonce: 'nonce_b64',
    })
    expect(verifyDekProof(identity.dekPublicKey, tampered, signature)).toBe(
      false
    )
  })

  it('rejects a wrong public key', async () => {
    const dek = await aesKey()
    const aad = vaultIdentityAad('vault_abc')
    const identity = await generateVaultIdentity(dek, { aad })
    const other = await generateVaultIdentity(dek, { aad })
    const message = buildDekProofMessage({
      purpose: 'publish_handoff',
      vaultId: 'vault_abc',
      challengeId: 'chal_2',
      nonce: 'n2',
    })
    const signature = await signDekChallenge(
      dek,
      identity.encryptedVaultIdentityKey,
      message,
      { aad }
    )
    expect(verifyDekProof(other.dekPublicKey, message, signature)).toBe(false)
  })

  it('fails to unwrap with the wrong DEK', async () => {
    const dek = await aesKey()
    const otherDek = await aesKey()
    const aad = vaultIdentityAad('vault_abc')
    const identity = await generateVaultIdentity(dek, { aad })
    await expect(
      signDekChallenge(
        otherDek,
        identity.encryptedVaultIdentityKey,
        'message',
        { aad }
      )
    ).rejects.toThrow()
  })

  it('binds the private-key wrap to AAD', async () => {
    const dek = await aesKey()
    const identity = await generateVaultIdentity(dek, {
      aad: vaultIdentityAad('vault_a'),
    })
    await expect(
      signDekChallenge(
        dek,
        identity.encryptedVaultIdentityKey,
        'message',
        { aad: vaultIdentityAad('vault_b') }
      )
    ).rejects.toThrow()
  })

  it('does not collide messages across tuples that would collide under a naive delimiter join', () => {
    // Under a raw join('|') both tuples produce the identical tail
    // "...|chal|1|2" (challengeId="chal|1", nonce="2" vs
    // challengeId="chal", nonce="1|2") — the encoding must keep them distinct.
    const a = buildDekProofMessage({
      purpose: 'allow_replace',
      vaultId: 'vault1',
      challengeId: 'chal|1',
      nonce: '2',
    })
    const b = buildDekProofMessage({
      purpose: 'allow_replace',
      vaultId: 'vault1',
      challengeId: 'chal',
      nonce: '1|2',
    })
    expect(a).not.toBe(b)
  })

  it('rejects malformed signature/public key without throwing', () => {
    expect(verifyDekProof('not-base64!!!', 'msg', 'also-bad')).toBe(false)
    expect(verifyDekProof(bytesToFakeB64(new Uint8Array(16)), 'msg', bytesToFakeB64(new Uint8Array(64)))).toBe(
      false
    )
  })
})

function bytesToFakeB64(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary)
}
