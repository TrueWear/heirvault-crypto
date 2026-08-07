/**
 * Vault-identity signing keys for proof-of-DEK.
 *
 * At vault setup the client generates a P-256 keypair, wraps the private key
 * under the vault DEK (AES-GCM + AAD), and stores the public key on the vault
 * row. Privileged mutations require a signature over a server-issued challenge
 * that only a holder of the DEK can produce.
 *
 * Sign/verify use @noble/curves (pure JS) so the same verify path runs in the
 * browser and in Convex. AES wrap of the private key still uses Web Crypto.
 */
import { p256 } from '@noble/curves/p256'
import { sha256 } from '@noble/hashes/sha256'
import {
  decryptUtf8,
  encryptUtf8,
  type EncryptedPayload,
} from './aes-gcm'
import { base64ToBytes, bytesToBase64 } from './encoding'
import type { VaultDek } from './vault'

export type VaultIdentityMaterial = {
  /** Compressed P-256 public key, base64. */
  dekPublicKey: string
  /** Private key bytes wrapped under the vault DEK. */
  encryptedVaultIdentityKey: EncryptedPayload
}

export type DekProofPurpose =
  | 'allow_replace'
  | 'mint_kill_key'
  | 'mint_panic_key'
  | 'mint_checkin_key'
  | 'rotate_vault_crypto'
  | 'store_recovery_wrap'
  | 'publish_handoff'
  | 'mark_handoff_stale'
  | 'rotate_vault_identity'
  | 'schedule_hard_kill'
  | 'update_kill_pending_hours'
  | 'duress_register'
  | 'enable_duress'
  | 'account_deletion'
  | 'revoke_claim_link'
  | 'update_vault_release_settings'
  | 'clear_lockdown'

/** Domain-separated AAD for the identity private-key wrap. */
export function vaultIdentityAad(vaultId: string): string {
  return `heirvault-vault-identity-v1|${vaultId}`
}

/**
 * Canonical challenge message. Server rebuilds this from the challenge row;
 * the client must sign the exact same string.
 */
export function buildDekProofMessage(parts: {
  purpose: string
  vaultId: string
  challengeId: string
  nonce: string
}): string {
  return [
    'heirvault-dek-proof-v1',
    parts.purpose,
    parts.vaultId,
    parts.challengeId,
    parts.nonce,
  ].join('|')
}

function hashMessage(message: string): Uint8Array {
  return sha256(new TextEncoder().encode(message))
}

/** Generate a P-256 identity keypair and wrap the private key under the DEK. */
export async function generateVaultIdentity(
  dek: VaultDek,
  options: { aad: string }
): Promise<VaultIdentityMaterial> {
  const privateKey = p256.utils.randomPrivateKey()
  const publicKey = p256.getPublicKey(privateKey, true)
  const encryptedVaultIdentityKey = await encryptUtf8(
    bytesToBase64(privateKey),
    dek,
    { additionalData: options.aad }
  )
  return {
    dekPublicKey: bytesToBase64(publicKey),
    encryptedVaultIdentityKey,
  }
}

async function unwrapIdentityPrivateKey(
  dek: VaultDek,
  encryptedVaultIdentityKey: EncryptedPayload,
  aad: string
): Promise<Uint8Array> {
  const privB64 = await decryptUtf8(encryptedVaultIdentityKey, dek, {
    additionalData: aad,
  })
  const priv = base64ToBytes(privB64)
  if (priv.length !== 32) {
    throw new Error('Invalid vault identity private key')
  }
  return priv
}

/** Sign a canonical DEK-proof message with the DEK-wrapped identity key. */
export async function signDekChallenge(
  dek: VaultDek,
  encryptedVaultIdentityKey: EncryptedPayload,
  message: string,
  options: { aad: string }
): Promise<string> {
  const privateKey = await unwrapIdentityPrivateKey(
    dek,
    encryptedVaultIdentityKey,
    options.aad
  )
  const digest = hashMessage(message)
  const signature = p256.sign(digest, privateKey)
  return bytesToBase64(signature.toCompactRawBytes())
}

/**
 * Verify a DEK proof signature against a stored public key.
 * Pure JS — safe to call from Convex mutations as well as the browser.
 */
export function verifyDekProof(
  dekPublicKey: string,
  message: string,
  signature: string
): boolean {
  try {
    const pub = base64ToBytes(dekPublicKey)
    const sig = base64ToBytes(signature)
    if (pub.length !== 33 && pub.length !== 65) return false
    if (sig.length !== 64) return false
    return p256.verify(sig, hashMessage(message), pub)
  } catch {
    return false
  }
}
