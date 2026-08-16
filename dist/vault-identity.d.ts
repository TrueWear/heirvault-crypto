import { EncryptedPayload } from './aes-gcm.js';
import { VaultDek } from './vault.js';
import './argon2.js';

type VaultIdentityMaterial = {
    /** Compressed P-256 public key, base64. */
    dekPublicKey: string;
    /** Private key bytes wrapped under the vault DEK. */
    encryptedVaultIdentityKey: EncryptedPayload;
};
type DekProofPurpose = 'allow_replace' | 'mint_kill_key' | 'mint_panic_key' | 'mint_checkin_key' | 'check_in' | 'rotate_vault_crypto' | 'store_recovery_wrap' | 'publish_handoff' | 'mark_handoff_stale' | 'rotate_vault_identity' | 'schedule_hard_kill' | 'cancel_hard_kill' | 'update_kill_pending_hours' | 'mutate_device_wrap' | 'duress_register' | 'enable_duress' | 'update_duress_settings' | 'account_deletion' | 'revoke_claim_link' | 'update_beneficiary_email' | 'update_vault_release_settings' | 'update_beneficiary_notify' | 'update_beneficiary_delivery_mode' | 'remove_beneficiary' | 'set_away_until' | 'clear_lockdown' | 'update_decoy_vault_key' | 'mutate_witness' | 'set_release_recipients';
/** Domain-separated AAD for the identity private-key wrap. */
declare function vaultIdentityAad(vaultId: string): string;
/**
 * Canonical challenge message. Server rebuilds this from the challenge row;
 * the client must sign the exact same string.
 *
 * Encoded as JSON rather than delimiter-joined so distinct (purpose, vaultId,
 * challengeId, nonce) tuples can never collide onto the same signed message.
 */
declare function buildDekProofMessage(parts: {
    purpose: DekProofPurpose;
    vaultId: string;
    challengeId: string;
    nonce: string;
}): string;
/** Generate a P-256 identity keypair and wrap the private key under the DEK. */
declare function generateVaultIdentity(dek: VaultDek, options: {
    aad: string;
}): Promise<VaultIdentityMaterial>;
/** Sign a canonical DEK-proof message with the DEK-wrapped identity key. */
declare function signDekChallenge(dek: VaultDek, encryptedVaultIdentityKey: EncryptedPayload, message: string, options: {
    aad: string;
}): Promise<string>;
/**
 * Verify a DEK proof signature against a stored public key.
 * Pure JS — safe to call from Convex mutations as well as the browser.
 */
declare function verifyDekProof(dekPublicKey: string, message: string, signature: string): boolean;

export { type DekProofPurpose, type VaultIdentityMaterial, buildDekProofMessage, generateVaultIdentity, signDekChallenge, vaultIdentityAad, verifyDekProof };
