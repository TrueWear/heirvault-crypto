declare const HKDF_INFO_AUTH = "heirvault-auth-v1";
declare const HKDF_INFO_VAULT_KEK = "heirvault-vault-kek-v1";
declare const HKDF_INFO_DEVICE = "heirvault-device-wrap-v1";
declare const HKDF_INFO_RECOVERY_AUTH = "heirvault-recovery-auth-v1";
/**
 * HKDF-SHA-256 expand from an already-extracted IKM (stretched password).
 * Salt is empty; domain separation uses the info string.
 */
declare function hkdfExpand(ikm: Uint8Array, info: string, length?: number): Promise<Uint8Array>;
/**
 * Full HKDF-SHA-256 (extract + expand) with a caller-supplied salt.
 *
 * Use this when the IKM is a high-entropy secret that has NOT been through a
 * memory-hard KDF -- the salt does the domain-separating work that
 * `hkdfExpand`'s empty salt leaves to the info string alone.
 */
declare function hkdfExtractExpand(ikm: Uint8Array, salt: Uint8Array, info: string, length?: number): Promise<Uint8Array>;
declare function deriveOpaquePassword(stretchedKey: Uint8Array): Promise<string>;
declare function deriveVaultKek(stretchedKey: Uint8Array): Promise<CryptoKey>;
declare function serializeKeyBytes(bytes: Uint8Array): string;
declare function deserializeKeyBytes(encoded: string): Uint8Array;

export { HKDF_INFO_AUTH, HKDF_INFO_DEVICE, HKDF_INFO_RECOVERY_AUTH, HKDF_INFO_VAULT_KEK, deriveOpaquePassword, deriveVaultKek, deserializeKeyBytes, hkdfExpand, hkdfExtractExpand, serializeKeyBytes };
