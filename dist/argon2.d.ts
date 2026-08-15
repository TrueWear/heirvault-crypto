declare const ARGON2_MEMORY_KIB = 65536;
declare const ARGON2_ITERATIONS = 3;
declare const ARGON2_PARALLELISM = 4;
declare const ARGON2_KEY_LENGTH = 32;
declare const ARGON2_SALT_LENGTH = 16;
/** Stretch passphrase to raw bytes (Argon2id). Used for v2 HKDF root. */
declare function deriveStretchedKeyBytes(password: string, salt: Uint8Array): Uint8Array;
declare function deriveVaultKeyArgon2(password: string, salt: Uint8Array): Promise<CryptoKey>;
declare function randomSaltArgon2(): Uint8Array;
declare function serializeArgon2Salt(salt: Uint8Array): string;
declare function deserializeArgon2Salt(encoded: string): Uint8Array;

export { ARGON2_ITERATIONS, ARGON2_KEY_LENGTH, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_SALT_LENGTH, deriveStretchedKeyBytes, deriveVaultKeyArgon2, deserializeArgon2Salt, randomSaltArgon2, serializeArgon2Salt };
