# Security Policy

## Reporting a vulnerability

Email [security@heirvault.io](mailto:security@heirvault.io).

Please include a clear description, steps to reproduce, and impact on the live vault crypto in this repository. Do not open a public GitHub issue for unfixed vulnerabilities.

## Scope

In scope: cryptographic correctness and implementation bugs in `@heirvault/crypto` (encoding, AES-GCM, Argon2id, HKDF, password prep, vault wraps, recovery wraps).

Out of scope for this repo: HeirVault product features (assisted delivery, claim flows, server escrow), account authentication, and infrastructure.

## Design notes and known limits

- **AES-GCM key usage volume**: nonces are always freshly generated via a CSPRNG (`crypto.getRandomValues`), never derived or reused. NIST SP 800-38D's guidance for randomly generated 96-bit IVs is to keep the number of encryptions under a single key well below 2^32 to bound the birthday-bound collision risk. This library does not enforce or track that count — callers deriving a single long-lived DEK (as HeirVault's vault DEK is) should be aware a given key is not intended for unbounded-volume encryption. For a personal vault's realistic field/attachment counts this is not a practical risk, but it is not programmatically enforced.

## Product security

HeirVault product security overview: https://heirvault.io/security
