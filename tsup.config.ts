import { defineConfig } from 'tsup'

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/encoding.ts',
    'src/aes-gcm.ts',
    'src/argon2.ts',
    'src/hkdf.ts',
    'src/passphrase.ts',
    'src/vault.ts',
    'src/recovery.ts',
  ],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  target: 'es2022',
  outDir: 'dist',
})
