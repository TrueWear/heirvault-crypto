import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // Argon2id vault KDF tests are intentionally slow.
    testTimeout: 90_000,
  },
})
