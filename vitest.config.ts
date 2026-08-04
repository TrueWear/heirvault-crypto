import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // Argon2id tests are CPU-heavy. Parallel workers starve Vitest's RPC and
    // surface a false "Timeout calling onTaskUpdate" even when all tests pass.
    pool: 'forks',
    fileParallelism: false,
    maxWorkers: 1,
    testTimeout: 120_000,
    hookTimeout: 120_000,
    teardownTimeout: 30_000,
  },
})
