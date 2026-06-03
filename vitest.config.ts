import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        exclude: ['lib/**', 'node_modules/**'],
        setupFiles: ['./test/vitest.setup-file.ts'],
        coverage: { enabled: true },
        testTimeout: 10_000,
    },
});
