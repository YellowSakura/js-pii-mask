import { defineConfig } from 'tsdown'

export default defineConfig({
    entry: ['./src/index.ts'],
    format: ['esm', 'cjs'], // Generate both formats
    dts: true,              // Automatically generate .d.ts files
    clean: true,            // Clean /dist folder before each build
    minify: true            // Optimize final code
})
