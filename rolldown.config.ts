import { defineConfig } from 'rolldown'

export default defineConfig({
  input: 'src/index.ts',
  output: {
    dir: 'dist',
    format: 'esm',
    entryFileNames: '[name].js',
  },
  external: ['elysia', '@elysiajs/jwt', 'oauth4webapi', 'jose', '@mks2508/no-throw', '@mks2508/better-logger'],
  platform: 'node',
})
