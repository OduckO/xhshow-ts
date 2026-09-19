import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts'],
  format: {
    cjs: {
      dts: false
    },
    esm: {}
  },
  dts: true,
  clean: true,
  outDir: 'dist',
  platform: 'node',
  target: 'node16',
  treeshake: true,
  sourcemap: false,
  shims: true,
  cjsDefault: true,
  outExtensions({ format }) {
    return {
      js: format === 'es' ? '.mjs' : '.cjs',
      dts: '.d.ts'
    }
  },
})
