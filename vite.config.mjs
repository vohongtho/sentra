// Frontend build: React + TypeScript sources in web/, static output into public/ (served by the API server and Vercel).
// public/ also holds product-requirements.md and feature-matrix.md, so the output directory is not emptied wholesale;
// only the generated index.html and assets/ are replaced.
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { rmSync } from 'node:fs';

export default defineConfig({
  root: 'web',
  plugins: [react(), { name: 'clean-assets', buildStart() { rmSync(new URL('./public/assets', import.meta.url), { recursive: true, force: true }); } }],
  build: { outDir: '../public', emptyOutDir: false, assetsDir: 'assets', sourcemap: false, target: 'es2022' },
  server: { proxy: { '/api': 'http://localhost:8080' } },
});
