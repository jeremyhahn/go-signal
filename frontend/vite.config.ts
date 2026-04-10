import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';
import path from 'path';
import fs from 'fs';

// Resolve the Wails-generated bindings directory. When running under the
// Wails build system the directory exists; during `npm run dev` and E2E
// tests it does not, so we point Vite at a no-op stub instead.
const wailsjsAppPath = path.resolve(__dirname, '../wailsjs/go/desktop/App');
const wailsjsStubPath = path.resolve(
  __dirname,
  'src/sdk/__stubs__/wailsjs-app.ts',
);
const wailsjsAlias = fs.existsSync(wailsjsAppPath + '.js')
  ? wailsjsAppPath
  : wailsjsStubPath;

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../build/frontend',
    emptyOutDir: true,
    sourcemap: true,
  },
  resolve: {
    alias: {
      '@': '/src',
      '../../wailsjs/go/desktop/App': wailsjsAlias,
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3001',
        changeOrigin: true,
      },
    },
  },
});
