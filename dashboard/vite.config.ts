import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_');
  const apiTarget = env.VITE_API_URL || 'http://localhost:8000';

  return {
    plugins: [react()],

    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },

    server: {
      port: 3000,
      // The dashboard calls the API on same-origin paths, so /api and the
      // monitoring socket are proxied to the backend during development.
      proxy: {
        '/api': {
          target: apiTarget,
          changeOrigin: true,
        },
        '/ws': {
          target: apiTarget.replace(/^http/, 'ws'),
          ws: true,
        },
      },
    },

    build: {
      outDir: 'build',
      sourcemap: mode !== 'production',
      rollupOptions: {
        output: {
          // Split the heaviest libraries out of the main bundle so a change to
          // application code does not invalidate the vendor chunk.
          manualChunks: {
            react: ['react', 'react-dom', 'react-router-dom'],
            mui: ['@mui/material', '@mui/icons-material'],
            charts: ['recharts'],
          },
        },
      },
    },

    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: './src/test/setup.ts',
    },
  };
});
