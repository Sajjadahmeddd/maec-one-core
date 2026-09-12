import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In development the API runs separately on :8000; in production FastAPI
// serves this bundle itself, so the same /api paths work with no CORS.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true } },
  },
  build: { outDir: 'dist', emptyOutDir: true },
})
