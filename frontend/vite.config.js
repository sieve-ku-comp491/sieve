import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In development, /api goes to the back end on port 8000 with the API token
// from SIEVE_API_TOKEN, the same way nginx forwards it in Docker Compose, so
// the app always calls /api/...
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.API_URL ?? 'http://localhost:8000',
        rewrite: (path) => path.replace(/^\/api/, ''),
        headers: { Authorization: `Bearer ${process.env.SIEVE_API_TOKEN ?? ''}` },
      },
    },
  },
})
