import { fileURLToPath } from 'node:url'
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// In development, /api goes to the back end on port 8000 with the API token
// from SIEVE_API_TOKEN, the same way nginx forwards it in Docker Compose, so
// the app always calls /api/... The token comes from the shell, or else from
// .env at the repository root. It stays in this server and never reaches the
// app. Because the proxy adds the token, the server allows no cross-origin
// requests, so a page from another local port can't read /api through it, and
// it stops instead of moving to another port when 5173 is taken, so the app's
// origin stays http://localhost:5173.
const root = fileURLToPath(new URL('..', import.meta.url))

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    cors: false,
    proxy: {
      '/api': {
        target: process.env.API_URL ?? 'http://localhost:8000',
        rewrite: (path) => path.replace(/^\/api/, ''),
        headers: {
          Authorization: `Bearer ${loadEnv(mode, root, 'SIEVE_API_TOKEN').SIEVE_API_TOKEN ?? ''}`,
        },
      },
    },
  },
}))
