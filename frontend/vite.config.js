import { fileURLToPath } from 'node:url'
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// In development, /api goes to the back end on port 8000 with the API token
// from SIEVE_API_TOKEN, the same way nginx forwards it in Docker Compose, so
// the app always calls /api/... The token comes from the shell, or else from
// .env at the repository root. It stays in this server and never reaches the
// app.
const root = fileURLToPath(new URL('..', import.meta.url))

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    port: 5173,
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
