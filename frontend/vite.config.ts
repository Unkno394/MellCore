
import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const target = env.MELLCORE_API_PROXY_TARGET || 'http://127.0.0.1:8080'

  return {
    plugins: [react(), tailwindcss()],
    server: {
      proxy: {
        '/api': { target, changeOrigin: true },
        '/health': { target, changeOrigin: true },
      },
    },
  }
})
