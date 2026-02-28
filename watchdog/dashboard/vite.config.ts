import { defineConfig } from 'vite'
import path from 'path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://10.192.225.151:3000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://10.192.225.151:3000',
        ws: true,
      },
    },
  },
  assetsInclude: ['**/*.svg', '**/*.csv'],
})
