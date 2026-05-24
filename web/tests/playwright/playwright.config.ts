import { defineConfig } from '@playwright/test'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const STORAGE_STATE = join(__dirname, 'auth-state.json')

export default defineConfig({
  testDir: '.',
  timeout: 30000,
  retries: 1,
  workers: 1,
  globalSetup: './global-setup.ts',
  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: join(__dirname, '../../playwright-report') }]
  ],
  use: {
    baseURL: 'http://localhost:18080',
    headless: true,
    viewport: { width: 1440, height: 900 },
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    video: 'off',
    storageState: STORAGE_STATE,
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
})
