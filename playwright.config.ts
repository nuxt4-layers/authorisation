import { defineConfig, devices } from '@playwright/test'
import { DATABASE, ORIGIN, PORT } from './tests/e2e/constants'

/**
 * Browser tests of the default pages against the built playground (with
 * Theme Manager styles) and a disposable PostgreSQL database. Requires
 * AUTHORISATION_TEST_DATABASE_URL. Set PLAYWRIGHT_CHROMIUM_EXECUTABLE to use
 * a preinstalled Chromium instead of the one Playwright downloads.
 */
const admin = new URL(process.env.AUTHORISATION_TEST_DATABASE_URL ?? 'postgres://postgres@localhost:5432/postgres')
const database = new URL(admin)
database.pathname = `/${DATABASE}`

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? 'github' : 'list',
  timeout: 60_000,
  use: {
    baseURL: ORIGIN,
    trace: 'retain-on-failure',
    ...devices['Desktop Chrome'],
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE } : {},
  },
  webServer: {
    command: 'node tests/e2e/prepare-database.mjs && node playground/.output/server/index.mjs',
    url: `${ORIGIN}/api/__playground/ready`,
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      PORT: String(PORT),
      AUTHORISATION_PLAYGROUND_TEST: '1',
      AUTHORISATION_DATABASE_URL: database.toString(),
      NUXT_AUTHORISATION_BASE_URL: ORIGIN,
    },
  },
})
