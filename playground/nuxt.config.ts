// Composition harness: proves the layer composes in a host. Not published.
export default defineNuxtConfig({
  // Composed as a host would: the authorisation layer and Theme Manager as peers.
  extends: ['..', '@nuxt4-layers/theme-manager'],
  css: ['~/assets/css/main.css'],
  compatibilityDate: '2026-06-30',
})
