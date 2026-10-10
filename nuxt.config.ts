/**
 * Nuxt layer entry point for `@nuxt4-layers/authorisation`.
 *
 * Hosts compose this layer by package name from `extends` and supply the
 * required ports from a Nitro plugin. See docs/composition-contract.md.
 */
export default defineNuxtConfig({
  compatibilityDate: '2026-06-30',

  runtimeConfig: {
    authorisation: {
      /**
       * The host's public origin (`NUXT_AUTHORISATION_BASE_URL`).
       * State-changing `/api/authorisation/*` requests must come from it;
       * without it they are all refused.
       */
      baseUrl: '',
    },
  },
})
