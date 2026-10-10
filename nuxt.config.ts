/**
 * Nuxt layer entry point for `@nuxt4-layers/authorisation`.
 *
 * Hosts compose this layer by package name from `extends` and supply the
 * required ports from a Nitro plugin. See docs/composition-contract.md.
 */
import { fileURLToPath } from 'node:url'

export default defineNuxtConfig({
  compatibilityDate: '2026-06-30',

  // Presentation (default pages and components), registered only when
  // `authorisation.presentation` is true. The core below never depends on it.
  modules: [fileURLToPath(new URL('./modules/presentation', import.meta.url))],

  runtimeConfig: {
    authorisation: {
      /**
       * The host's public origin (`NUXT_AUTHORISATION_BASE_URL`).
       * State-changing `/api/authorisation/*` requests must come from it;
       * without it they are all refused.
       */
      baseUrl: '',
    },
    public: {
      authorisation: {
        /** BCP 47 locale of the pages' text (`NUXT_PUBLIC_AUTHORISATION_LOCALE`). */
        locale: 'en-GB',
        /** Where the pages link. The presentation module fills in its own page paths; hosts set `signIn`. */
        routes: {
          signIn: '/sign-in',
          groupAccess: '/groups/:groupId/access',
          sharing: '/groups/:groupId/sharing',
          tenantRoles: '/tenants/:tenantId/roles',
          change: '/access-changes/:changeId',
        },
      },
    },
  },
})
