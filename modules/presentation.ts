import { addComponentsDir, addImportsDir, createResolver, defineNuxtModule, extendPages } from 'nuxt/kit'

/**
 * Registers the layer's presentation: the default pages, the
 * `Authorisation*` components and the presentation auto-imports
 * (`useAuthorisationText`, `useAuthorisationAction`, `useAuthorisationRoutes`,
 * `authorisationClasses`). The core (server, endpoints and
 * `useAuthorisation()`) never depends on any of it.
 *
 * Hosts configure it in nuxt.config.ts:
 *   authorisation: { pages: { paths: { groupAccess: '/teams/:groupId/roles' } } }  // move the pages
 *   authorisation: { pages: { enabled: false } }                                  // own pages, keep the components
 *   authorisation: { presentation: false }                                        // core only: register nothing here
 */
export interface AuthorisationPagePaths {
  /** Must contain `:groupId`. */
  groupAccess: string
  /** Must contain `:groupId`. */
  sharing: string
  /** Must contain `:tenantId`. */
  tenantRoles: string
  /** Must contain `:changeId`. */
  change: string
}

export interface AuthorisationModuleOptions {
  /** `false` registers no pages, components or presentation auto-imports. */
  presentation: boolean
  pages: {
    enabled: boolean
    paths: AuthorisationPagePaths
  }
}

const PAGES: { key: keyof AuthorisationPagePaths, file: string, parameter: string }[] = [
  { key: 'groupAccess', file: 'GroupAccessPage.vue', parameter: ':groupId' },
  { key: 'sharing', file: 'SharingPage.vue', parameter: ':groupId' },
  { key: 'tenantRoles', file: 'TenantRolesPage.vue', parameter: ':tenantId' },
  { key: 'change', file: 'ChangePage.vue', parameter: ':changeId' },
]

export default defineNuxtModule<AuthorisationModuleOptions>({
  meta: { name: '@nuxt4-layers/authorisation/presentation', configKey: 'authorisation' },
  defaults: {
    presentation: true,
    pages: {
      enabled: true,
      paths: {
        groupAccess: '/groups/:groupId/access',
        sharing: '/groups/:groupId/sharing',
        tenantRoles: '/tenants/:tenantId/roles',
        change: '/access-changes/:changeId',
      },
    },
  },
  setup(options, nuxt) {
    if (!options.presentation) return

    const { resolve } = createResolver(import.meta.url)
    addComponentsDir({ path: resolve('../presentation/components'), prefix: 'Authorisation', pathPrefix: false })
    addImportsDir([resolve('../presentation/composables'), resolve('../presentation/utils')])
    // Type-check the presentation sources with the host's app code.
    nuxt.hook('prepare:types', ({ tsConfig }) => {
      const include = (tsConfig.include ??= [])
      include.push(resolve('../presentation/**/*'))
    })

    if (!options.pages.enabled) return
    for (const page of PAGES) {
      const path = options.pages.paths[page.key]
      if (!path.startsWith('/') || path.startsWith('//')) {
        throw new Error(`authorisation.pages.paths.${page.key} must be an absolute path, got '${path}'.`)
      }
      if (!path.includes(page.parameter)) {
        throw new Error(`authorisation.pages.paths.${page.key} must contain '${page.parameter}', got '${path}'.`)
      }
    }
    // The pages link to one another through the public routes.
    const runtimeRoutes = (nuxt.options.runtimeConfig.public as { authorisation: { routes: Record<string, string> } }).authorisation.routes
    Object.assign(runtimeRoutes, options.pages.paths)

    // The pages act for the signed-in person: never framed (clickjacking),
    // never cached, never leaking a path in a Referer. Headers a host sets for
    // the same path take precedence.
    const routeRules = (nuxt.options.routeRules ??= {}) as Record<string, { headers?: Record<string, string> }>
    for (const path of Object.values(options.pages.paths)) {
      // One path segment per parameter: the rule covers these pages only.
      const pattern = path.replace(/:\w+/g, '*')
      const rule = (routeRules[pattern] ??= {})
      rule.headers = {
        'Content-Security-Policy': "frame-ancestors 'none'",
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Cache-Control': 'no-store',
        ...rule.headers,
      }
    }

    extendPages((pages) => {
      for (const page of PAGES) {
        pages.push({ name: `authorisation-${page.key}`, path: options.pages.paths[page.key], file: resolve('../presentation/pages', page.file) })
      }
    })
  },
})
