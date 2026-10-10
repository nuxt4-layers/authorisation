import { useRuntimeConfig } from '#imports'

/**
 * PUBLIC. Links between the layer's pages, and to the host's sign-in page,
 * from the paths the presentation module was given.
 */
export function useAuthorisationRoutes() {
  const routes = useRuntimeConfig().public.authorisation.routes
  const fill = (path: string, params: Record<string, string>) =>
    path.replace(/:(\w+)/g, (match, name: string) => (name in params ? encodeURIComponent(params[name]!) : match))
  return {
    groupAccess: (groupId: string) => fill(routes.groupAccess, { groupId }),
    sharing: (groupId: string) => fill(routes.sharing, { groupId }),
    tenantRoles: (tenantId: string) => fill(routes.tenantRoles, { tenantId }),
    change: (changeId: string) => fill(routes.change, { changeId }),
    signIn: () => routes.signIn,
  }
}
