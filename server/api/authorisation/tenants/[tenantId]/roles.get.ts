import { authorisationHandler, identifierParam, requireSubject } from '../../../../internal/http'
import { getAuthorisationAdministration } from '../../../../utils/authorisation-server'

/** GET /api/authorisation/tenants/:tenantId/roles — the roles the tenant's groups may assign (`authorisation.roles:view` in a group of the tenant). */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  return getAuthorisationAdministration().tenantRoles({ subject, tenantId: identifierParam(event, 'tenantId') })
})
