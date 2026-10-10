import { authorisationHandler, identifierParam, requireSubject } from '../../../../internal/http'
import { getAuthorisationAdministration } from '../../../../utils/authorisation-server'

/** GET /api/authorisation/groups/:groupId/access — the group's default roles and review interval (`authorisation.roles:view`). */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  return getAuthorisationAdministration().groupAccess({ subject, groupId: identifierParam(event, 'groupId') })
})
