import { authorisationHandler, identifierParam, requireSubject } from '../../../../internal/http'
import { getAuthorisationChanges } from '../../../../utils/authorisation-server'

/** GET /api/authorisation/groups/:groupId/changes — the group's changes not yet in effect (`authorisation.roles:view`). */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  return getAuthorisationChanges().listForGroup({ subject, groupId: identifierParam(event, 'groupId') })
})
