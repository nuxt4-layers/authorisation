import { authorisationHandler, identifierParam, requireSubject } from '../../../../internal/http'
import { getAuthorisationAdministration } from '../../../../utils/authorisation-server'

/** GET /api/authorisation/groups/:groupId/assignments — who holds which role in the group (`authorisation.roles:view`). */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  return getAuthorisationAdministration().assignments({ subject, groupId: identifierParam(event, 'groupId') })
})
