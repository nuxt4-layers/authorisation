import { authorisationHandler, identifierParam, requireSubject } from '../../../../internal/http'
import { getAuthorisationAdministration } from '../../../../utils/authorisation-server'

/** GET /api/authorisation/groups/:groupId/grants — what the group has shared (`authorisation.grants:manage`). */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  return getAuthorisationAdministration().grants({ subject, groupId: identifierParam(event, 'groupId') })
})
