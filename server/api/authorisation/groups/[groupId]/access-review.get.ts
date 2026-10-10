import { authorisationHandler, identifierParam, requireSubject } from '../../../../internal/http'
import { getAuthorisationAdministration } from '../../../../utils/authorisation-server'

/** GET /api/authorisation/groups/:groupId/access-review — assignments with provenance, confirmations and overdue marks (`authorisation.role-assignments:manage`). */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  return getAuthorisationAdministration().accessReview({ subject, groupId: identifierParam(event, 'groupId') })
})
