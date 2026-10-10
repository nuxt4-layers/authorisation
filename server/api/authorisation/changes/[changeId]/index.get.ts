import { authorisationHandler, requireSubject, uuidParam } from '../../../../internal/http'
import { getAuthorisationChanges } from '../../../../utils/authorisation-server'

/** GET /api/authorisation/changes/:changeId — a change, for its requester, beneficiary, approvers and whoever may see the group's roles. */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  return getAuthorisationChanges().get({ subject, changeId: uuidParam(event, 'changeId') })
})
