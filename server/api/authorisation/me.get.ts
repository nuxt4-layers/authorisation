import { authorisationHandler, requireSubject } from '../../internal/http'
import { getAuthorisationAdministration } from '../../utils/authorisation-server'

/** GET /api/authorisation/me — the signed-in principal's own assignments: hints for the user experience, never a decision. */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  return getAuthorisationAdministration().self({ subject })
})
