import { z } from 'zod'
import { authorisationHandler, correlationOf, readJson, requireSubject, uuidParam } from '../../../../internal/http'
import { getAuthorisationChanges } from '../../../../utils/authorisation-server'

/** POST /api/authorisation/changes/:changeId/cancel — the requester withdraws a change that has not taken effect. */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  const correlationId = correlationOf(event)
  await readJson(event, z.strictObject({}))
  return getAuthorisationChanges().cancel({ subject, changeId: uuidParam(event, 'changeId'), correlationId })
})
