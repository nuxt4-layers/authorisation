import { z } from 'zod'
import { authorisationHandler, correlationOf, readJson, requireSubject, uuidParam } from '../../../../internal/http'
import { getAuthorisationChanges } from '../../../../utils/authorisation-server'

const bodySchema = z.strictObject({ decision: z.enum(['approve', 'reject']), changeDigest: z.string().max(64) })

/** POST /api/authorisation/changes/:changeId/decision — approves or rejects the change whose digest the approver was shown. */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  const correlationId = correlationOf(event)
  const body = await readJson(event, bodySchema)
  return getAuthorisationChanges().decide({ subject, changeId: uuidParam(event, 'changeId'), changeDigest: body.changeDigest, decision: body.decision, correlationId })
})
