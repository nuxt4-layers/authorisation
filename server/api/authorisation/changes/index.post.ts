import { z } from 'zod'
import { authorisationHandler, correlationOf, created, readJson, requireSubject } from '../../../internal/http'
import { getAuthorisationChanges } from '../../../utils/authorisation-server'

const bodySchema = z.strictObject({ request: z.unknown() })

/** POST /api/authorisation/changes — requests a change to roles, assignments, grants or a group's access (§15). */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  const correlationId = correlationOf(event)
  const body = await readJson(event, bodySchema)
  const change = await getAuthorisationChanges().request({ subject, request: body.request, correlationId })
  created(event)
  return change
})
