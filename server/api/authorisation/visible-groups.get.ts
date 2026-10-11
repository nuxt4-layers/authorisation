import { getQuery } from 'h3'
import { AuthorisationFailure } from '../../../shared/errors'
import { authorisationHandler, requireSubject } from '../../internal/http'
import { listAuthorisationVisibleGroups } from '../../utils/authorisation-server'

/** GET /api/authorisation/visible-groups?permission= — the groups in which the signed-in principal holds the permission now. */
export default authorisationHandler(async (event) => {
  const subject = await requireSubject(event)
  const { permission } = getQuery(event)
  if (typeof permission !== 'string') throw new AuthorisationFailure('validation-failed')
  return listAuthorisationVisibleGroups({ subject, permission })
})
