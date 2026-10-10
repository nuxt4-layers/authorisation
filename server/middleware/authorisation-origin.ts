import { defineEventHandler } from 'h3'
import { useRuntimeConfig } from '#imports'
import { authorisationHttpError, originRejected } from '../internal/http'

/** CSRF defence for `/api/authorisation/*` (docs/contracts.md §16): state-changing requests must come from the configured origin (`NUXT_AUTHORISATION_BASE_URL`). */
export default defineEventHandler((event) => {
  if (originRejected(event, useRuntimeConfig().authorisation?.baseUrl)) throw authorisationHttpError('forbidden')
})
