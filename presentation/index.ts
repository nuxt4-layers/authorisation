/**
 * Public presentation surface of `@nuxt4-layers/authorisation`
 * (`@nuxt4-layers/authorisation/presentation`).
 *
 * The default pages and components depend on the contract and the client
 * API (`useAuthorisation()`) only, and decide nothing: every action is
 * decided again on the server.
 */

export type { AuthorisationMessageKey, AuthorisationMessages } from './messages'
export { AUTHORISATION_MESSAGES_EN_GB, formatMessage, resolveMessage } from './messages'
export { DELIBERATE_PAIRINGS } from './pairings'
export { authorisationClasses } from './utils/authorisation-classes'
