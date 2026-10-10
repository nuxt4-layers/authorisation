import { AUTHORISATION_APPROVAL_ROUTES, AUTHORISATION_CHANGE_STATES, AUTHORISATION_CHANGE_TYPES, AUTHORISATION_ERROR_CODES, AUTHORISATION_RISK_LEVELS, BUILT_IN_ROLE_IDS, CHANGE_REFUSALS, APPROVAL_REFUSALS, ROLE_ASSIGNMENT_SCOPES } from '../../contracts'

/** The contract's vocabularies the default pages put into words. */
export const ERROR_CODES_FOR_TEST = AUTHORISATION_ERROR_CODES
export const CHANGE_TYPES_FOR_TEST = AUTHORISATION_CHANGE_TYPES
export const STATES_FOR_TEST = [
  ...AUTHORISATION_CHANGE_STATES.map(state => `authorisation.changeState.${state}`),
  ...AUTHORISATION_CHANGE_STATES.map(state => `authorisation.outcome.${state}`),
  ...AUTHORISATION_APPROVAL_ROUTES.map(route => `authorisation.route.${route}`),
  ...AUTHORISATION_RISK_LEVELS.map(risk => `authorisation.risk.${risk}`),
  ...ROLE_ASSIGNMENT_SCOPES.map(scope => `authorisation.scope.${scope}`),
  ...BUILT_IN_ROLE_IDS.map(role => `authorisation.builtInRole.${role}`),
  ...[...CHANGE_REFUSALS, ...APPROVAL_REFUSALS].filter(reason => !['insufficient-assurance', 'digest-mismatch', 'tenant-mismatch'].includes(reason)).map(reason => `authorisation.reason.${reason}`),
]
