import type { AuthorisationClock } from '../../contracts'
import { AuthorisationFailure } from '../../contracts'

/**
 * PRIVATE. The current time, from the host's clock (docs/contracts.md,
 * "Time"). Every time Authorisation keeps or judges comes from here. A clock
 * that throws or answers anything but a valid `Date` fails the operation
 * closed as `unavailable`: a decision is never made on another time.
 */

/** The system clock, used when the host supplies none. */
export const systemAuthorisationClock: AuthorisationClock = Object.freeze({ now: () => new Date() })

/** The clock's time, validated, as a fresh `Date` the caller may keep. */
export function timeFrom(clock: AuthorisationClock): Date {
  let answer: unknown
  try {
    answer = clock.now()
  }
  catch {
    throw new AuthorisationFailure('unavailable', 'clock failed')
  }
  if (!(answer instanceof Date) || !Number.isFinite(answer.getTime())) throw new AuthorisationFailure('unavailable', 'clock answered an invalid time')
  return new Date(answer.getTime())
}
