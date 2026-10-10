import { randomUUID } from 'node:crypto'
import type { AuthorisationEvent, AuthorisationEventPublisher, AuthorisationEventType } from '../../contracts'
import { AuthorisationFailure, authorisationEventSchema } from '../../contracts'
import type { Database, Queryable } from './database'

/**
 * PRIVATE. Authorisation's transactional outbox (docs/contracts.md §8).
 * `enqueue` writes an event in the caller's transaction, after checking it
 * against the contract, so a malformed event fails the change rather than
 * reaching a consumer. The relay publishes in order, at least once.
 */

export type EventInput = {
  [T in AuthorisationEventType]: { type: T, data: Extract<AuthorisationEvent, { type: T }>['data'] }
}[AuthorisationEventType]

export async function enqueue(client: Queryable, schema: string, input: EventInput, context: { actorPrincipalId: string | null, correlationId: string, at: Date }): Promise<AuthorisationEvent> {
  const event = authorisationEventSchema.parse({
    eventId: randomUUID(),
    type: input.type,
    occurredAt: context.at.toISOString(),
    correlationId: context.correlationId,
    actorPrincipalId: context.actorPrincipalId,
    data: input.data,
  }) as AuthorisationEvent
  await client.query(
    `insert into ${schema}."outbox" ("event_id", "type", "payload", "occurred_at") values ($1, $2, $3::jsonb, $4)`,
    [event.eventId, event.type, JSON.stringify(event), event.occurredAt],
  )
  return event
}

export interface RelayResult {
  /** Events published and marked relayed. */
  published: number
  /** 1 when the relay stopped at an event it could not publish (it stays, and is retried next run); otherwise 0. */
  failed: number
}

/**
 * Publishes up to `limit` unpublished events in order. Stops at the first
 * that fails (or does not match the contract), leaving it and those after it
 * for the next run; marks relayed only what `publish` accepted.
 */
export async function relayOutbox(db: Database, publisher: AuthorisationEventPublisher, limit: number, at: () => Date): Promise<RelayResult> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new AuthorisationFailure('validation-failed', 'limit-out-of-range')
  if (typeof publisher?.publish !== 'function') throw new AuthorisationFailure('validation-failed', 'publisher-missing')
  return db.transaction(async (client) => {
    const { rows } = await client.query<{ sequence: string, payload: unknown }>(`select * from ${db.schema}.claim_outbox($1)`, [limit])
    const done: string[] = []
    let failed = 0
    for (const row of rows) {
      const parsed = authorisationEventSchema.safeParse(row.payload)
      if (!parsed.success) {
        console.error(`[authorisation] outbox event ${row.sequence} does not match the contract; not published`)
        failed = 1
        break
      }
      try {
        await publisher.publish(parsed.data as AuthorisationEvent)
        done.push(row.sequence)
      }
      catch (error) {
        console.error(`[authorisation] publishing outbox event ${row.sequence} failed:`, error instanceof Error ? error.message : error)
        failed = 1
        break
      }
    }
    if (done.length > 0) await client.query(`select ${db.schema}.mark_outbox_published($1::bigint[], $2)`, [done, at().toISOString()])
    return { published: done.length, failed }
  })
}
