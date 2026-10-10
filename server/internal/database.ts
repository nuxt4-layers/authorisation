import type { PostgresPoolLike } from '../../contracts'
import { quoteSchema } from '../database/migrations'

/**
 * PRIVATE. Plain parameterised SQL over the host's pool, and transactions
 * on one of its connections. Each change and its outbox events are written
 * in one transaction, so an event exists if and only if its change
 * committed.
 */

export interface Queryable {
  query<T = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<{ rows: T[] }>
}

interface PoolClientLike extends Queryable {
  release(error?: Error | boolean): void
}

export interface Database extends Queryable {
  /** The quoted schema identifier, safe to interpolate. */
  schema: string
  transaction<T>(run: (client: Queryable) => Promise<T>): Promise<T>
}

export function createDatabase(pool: PostgresPoolLike, schema: string): Database {
  const quoted = quoteSchema(schema)
  return {
    schema: quoted,
    query: <T>(text: string, values: readonly unknown[] = []) => pool.query(text, values) as Promise<{ rows: T[] }>,
    async transaction<T>(run: (client: Queryable) => Promise<T>): Promise<T> {
      const client = await pool.connect() as PoolClientLike
      try {
        await client.query('begin')
        const result = await run(client)
        await client.query('commit')
        client.release()
        return result
      }
      catch (error) {
        await client.query('rollback').catch(() => {})
        client.release(true)
        throw error
      }
    },
  }
}
