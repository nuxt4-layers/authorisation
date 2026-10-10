// Recreates the disposable e2e database before the playground server starts.
import pg from 'pg'

const database = 'authorisation_e2e'
const admin = new pg.Client({ connectionString: process.env.AUTHORISATION_TEST_DATABASE_URL })
await admin.connect()
await admin.query(`drop database if exists "${database}" with (force)`)
await admin.query(`create database "${database}"`)
await admin.end()
