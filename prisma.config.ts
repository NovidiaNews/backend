import 'dotenv/config'
import { defineConfig } from 'prisma/config'
import * as process from 'process'

const dbUrl = process.env.DATABASE_URL
if (!dbUrl) {
  throw new Error('DATABASE_URL is not set. Add it to your environment or to a .env file')
}

export default defineConfig({
  datasource: {
    url: dbUrl,
  },
})