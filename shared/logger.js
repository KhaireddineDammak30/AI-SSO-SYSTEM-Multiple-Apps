const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

// Setup path to JWT.log
const logPath = path.join(__dirname, 'JWT.log');
fs.mkdirSync(path.dirname(logPath), { recursive: true });

// PostgreSQL connection pool
const pool = new Pool({
  host:     process.env.PG_HOST     || 'localhost',
  port:     process.env.PG_PORT     || 5432,
  user:     process.env.PG_USER     || 'postgres',
  password: process.env.PG_PASSWORD || 'dammak30spl',
  database: process.env.PG_DB       || 'auth-server'
});

// ✅ Verify DB connection at startup
pool.connect()
  .then(client => {
    // console.log('✅ Logger connected to PostgreSQL');
    client.release(); // release connection back to the pool
  })
  .catch(err => {
    console.error('❌ Logger failed to connect to PostgreSQL:', err.message);
  });

/**
 * Logs a structured event to both a file and the PostgreSQL logs table
 * @param {string} context  The type of event (e.g., LOGIN_ISSUED)
 * @param {object} payload  Metadata: uid, ip, browser, etc.
 */
async function logEntry(context, payload = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    context,
    ...payload
  };

  // 1️⃣ Write to JWT.log (file)
  const text = JSON.stringify(entry, null, 2) + '\n\n';
  fs.appendFileSync(logPath, text);

  // 2️⃣ Write to PostgreSQL logs table
  try {
    await pool.query(
      `INSERT INTO logs (timestamp, context, payload)
       VALUES ($1, $2, $3)`,
      [entry.timestamp, context, payload]
    );
  } catch (err) {
    console.error('❌ Failed to insert log into PostgreSQL:', err.message);
  }
}

module.exports = { logEntry };
