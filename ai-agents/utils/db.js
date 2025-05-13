const { Client } = require('pg');
require('dotenv').config();

const db = new Client({
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE,
});

db.connect();
module.exports = db;
