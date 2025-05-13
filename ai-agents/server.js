const fs = require('fs');
const https = require('https');
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Routes
app.use('/agent/ask', require('./routes/askAgent'));
app.use('/admin/agents', require('./routes/manageAgents'));

// HTTPS Certs (reuse from ../certs/)
const sslOptions = {
  key: fs.readFileSync('../certs/localhost-key.pem'),
  cert: fs.readFileSync('../certs/localhost.pem')
};

https.createServer(sslOptions, app).listen(process.env.PORT || 5000, () => {
  console.log(`🟢 AI Agents server running on https://localhost:${process.env.PORT || 5000}`);
});
