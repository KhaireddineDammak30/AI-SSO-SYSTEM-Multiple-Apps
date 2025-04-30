// CommonJS module

const fs   = require('fs');
const path = require('path');

// log file sits next to this script
const logPath = path.join(__dirname, 'JWT.log');

// ensure the directory exists
fs.mkdirSync(path.dirname(logPath), { recursive: true });

/**
 * Append a pretty‑printed JSON entry + blank line.
 * @param {string} context   e.g. 'REGISTER','SIGN','REFRESH','MFA_SETUP'
 * @param {object} payload   any extra fields: uid, browser, loginCount, token…
 */
function logEntry(context, payload) {
  const entry = {
    timestamp: new Date().toISOString(),
    context,
    ...payload
  };
  const text = JSON.stringify(entry, null, 2) + '\n\n';
  fs.appendFileSync(logPath, text);
}

module.exports = { logEntry };
