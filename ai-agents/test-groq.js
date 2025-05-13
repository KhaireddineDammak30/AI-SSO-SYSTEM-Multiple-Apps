// test-groq.js
const queryGroqAgent = require('./utils/groqAgent');

queryGroqAgent([
  { role: 'system', content: 'You are a helpful assistant.' },
  { role: 'user', content: 'Say hello.' }
]).then(console.log).catch(console.error);
