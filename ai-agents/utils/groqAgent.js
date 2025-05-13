const axios = require('axios');
require('dotenv').config();

async function queryGroqAgent(messages) {
  try {
    const response = await axios.post(
      'https://api.groq.com/openai/v1/chat/completions',
      {
        model: process.env.GROQ_MODEL || 'mixtral-8x7b-32768',
        messages
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    return response.data.choices[0].message.content;

  } catch (err) {
    console.error('[❌ Groq API Error]', err.response?.data || err.message);
    throw new Error('Failed to contact Groq AI agent');
  }
}

module.exports = queryGroqAgent;
