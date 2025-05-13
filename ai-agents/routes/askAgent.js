const router = require('express').Router();
const queryGroqAgent = require('../utils/groqAgent');
const db = require('../utils/db');

router.post('/', async (req, res) => {
  const { userId, prompt, department } = req.body;

  try {
    // 🧠 Try to find a department-specific agent
    const agentData = await db.query(
      'SELECT system_prompt FROM ai_agents WHERE name = $1',
      [department]
    );

    let system_prompt;
    let agentName = department;

    if (agentData.rows.length) {
      system_prompt = agentData.rows[0].system_prompt;
    } else {
      // 👤 Fallback to built-in general assistant
      agentName = 'General Assistant';
      system_prompt = `
        You are a general-purpose AI assistant for the organization.
        The user contacting you works in a department where no specialized agent exists.

        You know their role, department, and username, which may help you personalize the response.

        Be warm, friendly, and clear.
        If the user asks "what is my name", "what is my department", etc.,
        answer based on the profile provided.

        You can help with general onboarding, support questions, or redirect them politely
        to IT/security/management if appropriate.
      `;
    }

    // 👤 Fetch user details for context
    const userData = await db.query(
      'SELECT username, department, role, email FROM users WHERE id = $1',
      [userId]
    );

    const user = userData.rows[0];
    const now = new Date().toUTCString();

    const messages = [
      { role: 'system', content: system_prompt },
      {
        role: 'user',
        content: `User: ${JSON.stringify(user)}\nCurrentTime: ${now}\nQuestion: ${prompt}`
      }
    ];

    const answer = await queryGroqAgent(messages);
    res.json({ answer });

  } catch (err) {
    console.error('[askAgent] Error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
