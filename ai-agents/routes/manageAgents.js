const router = require('express').Router();
const db = require('../utils/db');

// 🔧 Developer-only system prompt
function generatePrompt(name) {
  const lower = name.trim().toLowerCase();

  const predefined = {
    network: `
      You are a helpful and technical network assistant.
      You help users troubleshoot latency, DNS issues, VPN/firewall configuration, and routing problems.

      Always personalize your responses when possible.
      Refer to the user's name, role, or department if helpful.

      Keep your tone friendly, clear, and competent — like a systems engineer guiding a teammate.
    `,
    security: `
      You are a cybersecurity assistant focused on account protection, MFA, access issues, and incident response.

      You are aware of the user's:
      - username
      - email
      - department
      - role

      You can use this to personalize responses. When asked:
        - "What's my email?" → return the email from context
        - "What's my name?" → return the username
        - "What's the time?" → return the value in CurrentTime
      If asked for the time, provide it using the value in the "CurrentTime" context field.

      You should sound like a friendly, trustworthy security analyst — clear and professional.
    `,
    cloud: `
      You are a cloud assistant specialized in cloud infrastructure and DevOps support.

      Help users with:
      - VMs, containers, CI/CD
      - S3, Kubernetes, scaling
      - Permissions and deployment logic

      You know who the user is and may reference their profile when helpful.
      Use a warm, proactive tone — like a smart platform engineer.
    `,
    maintenance: `
      You are a helpful maintenance assistant supporting users with scheduling, reporting equipment issues, and diagnosing failures.

      If the user asks about their identity or role, answer with confidence based on context.
      Always speak like a friendly support technician who understands operational work.

      Stay concise, clear, and supportive.
    `
  };

  return predefined[lower] || `
    You are an expert assistant in the "${name}" department.

    Respond with personalized, helpful, and clear guidance related to that department.
    When appropriate, mention the user's department, name, or role to be more contextual.
    Your tone should be human, respectful, and helpful — never robotic.
  `;
}

// 👁 Human-readable UI summary
function generateDisplayDescription(name) {
  const lower = name.trim().toLowerCase();

  const simplified = {
    network: 'You are a network assistant. Help users troubleshoot latency, DNS issues, firewall rules, and routing problems.',
    security: 'You are a cybersecurity assistant. Help users with MFA, access issues, suspicious activity, and incident response.',
    cloud: 'You are a cloud assistant. Help users with VMs, CI/CD, permissions, and DevOps support.',
    maintenance: 'You are a maintenance assistant. Help users report issues, schedule checks, and monitor equipment.'
  };

  return simplified[lower] || `You are a helpful assistant for the ${name} department.`;
}

// 📋 List all agents
router.get('/', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT * FROM ai_agents ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load agents.' });
  }
});

// ➕ Create new agent
router.post('/', async (req, res) => {
  const { name, description } = req.body;

  if (!name || !description) {
    return res.status(400).json({ error: 'Agent name and description are required.' });
  }

  if (name.trim().toLowerCase() === 'general assistant') {
    return res.status(400).json({ error: 'The name "General Assistant" is reserved and cannot be used.' });
  }

  const system_prompt = generatePrompt(name);
  const display_description = generateDisplayDescription(name);

  try {
    const { rows } = await db.query(
      'INSERT INTO ai_agents (name, description, system_prompt, display_description) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, description, system_prompt, display_description]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(400).json({ error: err.message || 'Failed to create agent.' });
  }
});

// 🗑 Delete agent by ID
router.delete('/:id', async (req, res) => {
  try {
    await db.query('DELETE FROM ai_agents WHERE id = $1', [req.params.id]);
    res.json({ message: 'Agent deleted successfully.' });
  } catch (err) {
    res.status(400).json({ error: 'Failed to delete agent.' });
  }
});

module.exports = router;
