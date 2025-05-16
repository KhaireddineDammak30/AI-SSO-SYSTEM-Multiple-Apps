// auth-server/routes/admin-apps.js

import { fileURLToPath } from 'url';
import express from 'express';
import path from 'path';
import fs from 'fs';
import spawn from 'cross-spawn';
import { execPath } from 'process';
import { pool } from '../db.js';

const router = express.Router();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 🟢 GET all apps
router.get('/', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM apps ORDER BY created_at');
    res.json(rows);
  } catch (err) {
    console.error('❌ Failed to fetch apps:', err);
    res.status(500).json({ msg: 'Internal server error' });
  }
});

// 🟢 POST: create new app (without launching it)
router.post('/', async (req, res) => {
  const { name, port, description } = req.body;

  if (!name || !port || isNaN(Number(port)) || !description?.trim()) {
    return res.status(400).json({ msg: '❌ Name, port, and description are required' });
  }

  try {
    const exists = await pool.query('SELECT 1 FROM apps WHERE port = $1 OR name = $2', [port, name]);
    if (exists.rowCount) {
      return res.status(409).json({ msg: '⚠️ Port or name already in use' });
    }

    const projectRoot = path.resolve(__dirname, '..');
    const generatorPath = path.join(projectRoot, '..', 'app-factory', 'generateApp.js');

    if (!fs.existsSync(generatorPath)) {
      console.error('❌ generateApp.js not found:', generatorPath);
      return res.status(500).json({ msg: 'Internal generator script missing' });
    }

    console.log(`🚧 Generating app "${name}" on port ${port}...`);

    const generator = spawn(execPath, [generatorPath, name, port.toString()], {
      cwd: path.dirname(generatorPath),
      stdio: 'inherit',
      shell: false
    });

    let responded = false;

    generator.on('error', err => {
      console.error('❌ Generator spawn error:', err);
      if (!responded) {
        responded = true;
        return res.status(500).json({ msg: '❌ Could not start generator process' });
      }
    });

    generator.on('close', async (exitCode) => {
      if (exitCode !== 0) {
        console.error(`❌ generateApp.js exited with code ${exitCode}`);
        if (!responded) {
          responded = true;
          return res.status(500).json({ msg: 'App generation failed' });
        }
        return;
      }

      try {
        const { rows } = await pool.query(`
          INSERT INTO apps (name, port, description)
          VALUES ($1, $2, $3)
          RETURNING *`,
          [name, port, description]
        );

        console.log(`✅ App "${name}" created and saved to DB`);
        if (!responded) {
          responded = true;
          return res.status(201).json(rows[0]);
        }
      } catch (dbErr) {
        console.error('❌ DB insert error:', dbErr);
        if (!responded) {
          responded = true;
          return res.status(500).json({ msg: 'App created but not saved to DB' });
        }
      }
    });

  } catch (err) {
    console.error('❌ Unexpected error in POST /admin/apps:', err);
    if (!res.headersSent) {
      return res.status(500).json({ msg: 'Internal server error' });
    }
  }
});

// 🟠 POST: launch an existing app
router.post('/:id/launch', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT * FROM apps WHERE id = $1', [id]);
    if (!result.rowCount) return res.status(404).json({ msg: 'App not found' });

    const app = result.rows[0];
    const slug = app.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    const appPath = path.join(__dirname, '..', '..', 'app-factory', 'generated', slug);

    if (!fs.existsSync(appPath)) {
      console.error('❌ Generated app folder not found:', appPath);
      return res.status(404).json({ msg: 'App folder not found on disk' });
    }

    console.log(`🚀 Launching app "${app.name}" on port ${app.port}...`);

    const child = spawn(
      process.execPath,
      ['node_modules/vite/bin/vite.js', 'dev'], // ✅ Use vite.js to run dev server
      {
        cwd: appPath,
        detached: true,
        stdio: 'ignore',
        windowsHide: true,
        shell: false,
        env: {
          ...process.env,
          PORT: app.port.toString()
        }
      }
    );

    child.unref();

    res.json({ msg: `🚀 App "${app.name}" launched.` });

  } catch (err) {
    console.error('❌ Failed to launch app:', err);
    res.status(500).json({ msg: 'Failed to launch app' });
  }
});

// 🔴 DELETE app (if not fixed)
router.delete('/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT * FROM apps WHERE id = $1', [id]);
    if (!result.rowCount) return res.status(404).json({ msg: 'App not found' });

    const app = result.rows[0];
    if (app.is_fixed) return res.status(403).json({ msg: 'Cannot delete fixed app' });

    console.log(`🧨 Deleting app "${app.name}" from database...`);
    await pool.query('DELETE FROM apps WHERE id = $1', [id]);
    console.log(`✅ DB entry for "${app.name}" removed.`);

    // Trigger removeApp.js
    const removePath = path.join(__dirname, '..', '..', 'app-factory', 'removeApp.js');
    console.log(`🧪 Spawning removeApp.js for "${app.name}" at path: ${removePath}`);

    const child = spawn(process.execPath, [removePath, app.name], {
      cwd: path.join(__dirname, '..', '..', 'app-factory'),
      stdio: 'inherit',
      shell: false,
    });

    // You can track process end if desired:
    child.on('close', (code) => {
      console.log(`🧹 removeApp.js exited with code ${code}`);
    });

    res.json({ msg: `🗑 App "${app.name}" deleted`, id });

  } catch (err) {
    console.error('❌ Failed to delete app:', err);
    res.status(500).json({ msg: 'Failed to delete app' });
  }
});


export default router;


