// removeApp.js — Delete generated apps by name (slug-safe)

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

// 🔒 Protected apps that cannot be deleted
const protectedApps = ['app1', 'app2'];

function slugify(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function getPortFromEnv(appPath) {
  const envPath = path.join(appPath, '.env');
  if (!fs.existsSync(envPath)) return null;

  const content = fs.readFileSync(envPath, 'utf-8');
  const match = content.match(/^VITE_PORT=(\d+)/m); // ✅ Vite env key
  return match ? match[1] : null;
}

function killPort(port) {
  console.log(`⛔ Attempting to kill any process using port ${port}...`);
  try {
    if (os.platform() === 'win32') {
      execSync(`for /f "tokens=5" %a in ('netstat -aon ^| find ":${port}" ^| find "LISTENING"') do taskkill /f /pid %a`);
    } else {
      execSync(`lsof -ti tcp:${port} | xargs kill -9`);
    }
    console.log(`🛑 Process on port ${port} killed successfully.`);
  } catch (err) {
    console.warn(`⚠️ No process found or failed to kill port ${port}: ${err.message}`);
  }
}

function removeApp(appName) {
  const slug = slugify(appName);
  const appPath = path.join(__dirname, 'generated', slug);

  console.log(`📦 Target app folder: ${appPath}`);

  if (protectedApps.includes(slug)) {
    console.error(`❌ "${appName}" is protected and cannot be deleted.`);
    process.exit(1);
  }

  if (!fs.existsSync(appPath)) {
    console.error(`❌ App folder not found: ${appPath}`);
    process.exit(1);
  }

  const port = getPortFromEnv(appPath);
  if (port) killPort(port);

  try {
    console.log(`🧹 Deleting folder: ${appPath}...`);
    fs.rmSync(appPath, { recursive: true, force: true });
    console.log(`✅ Folder removed successfully.`);
    console.log(`🗑 App "${appName}" deleted (slug: ${slug})`);
  } catch (err) {
    console.error(`❌ Failed to delete app folder:`, err.message);
    process.exit(1);
  }
}

// ✅ CLI usage
if (require.main === module) {
  const [appName] = process.argv.slice(2);
  if (!appName) {
    console.error('❌ Usage: node removeApp.js "App Name"');
    process.exit(1);
  }

  console.log(`🚨 Starting removal of app: "${appName}"`);
  removeApp(appName);
}