// generateApp.js — Dynamically clone app1-template with custom name/port

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');

// Inject environment variables for .env generation
function setEnv(appName, port) {
  process.env.APP_NAME = appName;
  process.env.APP_PORT = port.toString();
}

// Kill process using a port
function killPort(port) {
  try {
    if (os.platform() === 'win32') {
      execSync(`for /f "tokens=5" %a in ('netstat -aon ^| find ":${port}" ^| find "LISTENING"') do taskkill /f /pid %a`);
    } else {
      execSync(`lsof -ti tcp:${port} | xargs kill -9`);
    }
    console.log(`🛑 Killed process using port ${port}`);
  } catch (err) {
    console.warn(`⚠️ No process found or failed to kill port ${port}: ${err.message}`);
  }
}

// Copy template with .env replacement
function copyDirWithEnv(src, dest) {
  fs.mkdirSync(dest, { recursive: true });

  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirWithEnv(srcPath, destPath);
    } else {
      if (entry.name === '.env.template') {
        const envContent = fs
          .readFileSync(srcPath, 'utf-8')
          .replace('{{PORT}}', process.env.APP_PORT)
          .replace('{{APP_NAME}}', process.env.APP_NAME);

        fs.writeFileSync(path.join(dest, '.env'), envContent);
      } else {
        fs.copyFileSync(srcPath, destPath);
      }
    }
  }
}

// Copy certs for HTTPS
function copyCerts(outputPath) {
  const certsSrc = path.join(__dirname, '..', 'certs');
  const certsDest = path.join(outputPath, 'certs');

  if (fs.existsSync(certsSrc)) {
    fs.mkdirSync(certsDest, { recursive: true });
    fs.readdirSync(certsSrc).forEach(file => {
      fs.copyFileSync(path.join(certsSrc, file), path.join(certsDest, file));
    });
    console.log('🔐 SSL certificates copied to app.');
  } else {
    console.warn('⚠️  certs folder not found. HTTPS may not work.');
  }
}

// Main generator
function generateApp(appName, port) {
  const slug = appName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  const templatePath = path.join(__dirname, 'templates', 'app1-template');
  const outputPath = path.join(__dirname, 'generated', slug);

  if (!fs.existsSync(templatePath)) {
    console.error(`❌ Template not found: ${templatePath}`);
    process.exit(1);
  }

  if (fs.existsSync(outputPath)) {
    console.log(`⚠️ App "${slug}" already exists. Deleting...`);

    // ✅ Kill process on existing app's port
    const envPath = path.join(outputPath, '.env');
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, 'utf-8');
      const match = content.match(/^VITE_PORT=(\d+)/m);
      if (match) killPort(match[1]);
    }

    try {
      fs.rmSync(outputPath, { recursive: true, force: true });
    } catch (err) {
      console.error(`❌ Could not delete folder: ${outputPath}`);
      console.error(`🔒 Reason: ${err.message}`);
      console.error(`💡 Close any editor or terminal using this folder and try again.`);
      process.exit(1);
    }
  }

  setEnv(appName, port);
  copyDirWithEnv(templatePath, outputPath);
  copyCerts(outputPath);

  console.log(`✅ App "${appName}" created at ${outputPath}`);
  console.log('📦 Installing dependencies...');

  const install = spawn('npm', ['install'], {
    cwd: outputPath,
    stdio: 'inherit',
    shell: true
  });

  install.on('close', code => {
    if (code !== 0) {
      console.error(`❌ npm install failed with code ${code}`);
      process.exit(code);
    }

    console.log('✅ Dependencies installed. App is ready.');
    process.exit(0);
  });

  install.on('error', err => {
    console.error('❌ Failed to run npm install:', err);
    process.exit(1);
  });
}

// CLI entry point
if (require.main === module) {
  const [appName, portRaw] = process.argv.slice(2);
  const port = parseInt(portRaw?.trim?.(), 10);

  if (!appName || !port || isNaN(port) || port < 1024 || port > 65535) {
    console.error('❌ Invalid app name or port.');
    console.error('Usage: node generateApp.js "App Name" 3003');
    process.exit(1);
  }

  generateApp(appName.trim(), port);
}
