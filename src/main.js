/**
 * Apify Actor Entry Point
 * ========================
 * Runs the project health scanner as an Apify actor.
 * Accepts a zip URL or GitHub repo URL as input,
 * downloads/clones it, scans, and returns results.
 */

const { Actor } = require('apify');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { scanProject, checkSecretsOnly, checkDependenciesOnly, checkLicensesOnly, quickHealthScore } = require('./scanner');

Actor.main(async () => {
  const input = await Actor.getInput();
  if (!input) {
    throw new Error('No input provided. Provide { "url": "...", "tool": "scan_project" }');
  }

  const { url, tool = 'scan_project', githubRepo } = input;
  const workDir = path.join('/tmp', `scan-${Date.now()}`);
  fs.mkdirSync(workDir, { recursive: true });

  let projectDir = workDir;

  try {
    if (githubRepo) {
      // Clone GitHub repo
      console.log(`Cloning ${githubRepo}...`);
      execSync(`git clone --depth 1 ${githubRepo} ${workDir}/repo`, {
        encoding: 'utf-8',
        timeout: 60000,
      });
      projectDir = path.join(workDir, 'repo');
    } else if (url) {
      // Download and extract zip
      console.log(`Downloading ${url}...`);
      const zipPath = path.join(workDir, 'project.zip');
      await downloadFile(url, zipPath);
      execSync(`unzip -o ${zipPath} -d ${workDir}/extracted`, {
        encoding: 'utf-8',
        timeout: 30000,
      });
      // Find the actual project root
      const extracted = path.join(workDir, 'extracted');
      const entries = fs.readdirSync(extracted);
      projectDir = entries.length === 1 && fs.statSync(path.join(extracted, entries[0])).isDirectory()
        ? path.join(extracted, entries[0])
        : extracted;
    } else {
      throw new Error('Provide either "url" (zip URL) or "githubRepo" (Git clone URL)');
    }

    // Run the requested tool
    let result;
    switch (tool) {
      case 'scan_project': result = scanProject(projectDir); break;
      case 'check_secrets': result = checkSecretsOnly(projectDir); break;
      case 'check_dependencies': result = checkDependenciesOnly(projectDir); break;
      case 'check_licenses': result = checkLicensesOnly(projectDir); break;
      case 'health_score': result = quickHealthScore(projectDir); break;
      default: throw new Error(`Unknown tool: ${tool}`);
    }

    await Actor.pushData(result);
    console.log('Scan complete. Results pushed to dataset.');
  } finally {
    // Cleanup
    try { execSync(`rm -rf ${workDir}`); } catch {}
  }
});

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const protocol = url.startsWith('https') ? https : http;
    const file = fs.createWriteStream(dest);
    protocol.get(url, (response) => {
      if (response.statusCode === 301 || response.statusCode === 302) {
        return downloadFile(response.headers.location, dest).then(resolve).catch(reject);
      }
      response.pipe(file);
      file.on('finish', () => { file.close(); resolve(); });
    }).on('error', reject);
  });
}
