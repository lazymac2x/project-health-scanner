/**
 * Project Health Scanner — Core Scanning Engine
 * ===============================================
 * Performs deep, local-only analysis of project directories:
 * dependency audit, secret detection, license compliance,
 * code quality, git health, security headers, and scoring.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const {
  SECRET_PATTERNS,
  KNOWN_CVES,
  LICENSE_INFO,
  GITIGNORE_RECOMMENDATIONS,
  SECURITY_MIDDLEWARE,
  BINARY_EXTENSIONS,
} = require('./patterns');

// ─── Helpers ─────────────────────────────────────────────

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'vendor', 'venv', '.venv', '__pycache__',
  'dist', 'build', '.next', '.nuxt', 'coverage', '.pytest_cache',
  '.mypy_cache', '.tox', 'egg-info', '.eggs', 'target',
]);

const TEXT_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.pyw', '.rb', '.go', '.rs', '.java', '.kt', '.scala',
  '.c', '.cpp', '.h', '.hpp', '.cs', '.swift', '.m',
  '.php', '.pl', '.pm', '.sh', '.bash', '.zsh', '.fish',
  '.json', '.yaml', '.yml', '.toml', '.xml', '.ini', '.cfg', '.conf',
  '.env', '.env.local', '.env.development', '.env.production',
  '.html', '.htm', '.css', '.scss', '.less', '.sass',
  '.sql', '.graphql', '.gql', '.prisma',
  '.md', '.txt', '.rst', '.tex',
  '.dockerfile', '.tf', '.hcl',
  '.vue', '.svelte', '.astro',
]);

function walkDir(dir, maxDepth = 8, depth = 0) {
  const results = [];
  if (depth > maxDepth) return results;

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.git')) {
        results.push(...walkDir(fullPath, maxDepth, depth + 1));
      }
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }
  return results;
}

function readFileSafe(filePath, maxSize = 512 * 1024) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > maxSize) return null;
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

function isTextFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath).toLowerCase();
  if (TEXT_EXTENSIONS.has(ext)) return true;
  if (basename === '.env' || basename.startsWith('.env.')) return true;
  if (['makefile', 'dockerfile', 'procfile', 'gemfile', 'rakefile', 'vagrantfile'].includes(basename)) return true;
  if (ext === '' || ext === '.lock') return false;
  return false;
}

function parseVersion(v) {
  if (!v) return [0, 0, 0];
  const cleaned = v.replace(/^[~^>=<!\s]+/, '').split('-')[0];
  const parts = cleaned.split('.').map(Number);
  return [parts[0] || 0, parts[1] || 0, parts[2] || 0];
}

function versionBelow(current, target) {
  const [ca, cb, cc] = parseVersion(current);
  const [ta, tb, tc] = parseVersion(target);
  if (ca !== ta) return ca < ta;
  if (cb !== tb) return cb < tb;
  return cc < tc;
}

function detectProjectType(projectDir) {
  const types = [];
  if (fs.existsSync(path.join(projectDir, 'package.json'))) types.push('node');
  if (fs.existsSync(path.join(projectDir, 'requirements.txt')) || fs.existsSync(path.join(projectDir, 'pyproject.toml')) || fs.existsSync(path.join(projectDir, 'setup.py'))) types.push('python');
  if (fs.existsSync(path.join(projectDir, 'go.mod'))) types.push('go');
  if (fs.existsSync(path.join(projectDir, 'Cargo.toml'))) types.push('rust');
  if (fs.existsSync(path.join(projectDir, 'Gemfile'))) types.push('ruby');
  if (types.length === 0) types.push('unknown');
  return types;
}

// ─── 1. Dependency Audit ─────────────────────────────────

function auditDependencies(projectDir) {
  const issues = [];
  const stats = { total: 0, vulnerable: 0, outdatedPatterns: 0 };

  // Node.js — package.json
  const pkgPath = path.join(projectDir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSafe(pkgPath));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      stats.total += Object.keys(allDeps).length;

      for (const [name, version] of Object.entries(allDeps)) {
        if (KNOWN_CVES[name]) {
          for (const cve of KNOWN_CVES[name]) {
            if (versionBelow(version, cve.below)) {
              stats.vulnerable++;
              issues.push({
                type: 'vulnerability',
                severity: cve.severity,
                package: name,
                currentVersion: version,
                cve: cve.cve,
                description: cve.description,
                fix: cve.fix,
              });
            }
          }
        }
      }

      // Check for wildcard or * versions
      for (const [name, version] of Object.entries(allDeps)) {
        if (version === '*' || version === 'latest') {
          issues.push({
            type: 'unpinned_version',
            severity: 'medium',
            package: name,
            currentVersion: version,
            description: `Package "${name}" uses unpinned version "${version}" — builds are not reproducible`,
            fix: `Pin to a specific version: npm install ${name}@latest --save-exact`,
          });
        }
      }

      // Check if package-lock.json exists
      if (!fs.existsSync(path.join(projectDir, 'package-lock.json')) && !fs.existsSync(path.join(projectDir, 'yarn.lock')) && !fs.existsSync(path.join(projectDir, 'pnpm-lock.yaml'))) {
        issues.push({
          type: 'missing_lockfile',
          severity: 'medium',
          description: 'No lockfile found (package-lock.json, yarn.lock, or pnpm-lock.yaml)',
          fix: 'Run "npm install" to generate package-lock.json for reproducible builds',
        });
      }
    } catch (e) {
      issues.push({ type: 'parse_error', severity: 'low', description: `Failed to parse package.json: ${e.message}` });
    }
  }

  // Python — requirements.txt
  const reqPath = path.join(projectDir, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    const content = readFileSafe(reqPath);
    if (content) {
      const lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
      for (const line of lines) {
        const match = line.match(/^([a-zA-Z0-9_-]+)\s*(?:==|>=|~=)\s*([0-9.]+)/);
        if (match) {
          const [, name, version] = match;
          stats.total++;
          const normalizedName = name.toLowerCase().replace(/-/g, '');
          for (const [knownName, cves] of Object.entries(KNOWN_CVES)) {
            if (knownName.toLowerCase().replace(/-/g, '') === normalizedName) {
              for (const cve of cves) {
                if (versionBelow(version, cve.below)) {
                  stats.vulnerable++;
                  issues.push({
                    type: 'vulnerability',
                    severity: cve.severity,
                    package: name,
                    currentVersion: version,
                    cve: cve.cve,
                    description: cve.description,
                    fix: cve.fix,
                  });
                }
              }
            }
          }
        }

        // Unpinned deps
        if (/^[a-zA-Z0-9_-]+\s*$/.test(line.trim())) {
          stats.total++;
          issues.push({
            type: 'unpinned_version',
            severity: 'medium',
            package: line.trim(),
            description: `Python package "${line.trim()}" has no version pin`,
            fix: `Pin the version: ${line.trim()}==<version>`,
          });
        }
      }
    }
  }

  // Go — go.mod
  const goModPath = path.join(projectDir, 'go.mod');
  if (fs.existsSync(goModPath)) {
    const content = readFileSafe(goModPath);
    if (content) {
      const reqLines = content.match(/require\s*\(([\s\S]*?)\)/);
      if (reqLines) {
        const deps = reqLines[1].split('\n').filter(l => l.trim() && !l.startsWith('//'));
        stats.total += deps.length;
      }
    }
  }

  return { issues, stats };
}

// ─── 2. Secret Detection ─────────────────────────────────

function detectSecrets(projectDir) {
  const issues = [];
  const files = walkDir(projectDir);
  let scannedFiles = 0;

  for (const filePath of files) {
    if (!isTextFile(filePath)) continue;
    const content = readFileSafe(filePath);
    if (!content) continue;
    scannedFiles++;

    const relativePath = path.relative(projectDir, filePath);
    const lines = content.split('\n');

    for (const secretDef of SECRET_PATTERNS) {
      // If pattern is file-specific, check filename
      if (secretDef.filePattern && !secretDef.filePattern.test(filePath)) continue;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Skip comments and test fixtures
        if (line.trim().startsWith('//') && !line.includes('=')) continue;
        if (line.trim().startsWith('#') && !line.includes('=')) continue;
        if (/example|placeholder|your[_-]|xxx|changeme|TODO/i.test(line)) continue;

        if (secretDef.pattern.test(line)) {
          // Mask the secret in output
          const maskedLine = line.length > 120 ? line.substring(0, 120) + '...' : line;
          issues.push({
            type: 'secret',
            severity: secretDef.severity,
            name: secretDef.name,
            file: relativePath,
            line: i + 1,
            preview: maskedLine.replace(/([A-Za-z0-9_\-/+=]{8})[A-Za-z0-9_\-/+=]{4,}/g, '$1********'),
            description: secretDef.description,
            fix: secretDef.fix,
          });
          break; // One match per pattern per file is enough
        }
      }
    }
  }

  return { issues, stats: { scannedFiles, secretsFound: issues.length } };
}

// ─── 3. License Compliance ───────────────────────────────

function checkLicenses(projectDir) {
  const issues = [];
  let projectLicense = null;

  // Detect project's own license
  const licenseFiles = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENCE', 'COPYING'];
  for (const lf of licenseFiles) {
    const lfPath = path.join(projectDir, lf);
    if (fs.existsSync(lfPath)) {
      const content = readFileSafe(lfPath);
      if (content) {
        projectLicense = detectLicenseType(content);
        break;
      }
    }
  }

  // Also check package.json license field
  const pkgPath = path.join(projectDir, 'package.json');
  if (!projectLicense && fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSafe(pkgPath));
      if (pkg.license) projectLicense = pkg.license;
    } catch {}
  }

  if (!projectLicense) {
    issues.push({
      type: 'missing_license',
      severity: 'medium',
      description: 'No LICENSE file found in project root',
      fix: 'Add a LICENSE file. MIT is recommended for open source: https://choosealicense.com/',
    });
  }

  // Check dependency licenses from node_modules
  const nmDir = path.join(projectDir, 'node_modules');
  if (fs.existsSync(nmDir)) {
    let entries;
    try { entries = fs.readdirSync(nmDir, { withFileTypes: true }); } catch { entries = []; }

    const depDirs = [];
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith('@')) {
        // Scoped packages
        try {
          const scopedEntries = fs.readdirSync(path.join(nmDir, entry.name), { withFileTypes: true });
          for (const se of scopedEntries) {
            if (se.isDirectory()) depDirs.push(path.join(nmDir, entry.name, se.name));
          }
        } catch {}
      } else {
        depDirs.push(path.join(nmDir, entry.name));
      }
    }

    const licenseBreakdown = { permissive: 0, 'weak-copyleft': 0, copyleft: 0, restrictive: 0, unknown: 0 };

    for (const depDir of depDirs) {
      const depPkgPath = path.join(depDir, 'package.json');
      if (!fs.existsSync(depPkgPath)) continue;

      try {
        const depPkg = JSON.parse(readFileSafe(depPkgPath));
        const depName = depPkg.name || path.basename(depDir);
        let depLicense = depPkg.license;
        if (typeof depLicense === 'object') depLicense = depLicense.type;

        if (!depLicense) {
          licenseBreakdown.unknown++;
          continue;
        }

        const normalized = normalizeLicense(depLicense);
        const info = LICENSE_INFO[normalized];

        if (info) {
          licenseBreakdown[info.type] = (licenseBreakdown[info.type] || 0) + 1;

          if (info.risk === 'critical') {
            issues.push({
              type: 'license_conflict',
              severity: 'critical',
              package: depName,
              license: depLicense,
              description: `${depName} uses ${depLicense} — this is a strong copyleft license that may require your entire project to be open-sourced under the same license`,
              fix: `Replace ${depName} with an MIT/Apache-2.0 licensed alternative, or ensure your project complies with ${depLicense}`,
            });
          } else if (info.risk === 'high') {
            issues.push({
              type: 'license_warning',
              severity: 'high',
              package: depName,
              license: depLicense,
              description: `${depName} uses ${depLicense} — copyleft license, may affect distribution`,
              fix: `Review ${depLicense} requirements or find a permissively-licensed alternative`,
            });
          }
        } else {
          licenseBreakdown.unknown++;
        }
      } catch {}
    }

    return { issues, projectLicense, breakdown: licenseBreakdown, stats: { totalDepsChecked: depDirs.length } };
  }

  return { issues, projectLicense, breakdown: {}, stats: { totalDepsChecked: 0 } };
}

function detectLicenseType(content) {
  const c = content.toLowerCase();
  if (c.includes('mit license') || c.includes('permission is hereby granted, free of charge')) return 'MIT';
  if (c.includes('apache license') && c.includes('version 2.0')) return 'Apache-2.0';
  if (c.includes('gnu general public license') && c.includes('version 3')) return 'GPL-3.0';
  if (c.includes('gnu general public license') && c.includes('version 2')) return 'GPL-2.0';
  if (c.includes('gnu lesser general public license')) return 'LGPL-3.0';
  if (c.includes('bsd 2-clause') || c.includes('redistribution and use in source and binary')) return 'BSD-2-Clause';
  if (c.includes('bsd 3-clause')) return 'BSD-3-Clause';
  if (c.includes('isc license')) return 'ISC';
  if (c.includes('unlicense') || c.includes('this is free and unencumbered')) return 'Unlicense';
  if (c.includes('mozilla public license')) return 'MPL-2.0';
  return 'Unknown';
}

function normalizeLicense(license) {
  if (!license) return 'Unknown';
  const l = license.trim();
  // Handle SPDX expressions
  if (l.includes(' OR ')) {
    const parts = l.split(' OR ').map(p => p.trim().replace(/[()]/g, ''));
    // Pick the most permissive
    for (const p of parts) {
      if (LICENSE_INFO[p] && LICENSE_INFO[p].type === 'permissive') return p;
    }
    return parts[0];
  }
  return l;
}

// ─── 4. Code Quality ─────────────────────────────────────

function analyzeCodeQuality(projectDir) {
  const issues = [];
  const files = walkDir(projectDir);
  const stats = { totalFiles: 0, totalLines: 0, largeFiles: 0, todoCount: 0, fixmeCount: 0, hackCount: 0 };

  const importMap = new Map(); // file -> set of imported modules
  const allFiles = new Set();  // all source files by relative path
  const importedFiles = new Set(); // files that are imported somewhere

  // First pass: collect all files and their imports
  for (const filePath of files) {
    if (!isTextFile(filePath)) continue;
    const ext = path.extname(filePath).toLowerCase();
    if (!['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.go', '.rs', '.rb'].includes(ext)) continue;

    const relativePath = path.relative(projectDir, filePath);
    allFiles.add(relativePath);
    stats.totalFiles++;

    const content = readFileSafe(filePath);
    if (!content) continue;

    const lines = content.split('\n');
    stats.totalLines += lines.length;

    // Large file detection
    if (lines.length > 500) {
      stats.largeFiles++;
      issues.push({
        type: 'large_file',
        severity: 'low',
        file: relativePath,
        lines: lines.length,
        description: `File has ${lines.length} lines — consider splitting into smaller modules`,
        fix: `Break this file into smaller, focused modules (aim for <300 lines per file)`,
      });
    }

    // TODO/FIXME/HACK counting
    for (const line of lines) {
      if (/\bTODO\b/i.test(line)) stats.todoCount++;
      if (/\bFIXME\b/i.test(line)) stats.fixmeCount++;
      if (/\bHACK\b/i.test(line)) stats.hackCount++;
    }

    // Collect imports for dead file detection
    const imports = new Set();
    for (const line of lines) {
      // JS/TS imports
      let m = line.match(/(?:require|import)\s*\(?['"]([^'"]+)['"]\)?/);
      if (m) imports.add(m[1]);
      m = line.match(/from\s+['"]([^'"]+)['"]/);
      if (m) imports.add(m[1]);
      // Python imports
      m = line.match(/(?:from|import)\s+([a-zA-Z0-9_.]+)/);
      if (m) imports.add(m[1]);
    }
    importMap.set(relativePath, imports);
  }

  // Resolve relative imports to detect dead files
  for (const [importer, imports] of importMap) {
    for (const imp of imports) {
      if (imp.startsWith('.')) {
        const importerDir = path.dirname(importer);
        const resolved = path.normalize(path.join(importerDir, imp));
        // Try common extensions
        for (const ext of ['', '.js', '.jsx', '.ts', '.tsx', '/index.js', '/index.ts']) {
          importedFiles.add(resolved + ext);
        }
      }
    }
  }

  // Dead file detection (files not imported by anything)
  const entryPatterns = [
    /^(index|main|app|server|cli)\.[jt]sx?$/,
    /^src\/(index|main|app|server)\.[jt]sx?$/,
    /\.test\.|\.spec\.|__test__|__spec__/,
    /\.config\.|\.setup\./,
    /^(jest|babel|webpack|vite|rollup|tsconfig|tailwind)/,
  ];

  let deadFiles = 0;
  for (const file of allFiles) {
    const isEntry = entryPatterns.some(p => p.test(file));
    if (isEntry) continue;

    const fileWithoutExt = file.replace(/\.[^.]+$/, '');
    const isImported = importedFiles.has(file) || importedFiles.has(fileWithoutExt);
    if (!isImported) {
      deadFiles++;
      if (deadFiles <= 10) { // Limit output
        issues.push({
          type: 'potentially_dead_file',
          severity: 'low',
          file,
          description: `File does not appear to be imported by any other file`,
          fix: `Verify this file is still needed. If not, remove it to reduce project complexity`,
        });
      }
    }
  }

  if (stats.todoCount + stats.fixmeCount + stats.hackCount > 20) {
    issues.push({
      type: 'tech_debt_markers',
      severity: 'medium',
      description: `High number of code markers: ${stats.todoCount} TODOs, ${stats.fixmeCount} FIXMEs, ${stats.hackCount} HACKs`,
      fix: 'Schedule a tech debt sprint to address these items',
    });
  }

  stats.deadFiles = deadFiles;
  return { issues, stats };
}

// ─── 5. Git Health ───────────────────────────────────────

function checkGitHealth(projectDir) {
  const issues = [];
  const stats = { isGitRepo: false, uncommittedChanges: 0, binaryFilesTracked: 0 };
  const gitDir = path.join(projectDir, '.git');

  if (!fs.existsSync(gitDir)) {
    issues.push({
      type: 'no_git',
      severity: 'medium',
      description: 'Directory is not a git repository',
      fix: 'Run "git init" to initialize version control',
    });
    return { issues, stats };
  }

  stats.isGitRepo = true;

  // Check uncommitted changes
  try {
    const status = execSync('git status --porcelain', { cwd: projectDir, encoding: 'utf-8', timeout: 10000 });
    const changes = status.trim().split('\n').filter(l => l.trim());
    stats.uncommittedChanges = changes.length;
    if (changes.length > 0) {
      issues.push({
        type: 'uncommitted_changes',
        severity: 'low',
        count: changes.length,
        description: `${changes.length} uncommitted change(s) detected`,
        fix: 'Commit or stash your changes regularly',
      });
    }
  } catch {}

  // Check for large binary files tracked by git
  try {
    const tracked = execSync('git ls-files', { cwd: projectDir, encoding: 'utf-8', timeout: 10000 });
    const trackedFiles = tracked.trim().split('\n').filter(l => l.trim());

    for (const file of trackedFiles) {
      const ext = path.extname(file).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) {
        stats.binaryFilesTracked++;
        const fullPath = path.join(projectDir, file);
        let size = 0;
        try { size = fs.statSync(fullPath).size; } catch {}

        if (size > 100 * 1024) { // > 100KB
          issues.push({
            type: 'large_binary_in_git',
            severity: 'high',
            file,
            size: `${(size / 1024).toFixed(0)} KB`,
            description: `Large binary file "${file}" (${(size / 1024).toFixed(0)} KB) tracked in git — bloats repo history`,
            fix: `Remove with "git rm --cached ${file}", add to .gitignore, use Git LFS for large binaries`,
          });
        }
      }
    }
  } catch {}

  // Check .gitignore completeness
  const types = detectProjectType(projectDir);
  const gitignorePath = path.join(projectDir, '.gitignore');
  let gitignoreContent = '';

  if (!fs.existsSync(gitignorePath)) {
    issues.push({
      type: 'missing_gitignore',
      severity: 'high',
      description: 'No .gitignore file found',
      fix: 'Create a .gitignore file. Use gitignore.io or GitHub templates',
    });
  } else {
    gitignoreContent = readFileSafe(gitignorePath) || '';
  }

  if (gitignoreContent) {
    const missing = [];
    const recommended = [...GITIGNORE_RECOMMENDATIONS.general];
    for (const t of types) {
      if (GITIGNORE_RECOMMENDATIONS[t]) {
        recommended.push(...GITIGNORE_RECOMMENDATIONS[t]);
      }
    }

    for (const entry of recommended) {
      const pattern = entry.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*');
      if (!new RegExp(pattern, 'i').test(gitignoreContent) && !gitignoreContent.includes(entry.replace('/', ''))) {
        // Check if the file/dir actually exists
        const checkPath = path.join(projectDir, entry.replace(/\/$/, ''));
        if (fs.existsSync(checkPath)) {
          missing.push(entry);
        }
      }
    }

    if (missing.length > 0) {
      issues.push({
        type: 'incomplete_gitignore',
        severity: 'medium',
        missing,
        description: `Missing .gitignore entries for existing files/dirs: ${missing.join(', ')}`,
        fix: `Add these entries to .gitignore:\n${missing.join('\n')}`,
      });
    }
  }

  // Check if .env files are committed
  try {
    const tracked = execSync('git ls-files', { cwd: projectDir, encoding: 'utf-8', timeout: 10000 });
    const envFiles = tracked.trim().split('\n').filter(l => /\.env(?:\.\w+)?$/.test(l) && !l.includes('.example') && !l.includes('.sample'));
    if (envFiles.length > 0) {
      issues.push({
        type: 'env_committed',
        severity: 'critical',
        files: envFiles,
        description: `.env file(s) committed to git: ${envFiles.join(', ')} — may contain secrets`,
        fix: `Remove with "git rm --cached ${envFiles.join(' ')}" and add .env* to .gitignore`,
      });
    }
  } catch {}

  return { issues, stats };
}

// ─── 6. Security Headers (Express/Next.js) ──────────────

function checkSecurityHeaders(projectDir) {
  const issues = [];
  const files = walkDir(projectDir);
  const stats = { isWebApp: false, middlewareChecked: 0, middlewareMissing: 0 };

  // Detect if this is an Express or Next.js app
  const pkgPath = path.join(projectDir, 'package.json');
  let isExpress = false;
  let isNextJs = false;

  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSafe(pkgPath));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      isExpress = !!allDeps.express || !!allDeps.fastify || !!allDeps.koa;
      isNextJs = !!allDeps.next;
    } catch {}
  }

  if (!isExpress && !isNextJs) {
    return { issues, stats };
  }

  stats.isWebApp = true;

  // Scan all source files for security middleware usage
  let allSource = '';
  for (const filePath of files) {
    if (!isTextFile(filePath)) continue;
    const ext = path.extname(filePath);
    if (!['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext)) continue;
    const content = readFileSafe(filePath);
    if (content) allSource += content + '\n';
  }

  if (isExpress) {
    for (const middleware of SECURITY_MIDDLEWARE.express) {
      stats.middlewareChecked++;
      if (!middleware.pattern.test(allSource)) {
        stats.middlewareMissing++;
        issues.push({
          type: 'missing_security_middleware',
          severity: middleware.severity,
          name: middleware.name,
          description: middleware.description,
          fix: middleware.fix,
        });
      }
    }
  }

  // Check for common security anti-patterns
  if (/app\.use\(cors\(\)\)/.test(allSource) || /cors\(\{\s*origin:\s*['"]\*['"]\s*\}\)/.test(allSource)) {
    issues.push({
      type: 'permissive_cors',
      severity: 'medium',
      description: 'CORS is configured to allow all origins — this can be a security risk',
      fix: 'Restrict CORS to specific trusted domains: cors({ origin: "https://your-domain.com" })',
    });
  }

  if (/app\.disable\s*\(\s*['"]x-powered-by['"]\s*\)/.test(allSource) === false && !allSource.includes('helmet')) {
    issues.push({
      type: 'x_powered_by',
      severity: 'low',
      description: 'Express "X-Powered-By" header is not disabled — reveals server technology',
      fix: 'Use helmet() or app.disable("x-powered-by")',
    });
  }

  return { issues, stats };
}

// ─── 7. Health Score ─────────────────────────────────────

function calculateHealthScore(results) {
  let score = 100;
  const deductions = [];

  const severityWeights = {
    critical: 15,
    high: 8,
    medium: 4,
    low: 1,
  };

  // Aggregate all issues
  const allIssues = [
    ...(results.dependencies?.issues || []),
    ...(results.secrets?.issues || []),
    ...(results.licenses?.issues || []),
    ...(results.codeQuality?.issues || []),
    ...(results.gitHealth?.issues || []),
    ...(results.securityHeaders?.issues || []),
  ];

  // Calculate deductions by category
  const categories = {
    dependencies: results.dependencies?.issues || [],
    secrets: results.secrets?.issues || [],
    licenses: results.licenses?.issues || [],
    codeQuality: results.codeQuality?.issues || [],
    gitHealth: results.gitHealth?.issues || [],
    securityHeaders: results.securityHeaders?.issues || [],
  };

  for (const [category, issues] of Object.entries(categories)) {
    let categoryDeduction = 0;
    for (const issue of issues) {
      const weight = severityWeights[issue.severity] || 2;
      categoryDeduction += weight;
    }
    // Cap deduction per category
    categoryDeduction = Math.min(categoryDeduction, 30);
    if (categoryDeduction > 0) {
      deductions.push({ category, points: categoryDeduction, issueCount: issues.length });
    }
    score -= categoryDeduction;
  }

  score = Math.max(0, Math.min(100, score));

  let grade;
  if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 60) grade = 'D';
  else grade = 'F';

  // Issue summary
  const issueSummary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const issue of allIssues) {
    issueSummary[issue.severity] = (issueSummary[issue.severity] || 0) + 1;
  }

  return { score, grade, deductions, issueSummary, totalIssues: allIssues.length };
}

// ─── 8. Fix Suggestions ──────────────────────────────────

function generateFixSuggestions(results) {
  const suggestions = [];
  const allIssues = [
    ...(results.dependencies?.issues || []),
    ...(results.secrets?.issues || []),
    ...(results.licenses?.issues || []),
    ...(results.codeQuality?.issues || []),
    ...(results.gitHealth?.issues || []),
    ...(results.securityHeaders?.issues || []),
  ];

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allIssues.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

  // Group by type and deduplicate
  const seen = new Set();
  for (const issue of allIssues) {
    const key = `${issue.type}:${issue.severity}`;
    if (seen.has(key) && issue.type !== 'vulnerability' && issue.type !== 'secret') continue;
    seen.add(key);

    if (issue.fix) {
      suggestions.push({
        priority: issue.severity,
        category: issue.type,
        action: issue.fix,
        description: issue.description,
      });
    }
  }

  // Add positive suggestions
  if (results.healthScore?.score >= 80) {
    suggestions.push({
      priority: 'info',
      category: 'positive',
      action: 'Your project is in good shape! Consider setting up CI/CD to maintain this health score.',
      description: `Health score: ${results.healthScore.score}/100 (${results.healthScore.grade})`,
    });
  }

  return suggestions;
}

// ─── Public API ──────────────────────────────────────────

/**
 * Full project scan — runs all checks and returns comprehensive report.
 */
function scanProject(projectDir) {
  if (!fs.existsSync(projectDir)) {
    return { error: `Directory not found: ${projectDir}` };
  }

  const startTime = Date.now();
  const projectTypes = detectProjectType(projectDir);

  const results = {
    project: {
      path: projectDir,
      name: path.basename(projectDir),
      types: projectTypes,
      scannedAt: new Date().toISOString(),
    },
    dependencies: auditDependencies(projectDir),
    secrets: detectSecrets(projectDir),
    licenses: checkLicenses(projectDir),
    codeQuality: analyzeCodeQuality(projectDir),
    gitHealth: checkGitHealth(projectDir),
    securityHeaders: checkSecurityHeaders(projectDir),
  };

  results.healthScore = calculateHealthScore(results);
  results.suggestions = generateFixSuggestions(results);
  results.scanDuration = `${Date.now() - startTime}ms`;

  return results;
}

/**
 * Secret detection only.
 */
function checkSecretsOnly(projectDir) {
  if (!fs.existsSync(projectDir)) {
    return { error: `Directory not found: ${projectDir}` };
  }
  const startTime = Date.now();
  const result = detectSecrets(projectDir);
  result.scanDuration = `${Date.now() - startTime}ms`;
  return result;
}

/**
 * Dependency audit only.
 */
function checkDependenciesOnly(projectDir) {
  if (!fs.existsSync(projectDir)) {
    return { error: `Directory not found: ${projectDir}` };
  }
  const startTime = Date.now();
  const result = auditDependencies(projectDir);
  result.scanDuration = `${Date.now() - startTime}ms`;
  return result;
}

/**
 * License compliance only.
 */
function checkLicensesOnly(projectDir) {
  if (!fs.existsSync(projectDir)) {
    return { error: `Directory not found: ${projectDir}` };
  }
  const startTime = Date.now();
  const result = checkLicenses(projectDir);
  result.scanDuration = `${Date.now() - startTime}ms`;
  return result;
}

/**
 * Quick health score without full details.
 */
function quickHealthScore(projectDir) {
  if (!fs.existsSync(projectDir)) {
    return { error: `Directory not found: ${projectDir}` };
  }
  const startTime = Date.now();

  const results = {
    dependencies: auditDependencies(projectDir),
    secrets: detectSecrets(projectDir),
    licenses: checkLicenses(projectDir),
    codeQuality: analyzeCodeQuality(projectDir),
    gitHealth: checkGitHealth(projectDir),
    securityHeaders: checkSecurityHeaders(projectDir),
  };

  const healthScore = calculateHealthScore(results);
  return {
    project: path.basename(projectDir),
    ...healthScore,
    scanDuration: `${Date.now() - startTime}ms`,
  };
}

module.exports = {
  scanProject,
  checkSecretsOnly,
  checkDependenciesOnly,
  checkLicensesOnly,
  quickHealthScore,
};
