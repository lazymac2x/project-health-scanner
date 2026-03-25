/**
 * Secret Detection Patterns & Known CVE Patterns
 * ================================================
 * Curated regex patterns for detecting hardcoded secrets,
 * credentials, and known vulnerable dependency versions.
 */

const SECRET_PATTERNS = [
  // === AWS ===
  {
    name: 'AWS Access Key ID',
    pattern: /(?:^|[^A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)/,
    severity: 'critical',
    description: 'AWS Access Key ID found — can grant full AWS account access',
    fix: 'Remove the key, rotate it in AWS IAM, use environment variables or AWS Secrets Manager',
  },
  {
    name: 'AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i,
    severity: 'critical',
    description: 'AWS Secret Access Key found',
    fix: 'Rotate the key immediately in AWS IAM, use IAM roles or environment variables',
  },

  // === GitHub ===
  {
    name: 'GitHub Personal Access Token',
    pattern: /(?:^|[^A-Za-z0-9_])(ghp_[A-Za-z0-9]{36,})(?:[^A-Za-z0-9_]|$)/,
    severity: 'critical',
    description: 'GitHub PAT found — can access repos, gists, and user data',
    fix: 'Revoke the token at github.com/settings/tokens, use GITHUB_TOKEN env var',
  },
  {
    name: 'GitHub OAuth App Token',
    pattern: /(?:^|[^A-Za-z0-9_])(gho_[A-Za-z0-9]{36,})(?:[^A-Za-z0-9_]|$)/,
    severity: 'critical',
    description: 'GitHub OAuth token found',
    fix: 'Revoke the token, use OAuth flow with secure token storage',
  },
  {
    name: 'GitHub App Token',
    pattern: /(?:^|[^A-Za-z0-9_])(ghu_[A-Za-z0-9]{36,}|ghs_[A-Za-z0-9]{36,})(?:[^A-Za-z0-9_]|$)/,
    severity: 'critical',
    description: 'GitHub App installation/user token found',
    fix: 'Tokens should be generated at runtime, never committed',
  },
  {
    name: 'GitHub Fine-Grained PAT',
    pattern: /(?:^|[^A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{22,})(?:[^A-Za-z0-9_]|$)/,
    severity: 'critical',
    description: 'GitHub fine-grained personal access token found',
    fix: 'Revoke at github.com/settings/tokens, use environment variables',
  },

  // === Slack ===
  {
    name: 'Slack Bot Token',
    pattern: /(?:^|[^A-Za-z0-9-])(xoxb-[0-9]{10,}-[0-9A-Za-z]{20,})(?:[^A-Za-z0-9-]|$)/,
    severity: 'critical',
    description: 'Slack bot token found — can read/send messages as the bot',
    fix: 'Rotate the token in Slack App settings, use environment variables',
  },
  {
    name: 'Slack User Token',
    pattern: /(?:^|[^A-Za-z0-9-])(xoxp-[0-9]{10,}-[0-9A-Za-z]{20,})(?:[^A-Za-z0-9-]|$)/,
    severity: 'critical',
    description: 'Slack user token found — can act as the user in Slack',
    fix: 'Rotate the token, never commit user tokens',
  },
  {
    name: 'Slack Webhook URL',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/,
    severity: 'high',
    description: 'Slack webhook URL found — can post messages to a channel',
    fix: 'Regenerate the webhook URL, store in environment variables',
  },

  // === Google / GCP ===
  {
    name: 'Google API Key',
    pattern: /(?:^|[^A-Za-z0-9_])(AIza[0-9A-Za-z_-]{35})(?:[^A-Za-z0-9_-]|$)/,
    severity: 'high',
    description: 'Google API key found',
    fix: 'Restrict the key in Google Cloud Console, use environment variables',
  },
  {
    name: 'Google OAuth Client Secret',
    pattern: /(?:client_secret)\s*[=:]\s*['"]?([A-Za-z0-9_-]{24,})['"]?/i,
    severity: 'high',
    description: 'Google OAuth client secret found',
    fix: 'Rotate in Google Cloud Console, store securely',
  },

  // === Stripe ===
  {
    name: 'Stripe Secret Key',
    pattern: /(?:^|[^A-Za-z0-9_])(sk_live_[0-9a-zA-Z]{24,})(?:[^A-Za-z0-9_]|$)/,
    severity: 'critical',
    description: 'Stripe live secret key — can charge real credit cards',
    fix: 'Roll the key in Stripe Dashboard immediately, use environment variables',
  },
  {
    name: 'Stripe Restricted Key',
    pattern: /(?:^|[^A-Za-z0-9_])(rk_live_[0-9a-zA-Z]{24,})(?:[^A-Za-z0-9_]|$)/,
    severity: 'critical',
    description: 'Stripe live restricted key found',
    fix: 'Delete and recreate in Stripe Dashboard',
  },

  // === Database ===
  {
    name: 'Database Connection String',
    pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s'"<>{}|\\^`\[\]]{10,}/i,
    severity: 'high',
    description: 'Database connection string with potential credentials',
    fix: 'Use environment variables for connection strings, never hardcode credentials',
  },

  // === Private Keys ===
  {
    name: 'RSA Private Key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: 'critical',
    description: 'Private key file content found in source',
    fix: 'Remove immediately, regenerate the key pair, use a secrets manager',
  },

  // === JWT ===
  {
    name: 'JWT Secret',
    pattern: /(?:jwt_secret|jwt_key|jwt_token|jsonwebtoken)\s*[=:]\s*['"]([^'"]{8,})['"]?/i,
    severity: 'high',
    description: 'JWT secret/signing key found hardcoded',
    fix: 'Move to environment variable, use a strong random secret (256+ bits)',
  },

  // === Generic Patterns ===
  {
    name: 'Hardcoded Password',
    pattern: /(?:password|passwd|pwd|pass)\s*[=:]\s*['"]([^'"]{4,})['"](?!\s*[=])/i,
    severity: 'high',
    description: 'Hardcoded password found',
    fix: 'Use environment variables or a secrets manager for passwords',
  },
  {
    name: 'API Key Assignment',
    pattern: /(?:api_key|apikey|api_token|access_token|auth_token|secret_key|secret_token)\s*[=:]\s*['"]([A-Za-z0-9_\-./+=]{16,})['"]?/i,
    severity: 'high',
    description: 'API key or token found hardcoded in source',
    fix: 'Move to environment variables, add the file to .gitignore if it is a config file',
  },
  {
    name: 'Bearer Token',
    pattern: /(?:Authorization|Bearer)\s*[=:]\s*['"]Bearer\s+([A-Za-z0-9_\-.]+)['"]?/i,
    severity: 'high',
    description: 'Hardcoded Bearer token in source',
    fix: 'Use environment variables, inject tokens at runtime',
  },

  // === SendGrid / Mailgun / Twilio ===
  {
    name: 'SendGrid API Key',
    pattern: /(?:^|[^A-Za-z0-9_.])(SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,})(?:[^A-Za-z0-9_-]|$)/,
    severity: 'critical',
    description: 'SendGrid API key found — can send emails on your behalf',
    fix: 'Revoke in SendGrid dashboard, create a new key stored in env vars',
  },
  {
    name: 'Twilio Auth Token',
    pattern: /(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/i,
    severity: 'critical',
    description: 'Twilio auth token found — can send SMS/calls on your account',
    fix: 'Rotate in Twilio Console, use environment variables',
  },

  // === Heroku / Vercel / Netlify ===
  {
    name: 'Heroku API Key',
    pattern: /(?:HEROKU_API_KEY|heroku_api_key)\s*[=:]\s*['"]?([a-f0-9-]{36,})['"]?/i,
    severity: 'high',
    description: 'Heroku API key found',
    fix: 'Regenerate at Heroku dashboard, store in environment variables',
  },

  // === NPM Token ===
  {
    name: 'NPM Token',
    pattern: /(?:^|[^A-Za-z0-9_])(npm_[A-Za-z0-9]{36,})(?:[^A-Za-z0-9_]|$)/,
    severity: 'critical',
    description: 'NPM access token found — can publish packages under your account',
    fix: 'Revoke at npmjs.com/settings/tokens, create a new token',
  },

  // === .env file committed ===
  {
    name: '.env File Content',
    pattern: /^[A-Z_]{2,}=\S{8,}$/m,
    severity: 'medium',
    filePattern: /\.env(?:\.\w+)?$/,
    description: 'Environment variable file may contain secrets',
    fix: 'Add .env* to .gitignore, use .env.example with placeholder values',
  },
];

/**
 * Known CVE patterns for popular packages.
 * Maps package name to array of { range, cve, severity, description, fix }.
 * `range` is checked as: version < fix_version.
 */
const KNOWN_CVES = {
  // === Node.js / npm ===
  'lodash': [
    { below: '4.17.21', cve: 'CVE-2021-23337', severity: 'critical', description: 'Command injection via template', fix: 'Upgrade to 4.17.21+' },
    { below: '4.17.20', cve: 'CVE-2020-28500', severity: 'high', description: 'ReDoS in trim functions', fix: 'Upgrade to 4.17.21+' },
  ],
  'minimist': [
    { below: '1.2.6', cve: 'CVE-2021-44906', severity: 'critical', description: 'Prototype pollution', fix: 'Upgrade to 1.2.6+' },
  ],
  'node-fetch': [
    { below: '2.6.7', cve: 'CVE-2022-0235', severity: 'high', description: 'Exposure of sensitive info to unauthorized actor', fix: 'Upgrade to 2.6.7+ or 3.1.1+' },
  ],
  'express': [
    { below: '4.19.2', cve: 'CVE-2024-29041', severity: 'medium', description: 'Open redirect vulnerability', fix: 'Upgrade to 4.19.2+' },
  ],
  'axios': [
    { below: '1.6.0', cve: 'CVE-2023-45857', severity: 'high', description: 'CSRF token exposure via XSRF-TOKEN cookie', fix: 'Upgrade to 1.6.0+' },
  ],
  'jsonwebtoken': [
    { below: '9.0.0', cve: 'CVE-2022-23529', severity: 'critical', description: 'Insecure key retrieval allows JWT forgery', fix: 'Upgrade to 9.0.0+' },
  ],
  'tar': [
    { below: '6.1.9', cve: 'CVE-2021-37713', severity: 'high', description: 'Arbitrary file creation/overwrite on Windows', fix: 'Upgrade to 6.1.9+' },
  ],
  'semver': [
    { below: '7.5.2', cve: 'CVE-2022-25883', severity: 'medium', description: 'ReDoS in semver parsing', fix: 'Upgrade to 7.5.2+' },
  ],
  'got': [
    { below: '11.8.5', cve: 'CVE-2022-33987', severity: 'medium', description: 'SSRF via redirect to Unix socket', fix: 'Upgrade to 11.8.5+ or 12.1+' },
  ],
  'glob-parent': [
    { below: '5.1.2', cve: 'CVE-2020-28469', severity: 'high', description: 'Regular expression DoS', fix: 'Upgrade to 5.1.2+' },
  ],
  'path-parse': [
    { below: '1.0.7', cve: 'CVE-2021-23343', severity: 'medium', description: 'ReDoS via splitDeviceRe', fix: 'Upgrade to 1.0.7+' },
  ],
  'nanoid': [
    { below: '3.1.31', cve: 'CVE-2021-23566', severity: 'medium', description: 'Predictable ID generation', fix: 'Upgrade to 3.1.31+' },
  ],
  'follow-redirects': [
    { below: '1.15.4', cve: 'CVE-2023-26159', severity: 'high', description: 'SSRF via URL parsing bypass', fix: 'Upgrade to 1.15.4+' },
  ],
  'xml2js': [
    { below: '0.5.0', cve: 'CVE-2023-0842', severity: 'medium', description: 'Prototype pollution in parser', fix: 'Upgrade to 0.5.0+' },
  ],
  'qs': [
    { below: '6.10.3', cve: 'CVE-2022-24999', severity: 'high', description: 'Prototype pollution', fix: 'Upgrade to 6.10.3+' },
  ],

  // === Python ===
  'django': [
    { below: '4.2.8', cve: 'CVE-2023-46695', severity: 'high', description: 'DoS via file upload handler', fix: 'Upgrade to 4.2.8+' },
  ],
  'flask': [
    { below: '2.3.2', cve: 'CVE-2023-30861', severity: 'high', description: 'Cookie stealing via missing Vary header', fix: 'Upgrade to 2.3.2+' },
  ],
  'requests': [
    { below: '2.31.0', cve: 'CVE-2023-32681', severity: 'medium', description: 'Proxy-Authorization header leak on redirect', fix: 'Upgrade to 2.31.0+' },
  ],
  'urllib3': [
    { below: '2.0.7', cve: 'CVE-2023-45803', severity: 'medium', description: 'Request body not stripped on redirect', fix: 'Upgrade to 2.0.7+' },
  ],
  'pillow': [
    { below: '10.0.1', cve: 'CVE-2023-44271', severity: 'high', description: 'DoS via large text chunks in images', fix: 'Upgrade to 10.0.1+' },
  ],
  'cryptography': [
    { below: '41.0.6', cve: 'CVE-2023-49083', severity: 'high', description: 'NULL pointer dereference parsing PKCS7', fix: 'Upgrade to 41.0.6+' },
  ],
  'jinja2': [
    { below: '3.1.3', cve: 'CVE-2024-22195', severity: 'medium', description: 'XSS via xmlattr filter', fix: 'Upgrade to 3.1.3+' },
  ],
  'pyyaml': [
    { below: '6.0.1', cve: 'CVE-2020-14343', severity: 'critical', description: 'Arbitrary code execution via yaml.load()', fix: 'Upgrade to 6.0.1+ and use yaml.safe_load()' },
  ],
};

/**
 * License compatibility matrix.
 * 'permissive' licenses are compatible with everything.
 * 'copyleft' licenses require derivative work to use the same license.
 * 'weak-copyleft' is somewhere in between.
 */
const LICENSE_INFO = {
  'MIT':            { type: 'permissive', risk: 'low' },
  'ISC':            { type: 'permissive', risk: 'low' },
  'BSD-2-Clause':   { type: 'permissive', risk: 'low' },
  'BSD-3-Clause':   { type: 'permissive', risk: 'low' },
  'Apache-2.0':     { type: 'permissive', risk: 'low' },
  'Unlicense':      { type: 'permissive', risk: 'low' },
  'CC0-1.0':        { type: 'permissive', risk: 'low' },
  '0BSD':           { type: 'permissive', risk: 'low' },
  'WTFPL':          { type: 'permissive', risk: 'low' },
  'LGPL-2.1':       { type: 'weak-copyleft', risk: 'medium' },
  'LGPL-3.0':       { type: 'weak-copyleft', risk: 'medium' },
  'MPL-2.0':        { type: 'weak-copyleft', risk: 'medium' },
  'EPL-2.0':        { type: 'weak-copyleft', risk: 'medium' },
  'GPL-2.0':        { type: 'copyleft', risk: 'high' },
  'GPL-3.0':        { type: 'copyleft', risk: 'high' },
  'AGPL-3.0':       { type: 'copyleft', risk: 'critical' },
  'SSPL-1.0':       { type: 'copyleft', risk: 'critical' },
  'BSL-1.1':        { type: 'restrictive', risk: 'high' },
  'BUSL-1.1':       { type: 'restrictive', risk: 'high' },
};

/**
 * Files that SHOULD be in .gitignore for common project types.
 */
const GITIGNORE_RECOMMENDATIONS = {
  node: [
    'node_modules/',
    '.env',
    '.env.local',
    '.env.*.local',
    'dist/',
    'build/',
    '.DS_Store',
    'coverage/',
    '*.log',
    '.npm',
    '.yarn/cache',
  ],
  python: [
    '__pycache__/',
    '*.pyc',
    '.env',
    'venv/',
    '.venv/',
    'dist/',
    '*.egg-info/',
    '.pytest_cache/',
    '.mypy_cache/',
  ],
  go: [
    '.env',
    'vendor/',
    '*.exe',
    '*.test',
    '*.out',
  ],
  general: [
    '.env',
    '.DS_Store',
    'Thumbs.db',
    '*.log',
    '.idea/',
    '.vscode/',
    '*.swp',
    '*.swo',
  ],
};

/**
 * Security middleware that should be present in Express/Next.js apps.
 */
const SECURITY_MIDDLEWARE = {
  express: [
    { name: 'helmet', pattern: /require\(['"]helmet['"]\)|from\s+['"]helmet['"]/, severity: 'high', description: 'helmet sets security HTTP headers (X-Frame-Options, CSP, etc.)', fix: 'npm install helmet && app.use(helmet())' },
    { name: 'rate-limiter', pattern: /rate[-_]?limit|express-rate-limit|RateLimit/i, severity: 'high', description: 'Rate limiting prevents brute-force and DoS attacks', fix: 'npm install express-rate-limit && app.use(rateLimit({ windowMs: 15*60*1000, max: 100 }))' },
    { name: 'cors', pattern: /require\(['"]cors['"]\)|from\s+['"]cors['"]/, severity: 'medium', description: 'CORS middleware controls cross-origin access', fix: 'npm install cors && app.use(cors({ origin: "your-domain.com" }))' },
    { name: 'hpp', pattern: /require\(['"]hpp['"]\)|from\s+['"]hpp['"]/, severity: 'low', description: 'HPP protects against HTTP Parameter Pollution', fix: 'npm install hpp && app.use(hpp())' },
  ],
};

/**
 * Binary file extensions that should not be in git.
 */
const BINARY_EXTENSIONS = new Set([
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wav', '.flac',
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.ico', '.svg',
  '.psd', '.ai',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.sqlite', '.db',
  '.jar', '.war', '.class',
  '.pyc', '.pyo',
  '.o', '.a', '.lib',
]);

module.exports = {
  SECRET_PATTERNS,
  KNOWN_CVES,
  LICENSE_INFO,
  GITIGNORE_RECOMMENDATIONS,
  SECURITY_MIDDLEWARE,
  BINARY_EXTENSIONS,
};
