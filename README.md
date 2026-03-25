# Project Health Scanner

[![npm](https://img.shields.io/npm/v/@lazymac/project-health-scanner)](https://www.npmjs.com/package/@lazymac/project-health-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Get a 0-100 health score for any project in seconds.** Scans for dependency vulnerabilities, hardcoded secrets, license conflicts, code quality issues, and git health problems. Returns actionable fix suggestions.

## Why

You push code every day but never check if your dependencies have known CVEs, if someone committed an API key, or if your licenses conflict. This tool runs one scan and tells you everything.

## Install

```bash
npm i @lazymac/project-health-scanner
```

## Quick Start

### As REST API
```bash
npm start
# Server runs on http://localhost:3000
```

### As MCP Server
Add to your Cursor/Claude Code MCP config:
```json
{
  "mcpServers": {
    "project-health-scanner": {
      "command": "node",
      "args": ["node_modules/@lazymac/project-health-scanner/src/main.js"]
    }
  }
}
```

## API Endpoints

### `POST /scan`
Scan a project directory and get a full health report.

```bash
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/your/project"}'
```

**Response:**
```json
{
  "score": 72,
  "grade": "B",
  "checks": {
    "dependencies": { "score": 60, "issues": ["3 outdated packages", "1 known vulnerability"] },
    "secrets": { "score": 90, "issues": ["Possible API key in config.js:14"] },
    "licenses": { "score": 100, "issues": [] },
    "codeQuality": { "score": 65, "issues": ["12 files over 300 lines"] },
    "gitHealth": { "score": 85, "issues": ["No .gitignore found"] }
  },
  "suggestions": [
    "Run npm audit fix to resolve 1 vulnerability",
    "Rotate API key found in config.js and move to environment variable",
    "Add .gitignore from github/gitignore template"
  ]
}
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `scan_project` | Full health scan with 0-100 score |
| `check_dependencies` | Dependency audit only |
| `detect_secrets` | Secret/API key detection only |
| `check_licenses` | License compatibility check |
| `check_code_quality` | Code quality metrics |
| `check_git_health` | Git repository health |

## What It Checks

- **Dependencies** -- outdated packages, known vulnerabilities, unused dependencies
- **Secrets** -- API keys, passwords, tokens, private keys in source code
- **Licenses** -- MIT/Apache/GPL compatibility, missing license files
- **Code Quality** -- file sizes, complexity indicators, TODO/FIXME counts
- **Git Health** -- .gitignore presence, large files tracked, commit patterns

## Links

- [GitHub](https://github.com/lazymac2x/project-health-scanner)
- [All 29 Tools](https://lazymac2x.github.io/lazymac-api-store/)

## License

MIT
