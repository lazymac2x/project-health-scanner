/**
 * Project Health Scanner — MCP Server
 * =====================================
 * Express server exposing project health scanning via MCP protocol.
 * POST /mcp — JSON-RPC 2.0 endpoint for MCP tool calls.
 * GET /health — Server health check.
 */

const express = require('express');
const cors = require('cors');
const {
  scanProject,
  checkSecretsOnly,
  checkDependenciesOnly,
  checkLicensesOnly,
  quickHealthScore,
} = require('./scanner');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ─── MCP Tool Definitions ────────────────────────────────

const MCP_TOOLS = [
  {
    name: 'scan_project',
    description: 'Full health scan of a project directory. Checks dependencies, secrets, licenses, code quality, git health, security headers. Returns a 0-100 health score with A-F grade and actionable fix suggestions.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the project directory to scan',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'check_secrets',
    description: 'Scan a project directory for hardcoded secrets: AWS keys, GitHub tokens, Slack tokens, database URLs, private keys, API keys, passwords, and more. Returns masked previews of found secrets with fix suggestions.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the project directory to scan',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'check_dependencies',
    description: 'Audit project dependencies for known CVEs, unpinned versions, and missing lockfiles. Supports package.json (Node.js), requirements.txt (Python), and go.mod (Go).',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the project directory to scan',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'check_licenses',
    description: 'Check license compliance across all dependencies. Detects copyleft (GPL/AGPL) conflicts, missing LICENSE files, and provides a license type breakdown.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the project directory to scan',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'health_score',
    description: 'Quick project health score (0-100) with A-F grade. Runs all checks but returns only the score, grade, issue counts, and deduction breakdown — no full details.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute path to the project directory to scan',
        },
      },
      required: ['path'],
    },
  },
];

// ─── MCP Handler ─────────────────────────────────────────

function handleToolCall(name, args) {
  const projectPath = args.path;

  switch (name) {
    case 'scan_project':
      return scanProject(projectPath);
    case 'check_secrets':
      return checkSecretsOnly(projectPath);
    case 'check_dependencies':
      return checkDependenciesOnly(projectPath);
    case 'check_licenses':
      return checkLicensesOnly(projectPath);
    case 'health_score':
      return quickHealthScore(projectPath);
    default:
      return { error: `Unknown tool: ${name}` };
  }
}

// ─── Routes ──────────────────────────────────────────────

app.post('/mcp', (req, res) => {
  const { jsonrpc, id, method, params } = req.body;

  // JSON-RPC 2.0 validation
  if (jsonrpc !== '2.0') {
    return res.json({ jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid JSON-RPC version' } });
  }

  try {
    switch (method) {
      case 'initialize': {
        return res.json({
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: '2024-11-05',
            capabilities: { tools: {} },
            serverInfo: {
              name: 'project-health-scanner',
              version: '1.0.0',
              description: 'Scans projects for dependency vulnerabilities, hardcoded secrets, license conflicts, code quality issues, and git health problems. Returns a 0-100 health score with actionable fix suggestions.',
            },
          },
        });
      }

      case 'tools/list': {
        return res.json({
          jsonrpc: '2.0',
          id,
          result: { tools: MCP_TOOLS },
        });
      }

      case 'tools/call': {
        const { name, arguments: args } = params || {};
        if (!name) {
          return res.json({ jsonrpc: '2.0', id, error: { code: -32602, message: 'Missing tool name' } });
        }

        const result = handleToolCall(name, args || {});

        return res.json({
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result, null, 2),
              },
            ],
          },
        });
      }

      default: {
        return res.json({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `Method not found: ${method}` },
        });
      }
    }
  } catch (err) {
    return res.json({
      jsonrpc: '2.0',
      id,
      error: { code: -32603, message: err.message },
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'project-health-scanner', version: '1.0.0' });
});

// Root info
app.get('/', (req, res) => {
  res.json({
    name: 'project-health-scanner',
    version: '1.0.0',
    description: 'MCP server for project health scanning',
    endpoints: {
      'POST /mcp': 'MCP JSON-RPC 2.0 endpoint',
      'GET /health': 'Server health check',
    },
    tools: MCP_TOOLS.map(t => ({ name: t.name, description: t.description })),
  });
});

// ─── Start ───────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`project-health-scanner MCP server running on port ${PORT}`);
  console.log(`MCP endpoint: http://localhost:${PORT}/mcp`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});

module.exports = { app, server };
