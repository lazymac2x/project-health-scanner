/**
 * Integration test — starts the server, tests all MCP tools, then exits.
 */

const http = require('http');

const PORT = 3099;
process.env.PORT = PORT;

const BASE_URL = `http://localhost:${PORT}`;

// Use this project itself as the scan target
const TEST_PROJECT = '/Users/lazymac_2x/Projects/active/project-health-scanner';

let requestId = 0;

function mcpRequest(method, params = {}) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: ++requestId,
      method,
      params,
    });

    const req = http.request(`${BASE_URL}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`Parse error: ${data}`)); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function httpGet(path) {
  return new Promise((resolve, reject) => {
    http.get(`${BASE_URL}${path}`, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`Parse error: ${data}`)); }
      });
    }).on('error', reject);
  });
}

async function runTests() {
  let passed = 0;
  let failed = 0;

  function assert(name, condition, detail) {
    if (condition) {
      console.log(`  PASS  ${name}`);
      passed++;
    } else {
      console.log(`  FAIL  ${name}${detail ? ' — ' + detail : ''}`);
      failed++;
    }
  }

  console.log('\n=== Project Health Scanner — Integration Tests ===\n');

  // 1. Health check
  console.log('[GET /health]');
  const health = await httpGet('/health');
  assert('Returns status ok', health.status === 'ok');
  assert('Returns version', !!health.version);

  // 2. Root info
  console.log('\n[GET /]');
  const info = await httpGet('/');
  assert('Returns server name', info.name === 'project-health-scanner');
  assert('Lists tools', Array.isArray(info.tools) && info.tools.length === 5);

  // 3. MCP initialize
  console.log('\n[MCP initialize]');
  const init = await mcpRequest('initialize');
  assert('Returns protocol version', !!init.result?.protocolVersion);
  assert('Returns server info', init.result?.serverInfo?.name === 'project-health-scanner');

  // 4. MCP tools/list
  console.log('\n[MCP tools/list]');
  const toolsList = await mcpRequest('tools/list');
  const tools = toolsList.result?.tools || [];
  assert('Returns 5 tools', tools.length === 5);
  const toolNames = tools.map(t => t.name);
  assert('Has scan_project', toolNames.includes('scan_project'));
  assert('Has check_secrets', toolNames.includes('check_secrets'));
  assert('Has check_dependencies', toolNames.includes('check_dependencies'));
  assert('Has check_licenses', toolNames.includes('check_licenses'));
  assert('Has health_score', toolNames.includes('health_score'));

  // 5. scan_project
  console.log('\n[MCP tools/call — scan_project]');
  const scanRes = await mcpRequest('tools/call', { name: 'scan_project', arguments: { path: TEST_PROJECT } });
  const scanData = JSON.parse(scanRes.result?.content?.[0]?.text || '{}');
  assert('Returns project info', !!scanData.project);
  assert('Returns health score', typeof scanData.healthScore?.score === 'number');
  assert('Returns grade', /^[A-F]$/.test(scanData.healthScore?.grade));
  assert('Returns dependencies', !!scanData.dependencies);
  assert('Returns secrets check', !!scanData.secrets);
  assert('Returns licenses check', !!scanData.licenses);
  assert('Returns code quality', !!scanData.codeQuality);
  assert('Returns git health', !!scanData.gitHealth);
  assert('Returns suggestions', Array.isArray(scanData.suggestions));
  assert('Returns scan duration', !!scanData.scanDuration);
  console.log(`    Score: ${scanData.healthScore?.score}/100 (${scanData.healthScore?.grade})`);
  console.log(`    Issues: ${scanData.healthScore?.totalIssues} total`);

  // 6. check_secrets
  console.log('\n[MCP tools/call — check_secrets]');
  const secretsRes = await mcpRequest('tools/call', { name: 'check_secrets', arguments: { path: TEST_PROJECT } });
  const secretsData = JSON.parse(secretsRes.result?.content?.[0]?.text || '{}');
  assert('Returns scanned files count', typeof secretsData.stats?.scannedFiles === 'number');
  assert('Returns issues array', Array.isArray(secretsData.issues));
  console.log(`    Scanned ${secretsData.stats?.scannedFiles} files, found ${secretsData.stats?.secretsFound} secrets`);

  // 7. check_dependencies
  console.log('\n[MCP tools/call — check_dependencies]');
  const depsRes = await mcpRequest('tools/call', { name: 'check_dependencies', arguments: { path: TEST_PROJECT } });
  const depsData = JSON.parse(depsRes.result?.content?.[0]?.text || '{}');
  assert('Returns stats', !!depsData.stats);
  assert('Returns issues array', Array.isArray(depsData.issues));
  console.log(`    ${depsData.stats?.total} deps, ${depsData.stats?.vulnerable} vulnerable`);

  // 8. check_licenses
  console.log('\n[MCP tools/call — check_licenses]');
  const licRes = await mcpRequest('tools/call', { name: 'check_licenses', arguments: { path: TEST_PROJECT } });
  const licData = JSON.parse(licRes.result?.content?.[0]?.text || '{}');
  assert('Returns issues array', Array.isArray(licData.issues));
  assert('Returns scan duration', !!licData.scanDuration);

  // 9. health_score
  console.log('\n[MCP tools/call — health_score]');
  const scoreRes = await mcpRequest('tools/call', { name: 'health_score', arguments: { path: TEST_PROJECT } });
  const scoreData = JSON.parse(scoreRes.result?.content?.[0]?.text || '{}');
  assert('Returns numeric score', typeof scoreData.score === 'number');
  assert('Returns grade', /^[A-F]$/.test(scoreData.grade));
  assert('Returns issue summary', !!scoreData.issueSummary);
  console.log(`    Quick score: ${scoreData.score}/100 (${scoreData.grade})`);

  // 10. Error handling — invalid path
  console.log('\n[MCP tools/call — error handling]');
  const errRes = await mcpRequest('tools/call', { name: 'scan_project', arguments: { path: '/nonexistent/path' } });
  const errData = JSON.parse(errRes.result?.content?.[0]?.text || '{}');
  assert('Returns error for invalid path', !!errData.error);

  // 11. Unknown method
  const unkRes = await mcpRequest('unknown_method');
  assert('Returns error for unknown method', !!unkRes.error);

  // Summary
  console.log(`\n${'='.repeat(50)}`);
  console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  console.log(`${'='.repeat(50)}\n`);

  return failed === 0;
}

// Start server, run tests, exit
const { server } = require('./src/server');

// Wait for server to be ready
setTimeout(async () => {
  try {
    const success = await runTests();
    server.close();
    process.exit(success ? 0 : 1);
  } catch (err) {
    console.error('Test error:', err);
    server.close();
    process.exit(1);
  }
}, 500);
