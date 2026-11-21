// Records password-authorisation vectors from the REAL hem-sdk-js, so the Rust
// SDK is checked against the reference implementation, not against a copy of
// the algorithm written by the same hand.
//
//   node tests/vectors/gen.mjs [path/to/hem-sdk.js] > tests/vectors/password_v1.json
//
// Default SDK path: ../encedo-manager/sdk/hem-sdk.js (sibling checkout), or $HEM_SDK_JS.
// A fake device on 127.0.0.1 hands out a fixed challenge and captures the eJWT
// the SDK sends; Date.now is frozen so `iat` / `exp` are reproducible.

import http from 'node:http';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const sdkPath = resolve(process.argv[2] ?? process.env.HEM_SDK_JS ?? resolve(here, '../../../encedo-manager/sdk/hem-sdk.js'));
const { HEM } = await import(pathToFileURL(sdkPath).href);

let sdkCommit = 'unknown';
try { sdkCommit = execFileSync('git', ['-C', dirname(sdkPath), 'rev-parse', 'HEAD']).toString().trim(); } catch {}

const b64 = (buf) => Buffer.from(buf).toString('base64');
const sha = (s) => createHash('sha256').update(s).digest();

const CASES = [
  { name: 'ascii, one scope, defaults', password: 'password', scope: 'keymgmt:list', opts: {} },
  { name: 'utf-8 password, scope list, ctx, exp 60', password: 'zażółć gęślą jaźń 🔑',
    scope: ['keymgmt:list', 'keymgmt:use:00112233445566778899aabbccddeeff'], opts: { expSeconds: 60, ctx: 'ssh-agent' } },
  { name: 'one-element list stays a list', password: 'p', scope: ['keymgmt:get'], opts: {} },
  { name: 'ctx needing JSON escapes', password: 'Correct Horse Battery Staple', scope: 'storage:disk0:rw',
    opts: { ctx: 'host "a\\b"\tł/€' } },
  { name: 'long exp', password: '1234567890'.repeat(8), scope: 'system:config', opts: { expSeconds: 86400 } },
];

const NOW_MS = 1795260653987; // fractional second: the SDK floors it
let challenge = null;
let captured = null;

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    res.setHeader('Content-Type', 'application/json');
    if (req.method === 'GET' && req.url === '/api/auth/token') {
      res.end(JSON.stringify(challenge));
    } else if (req.method === 'POST' && req.url === '/api/auth/token') {
      captured = JSON.parse(body).auth;
      // A token the SDK can cache; its content does not matter here.
      const p = Buffer.from(JSON.stringify({ exp: Math.floor(NOW_MS / 1000) + 600, scope: 'x' })).toString('base64url');
      res.end(JSON.stringify({ token: `e30.${p}.sig` }));
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const url = `http://127.0.0.1:${server.address().port}`;

const realNow = Date.now;
Date.now = () => NOW_MS;

const out = [];
try {
  for (const [i, c] of CASES.entries()) {
    challenge = { eid: b64(sha(`eid-${i}`)), spk: b64(sha(`spk-${i}`)), jti: b64(sha(`jti-${i}`)) };
    captured = null;
    const hem = new HEM(url, { broker: url });
    await hem.authorizePassword(c.password, c.scope, { remember: false, ...c.opts });
    const payload = JSON.parse(Buffer.from(captured.split('.')[1], 'base64url').toString('utf8'));
    out.push({
      name: c.name,
      password: c.password,
      ...challenge,
      now: Math.floor(NOW_MS / 1000),
      scope: c.scope,
      exp_seconds: c.opts.expSeconds ?? 300,
      ctx: c.opts.ctx ?? null,
      iss: payload.iss,
      ejwt: captured,
    });
  }
} finally {
  Date.now = realNow;
  server.close();
}

process.stdout.write(JSON.stringify({ source: 'hem-sdk-js', sdk_commit: sdkCommit, cases: out }, null, 2) + '\n');
