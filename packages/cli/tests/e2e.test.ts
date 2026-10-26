import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Keypair } from '@stellar/stellar-sdk';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CLI_ROOT = path.resolve(__dirname, '..');
const CLI_ENTRY = path.join(CLI_ROOT, 'dist', 'index.js');

interface SandboxCommitment {
  id: number;
  issuer: string;
  counterparty: string;
  terms_hash: string;
  due_at: number;
  status: 'Pending' | 'Fulfilled' | 'Late' | 'Breached' | 'Disputed';
  encrypted: boolean;
  txHash: string;
}

interface SandboxReputation {
  fulfilled: number;
  late: number;
  breached: number;
}

interface SandboxHarness {
  rpcUrl: string;
  apiUrl: string;
  commitments: Map<number, SandboxCommitment>;
  reputations: Map<string, SandboxReputation>;
  rpcCalls: Array<{ method: string; params: any }>;
  injectContractError: string | null;
  injectDisconnect: boolean;
  close: () => Promise<void>;
}

async function startSorobanSandbox(): Promise<SandboxHarness> {
  const commitments = new Map<number, SandboxCommitment>();
  const reputations = new Map<string, SandboxReputation>();
  const rpcCalls: Array<{ method: string; params: any }> = [];
  let nextCommitmentId = 1;
  let txCounter = 1;

  const state: {
    injectContractError: string | null;
    injectDisconnect: boolean;
  } = {
    injectContractError: null,
    injectDisconnect: false,
  };

  const getRep = (address: string): SandboxReputation => {
    const existing = reputations.get(address);
    if (existing) return existing;
    const init = { fulfilled: 0, late: 0, breached: 0 };
    reputations.set(address, init);
    return init;
  };

  const server = http.createServer((req, res) => {
    if (state.injectDisconnect) {
      req.socket.destroy();
      return;
    }

    const url = new URL(req.url || '/', 'http://127.0.0.1');

    // Soroban JSON-RPC endpoint
    if (req.method === 'POST' && url.pathname === '/soroban/rpc') {
      let body = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => {
        body += chunk;
      });
      req.on('end', () => {
        let payload: any;
        try {
          payload = JSON.parse(body);
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { code: -32700, message: 'Parse error' } }));
          return;
        }

        const { id = 1, method, params = {} } = payload;
        rpcCalls.push({ method, params });

        if (state.injectContractError && method === 'simulateTransaction') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: {
                error: state.injectContractError,
              },
            }),
          );
          return;
        }

        if (method === 'simulateTransaction') {
          const contractMethod = params.contractMethod;
          if (contractMethod === 'get_reputation') {
            const rep = getRep(params.address);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                jsonrpc: '2.0',
                id,
                result: {
                  reputation: {
                    fulfilledCount: rep.fulfilled,
                    lateCount: rep.late,
                    breachedCount: rep.breached,
                  },
                },
              }),
            );
            return;
          }

          if (contractMethod === 'attest') {
            const existing = commitments.get(Number(params.commitmentId));
            if (!existing) {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(
                JSON.stringify({
                  jsonrpc: '2.0',
                  id,
                  result: {
                    error: 'HostError: Error(Contract, #404): CommitmentNotFound',
                  },
                }),
              );
              return;
            }
          }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: {
                commitmentId: nextCommitmentId,
                cost: { cpuInsns: '42100', memBytes: '16384' },
              },
            }),
          );
          return;
        }

        if (method === 'sendTransaction') {
          const contractMethod = params.contractMethod;
          const txHash = (txCounter++).toString(16).padStart(64, '0');

          if (contractMethod === 'create_commitment') {
            const assignedId = nextCommitmentId++;
            commitments.set(assignedId, {
              id: assignedId,
              issuer: params.issuer,
              counterparty: params.counterparty,
              terms_hash: params.termsHash,
              due_at: Number(params.dueAt),
              status: 'Pending',
              encrypted: false,
              txHash,
            });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                jsonrpc: '2.0',
                id,
                result: {
                  status: 'PENDING',
                  hash: txHash,
                  commitmentId: assignedId,
                },
              }),
            );
            return;
          }

          if (contractMethod === 'attest') {
            const cmmt = commitments.get(Number(params.commitmentId));
            if (cmmt) {
              cmmt.status = params.outcome;
              const rep = getRep(cmmt.counterparty);
              if (params.outcome === 'Fulfilled') rep.fulfilled += 1;
              else if (params.outcome === 'Late') rep.late += 1;
              else if (params.outcome === 'Breached') rep.breached += 1;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                jsonrpc: '2.0',
                id,
                result: {
                  status: 'PENDING',
                  hash: txHash,
                },
              }),
            );
            return;
          }
        }

        if (method === 'getTransaction') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: {
                status: 'SUCCESS',
                commitmentId: nextCommitmentId - 1,
              },
            }),
          );
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            error: { code: -32601, message: `Method not found: ${method}` },
          }),
        );
      });
      return;
    }

    // Backend REST API: GET /commitments
    if (req.method === 'GET' && url.pathname === '/commitments') {
      const statusFilter = url.searchParams.get('status');
      let list = Array.from(commitments.values());
      if (statusFilter) {
        list = list.filter((c) => c.status.toLowerCase() === statusFilter.toLowerCase());
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(list));
      return;
    }

    // Backend REST API: GET /reputation/:address
    if (req.method === 'GET' && url.pathname.startsWith('/reputation/')) {
      const address = decodeURIComponent(url.pathname.slice('/reputation/'.length));
      const rep = getRep(address);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(rep));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const addr = server.address() as { port: number };
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  return {
    rpcUrl: `${baseUrl}/soroban/rpc`,
    apiUrl: baseUrl,
    commitments,
    reputations,
    rpcCalls,
    get injectContractError() {
      return state.injectContractError;
    },
    set injectContractError(val: string | null) {
      state.injectContractError = val;
    },
    get injectDisconnect() {
      return state.injectDisconnect;
    },
    set injectDisconnect(val: boolean) {
      state.injectDisconnect = val;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

interface CliRunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

function runCli(
  args: string[],
  options: {
    configDir: string;
    stdin?: string;
    env?: Record<string, string>;
  },
): Promise<CliRunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_ENTRY, ...args], {
      cwd: CLI_ROOT,
      env: {
        ...process.env,
        PACTUM_CONFIG_DIR: options.configDir,
        FORCE_COLOR: '0',
        ...options.env,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });

    child.on('error', reject);
    child.on('close', (code) => {
      resolve({
        exitCode: code ?? 1,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
      });
    });

    if (options.stdin !== undefined) {
      child.stdin.write(options.stdin);
    }
    child.stdin.end();
  });
}

describe('Pactum CLI End-to-End Sandbox Integration Harness', () => {
  let sandbox: SandboxHarness;
  let tempConfigDir: string;

  beforeAll(() => {
    if (!fs.existsSync(CLI_ENTRY)) {
      execFileSync('npm', ['run', 'build'], {
        cwd: CLI_ROOT,
        stdio: 'pipe',
      });
    }
  });

  beforeEach(async () => {
    tempConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pactum-cli-e2e-'));
    sandbox = await startSorobanSandbox();
  });

  afterEach(async () => {
    await sandbox.close();
    if (fs.existsSync(tempConfigDir)) {
      fs.rmSync(tempConfigDir, { recursive: true, force: true });
    }
  });

  it('executes full commitment lifecycle (auth init -> commitments create -> commitments attest -> reputation get)', async () => {
    const issuerKeypair = Keypair.random();
    const counterpartyKeypair = Keypair.random();
    const issuerSecret = issuerKeypair.secret();
    const issuerAddress = issuerKeypair.publicKey();
    const counterpartyAddress = counterpartyKeypair.publicKey();
    const termsHash = 'a'.repeat(64);
    const dueAt = Math.floor(Date.now() / 1000) + 3600;

    // 1. Authenticate via `pactum auth init <secret>`
    const authRes = await runCli(['auth', 'init', issuerSecret, '--network', 'testnet', '--json'], {
      configDir: tempConfigDir,
    });
    expect(authRes.exitCode).toBe(0);
    const authJson = JSON.parse(authRes.stdout);
    expect(authJson.success).toBe(true);
    expect(authJson.address).toBe(issuerAddress);
    expect(authJson.network).toBe('testnet');

    const configFile = path.join(tempConfigDir, 'config.json');
    expect(fs.existsSync(configFile)).toBe(true);
    if (process.platform !== 'win32') {
      expect(fs.statSync(configFile).mode & 0o777).toBe(0o600);
    }

    // 2. Create commitment via `pactum commitments create`
    const createRes = await runCli(
      [
        'commitments',
        'create',
        '--counterparty',
        counterpartyAddress,
        '--terms-hash',
        termsHash,
        '--due-at',
        String(dueAt),
        '--rpc-url',
        sandbox.rpcUrl,
        '--json',
      ],
      { configDir: tempConfigDir },
    );
    expect(createRes.exitCode).toBe(0);
    const createJson = JSON.parse(createRes.stdout);
    expect(createJson.success).toBe(true);
    expect(createJson.commitmentId).toBe(1);
    expect(createJson.issuer).toBe(issuerAddress);
    expect(createJson.counterparty).toBe(counterpartyAddress);
    expect(createJson.status).toBe('Pending');
    expect(sandbox.commitments.get(1)?.status).toBe('Pending');

    // 3. Attest commitment via `pactum commitments attest`
    const attestRes = await runCli(
      [
        'commitments',
        'attest',
        '1',
        '--outcome',
        'Fulfilled',
        '--rpc-url',
        sandbox.rpcUrl,
        '--json',
      ],
      { configDir: tempConfigDir },
    );
    expect(attestRes.exitCode).toBe(0);
    const attestJson = JSON.parse(attestRes.stdout);
    expect(attestJson.success).toBe(true);
    expect(attestJson.commitmentId).toBe(1);
    expect(attestJson.outcome).toBe('Fulfilled');
    expect(sandbox.commitments.get(1)?.status).toBe('Fulfilled');

    // 4. Verify commitments list table & JSON reflect updated state
    const listRes = await runCli(
      ['commitments', 'list', counterpartyAddress, '--api-url', sandbox.apiUrl],
      { configDir: tempConfigDir },
    );
    expect(listRes.exitCode).toBe(0);
    expect(listRes.stdout).toContain('#1');
    expect(listRes.stdout).toContain('Fulfilled');

    // 5. Query reputation via `pactum reputation get` against sandbox RPC
    const repRes = await runCli(
      ['reputation', 'get', counterpartyAddress, '--rpc-url', sandbox.rpcUrl, '--json'],
      { configDir: tempConfigDir },
    );
    expect(repRes.exitCode).toBe(0);
    const repJson = JSON.parse(repRes.stdout);
    expect(repJson.address).toBe(counterpartyAddress);
    expect(repJson.score).toBe(100);
    expect(repJson.reputation.fulfilled).toBe(1);
    expect(repJson.reputation.late).toBe(0);
    expect(repJson.reputation.breached).toBe(0);
  });

  it('supports stdin credential piping, status inspection, and credential clearing in isolated temp directories', async () => {
    const kp = Keypair.random();

    const stdinAuth = await runCli(['auth', 'init', '--secret-stdin', '--json'], {
      configDir: tempConfigDir,
      stdin: `${kp.secret()}\n`,
    });
    expect(stdinAuth.exitCode).toBe(0);
    expect(JSON.parse(stdinAuth.stdout).address).toBe(kp.publicKey());

    const statusRes = await runCli(['auth', '--status'], {
      configDir: tempConfigDir,
    });
    expect(statusRes.exitCode).toBe(0);
    expect(statusRes.stdout).toContain('Authenticated');
    expect(statusRes.stdout).toContain(kp.publicKey());

    const clearRes = await runCli(['auth', '--clear', '--json'], {
      configDir: tempConfigDir,
    });
    expect(clearRes.exitCode).toBe(0);
    expect(JSON.parse(clearRes.stdout).success).toBe(true);

    const afterClearStatus = await runCli(['auth', '--status', '--json'], {
      configDir: tempConfigDir,
    });
    expect(afterClearStatus.exitCode).toBe(0);
    expect(JSON.parse(afterClearStatus.stdout).authenticated).toBe(false);
  });

  it('rejects invalid seed phrases and malformed Stellar keys with non-zero exit code', async () => {
    const badSeedRes = await runCli(
      ['auth', 'init', 'abandon abandon abandon abandon abandon abandon abandon abandon', '--json'],
      { configDir: tempConfigDir },
    );
    expect(badSeedRes.exitCode).toBe(1);
    const badSeedErr = JSON.parse(badSeedRes.stderr);
    expect(badSeedErr.error).toContain('Invalid Stellar secret key');
    expect(fs.existsSync(path.join(tempConfigDir, 'config.json'))).toBe(false);

    const badAddressRes = await runCli(
      ['reputation', 'get', 'GNOT_A_VALID_STELLAR_PUBLIC_KEY_12345', '--json'],
      { configDir: tempConfigDir },
    );
    expect(badAddressRes.exitCode).toBe(1);
    expect(JSON.parse(badAddressRes.stderr).error).toContain('Invalid Stellar public key');
  });

  it('surfaces Soroban contract simulation errors during commitment creation, attestation, and reputation queries', async () => {
    const issuer = Keypair.random();
    const counterparty = Keypair.random();

    await runCli(['auth', 'init', issuer.secret()], { configDir: tempConfigDir });

    // Attesting a non-existent commitment triggers Contract Error #404
    const missingAttest = await runCli(
      [
        'commitments',
        'attest',
        '999',
        '--outcome',
        'Fulfilled',
        '--rpc-url',
        sandbox.rpcUrl,
        '--json',
      ],
      { configDir: tempConfigDir },
    );
    expect(missingAttest.exitCode).toBe(1);
    expect(JSON.parse(missingAttest.stderr).error).toContain('CommitmentNotFound');

    // Injected contract error during commitment creation
    sandbox.injectContractError = 'HostError: Error(Contract, #401): UnauthorizedIssuer';
    const createFail = await runCli(
      [
        'commitments',
        'create',
        '--counterparty',
        counterparty.publicKey(),
        '--rpc-url',
        sandbox.rpcUrl,
        '--json',
      ],
      { configDir: tempConfigDir },
    );
    expect(createFail.exitCode).toBe(1);
    expect(JSON.parse(createFail.stderr).error).toContain('UnauthorizedIssuer');

    // Injected contract error during reputation query
    const repFail = await runCli(
      ['reputation', 'get', counterparty.publicKey(), '--rpc-url', sandbox.rpcUrl, '--json'],
      { configDir: tempConfigDir },
    );
    expect(repFail.exitCode).toBe(1);
    expect(JSON.parse(repFail.stderr).error).toContain('UnauthorizedIssuer');
  });

  it('handles network disconnects cleanly and falls back to Backend API when Soroban RPC is unreachable', async () => {
    const issuer = Keypair.random();
    const counterparty = Keypair.random();
    await runCli(['auth', 'init', issuer.secret()], { configDir: tempConfigDir });

    // Seed reputation in sandbox backend API, then point --rpc-url at an closed port
    sandbox.reputations.set(counterparty.publicKey(), {
      fulfilled: 8,
      late: 2,
      breached: 0,
    });

    const fallbackRep = await runCli(
      [
        'reputation',
        'get',
        counterparty.publicKey(),
        '--rpc-url',
        'http://127.0.0.1:1/soroban/rpc',
        '--api-url',
        sandbox.apiUrl,
        '--json',
      ],
      { configDir: tempConfigDir },
    );
    expect(fallbackRep.exitCode).toBe(0);
    const parsedFallback = JSON.parse(fallbackRep.stdout);
    expect(parsedFallback.source).toBe('backend-api');
    expect(parsedFallback.score).toBe(90);

    // Simulate abrupt socket disconnect on both RPC and API
    sandbox.injectDisconnect = true;

    const disconnectCreate = await runCli(
      [
        'commitments',
        'create',
        '--counterparty',
        counterparty.publicKey(),
        '--rpc-url',
        sandbox.rpcUrl,
        '--json',
      ],
      { configDir: tempConfigDir },
    );
    expect(disconnectCreate.exitCode).toBe(1);
    expect(JSON.parse(disconnectCreate.stderr).error).toBeTruthy();

    const disconnectList = await runCli(
      ['commitments', 'list', counterparty.publicKey(), '--api-url', sandbox.apiUrl, '--json'],
      { configDir: tempConfigDir },
    );
    expect(disconnectList.exitCode).toBe(1);
    expect(JSON.parse(disconnectList.stderr).error).toBeTruthy();
  });
});
