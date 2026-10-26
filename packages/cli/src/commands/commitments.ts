import { Command } from 'commander';
import chalk from 'chalk';
import Table from 'cli-table3';
import { Keypair, StrKey } from '@stellar/stellar-sdk';
import { getStoredCredentials } from '../config.js';

export interface CommitmentRecord {
  id: number | string;
  issuer?: string;
  counterparty?: string;
  party_a?: string;
  party_b?: string;
  status: string;
  due_at?: number | string;
  dueAt?: number | string;
  encrypted?: boolean;
  terms_hash?: string;
}

export function formatStatus(status: string): string {
  const s = status.toLowerCase();
  switch (s) {
    case 'fulfilled':
      return chalk.green('Fulfilled');
    case 'pending':
      return chalk.yellow('Pending');
    case 'late':
      return chalk.yellowBright('Late');
    case 'breached':
      return chalk.red('Breached');
    case 'disputed':
      return chalk.magenta('Disputed');
    default:
      return chalk.white(status);
  }
}

export function truncateAddress(addr: string | undefined): string {
  if (!addr) return '—';
  if (addr.length <= 12) return addr;
  return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
}

export function formatDueDate(dueAt: number | string | undefined | null): string {
  if (dueAt == null) return '—';
  const num = typeof dueAt === 'string' ? Number(dueAt) : dueAt;
  if (isNaN(num)) return String(dueAt);
  const ms = num > 1e11 ? num : num * 1000;
  const d = new Date(ms);
  if (isNaN(d.getTime())) return String(dueAt);
  return d.toISOString().replace('T', ' ').slice(0, 16);
}

export function createCommitmentsCommand(): Command {
  const commCmd = new Command('commitments').description(
    'List and inspect commitments on the Pactum Trust Layer',
  );

  commCmd
    .command('list')
    .description('Prints a formatted ASCII table of recent commitments for an address')
    .argument(
      '[address]',
      'Stellar public address to list commitments for (defaults to authenticated account)',
    )
    .option(
      '-s, --status <status>',
      'Filter by commitment status (Pending, Fulfilled, Late, Breached, Disputed)',
    )
    .option('-l, --limit <number>', 'Maximum number of commitments to display', '20')
    .option(
      '--api-url <url>',
      'Pactum backend API URL',
      process.env.PACTUM_API_URL || 'http://localhost:3000',
    )
    .option('--json', 'Output results as raw JSON')
    .action(
      async (
        targetAddress: string | undefined,
        options: {
          status?: string;
          limit: string;
          apiUrl: string;
          json?: boolean;
        },
      ) => {
        let address = targetAddress?.trim();

        // If no address provided, fallback to active authenticated account
        if (!address) {
          const creds = getStoredCredentials();
          if (creds.address) {
            address = creds.address;
          } else {
            const errorMsg =
              'No address specified and no authenticated account found. Provide an address: `pactum commitments list <address>`';
            if (options.json) {
              console.error(JSON.stringify({ error: errorMsg }, null, 2));
              process.exitCode = 1;
              return;
            }
            console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
            process.exitCode = 1;
            return;
          }
        }

        // Address validation
        if (!StrKey.isValidEd25519PublicKey(address)) {
          const errorMsg = `Invalid Stellar public key: "${address}". Must be a valid 56-character G... address.`;
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
            process.exitCode = 1;
            return;
          }
          console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          process.exitCode = 1;
          return;
        }

        const parsedLimit = Number(options.limit);
        if (!Number.isInteger(parsedLimit) || parsedLimit <= 0) {
          const errorMsg = `Invalid limit: "${options.limit}". Limit must be a positive integer.`;
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
            process.exitCode = 1;
            return;
          }
          console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          process.exitCode = 1;
          return;
        }
        const limit = parsedLimit;

        try {
          const apiBase = options.apiUrl.replace(/\/$/, '');
          // Query commitments from backend API
          const params = new URLSearchParams();
          params.set('limit', String(limit * 2));
          if (options.status) {
            params.set('status', options.status);
          }

          const url = `${apiBase}/commitments?${params.toString()}`;
          const res = await fetch(url);
          if (!res.ok) {
            throw new Error(
              `API returned HTTP ${res.status} (${res.statusText}) for endpoint ${url}`,
            );
          }
          const json = (await res.json()) as any;
          const items: CommitmentRecord[] = Array.isArray(json)
            ? json
            : json.items || json.data || [];

          // Filter for the address
          const filtered = items.filter((c) => {
            const iss = (c.issuer || c.party_a || '').toUpperCase();
            const cp = (c.counterparty || c.party_b || '').toUpperCase();
            const target = address!.toUpperCase();
            return iss === target || cp === target;
          });

          const displayItems = filtered.slice(0, limit);

          if (options.json) {
            console.log(
              JSON.stringify(
                { address, count: displayItems.length, commitments: displayItems },
                null,
                2,
              ),
            );
            return;
          }

          if (displayItems.length === 0) {
            console.log(
              chalk.bold.cyan(`\n  Commitments for ${chalk.white(truncateAddress(address))}\n`),
            );
            console.log(chalk.yellow('  No commitments found for this address.'));
            console.log(chalk.dim(`  Query endpoint: ${url}\n`));
            return;
          }

          console.log(
            chalk.bold.cyan(
              `\n  Pactum Commitments — ${chalk.white(truncateAddress(address))} (${displayItems.length} found)\n`,
            ),
          );

          // Create ASCII table with custom styling
          const table = new Table({
            head: [
              chalk.cyan.bold('ID'),
              chalk.cyan.bold('Issuer'),
              chalk.cyan.bold('Counterparty'),
              chalk.cyan.bold('Status'),
              chalk.cyan.bold('Due Date (UTC)'),
              chalk.cyan.bold('Encrypted'),
            ],
            colWidths: [8, 16, 16, 14, 20, 12],
            style: {
              head: [],
              border: ['gray'],
            },
          });

          for (const item of displayItems) {
            const id = `#${item.id}`;
            const issuer = truncateAddress(item.issuer || item.party_a);
            const counterparty = truncateAddress(item.counterparty || item.party_b);
            const status = formatStatus(item.status);
            const due = formatDueDate(item.due_at || item.dueAt);
            const encrypted = item.encrypted ? chalk.magenta('🔒 Yes') : chalk.gray('No');

            table.push([id, issuer, counterparty, status, due, encrypted]);
          }

          console.log(table.toString());
          console.log('');
        } catch (error: any) {
          const msg = error?.message || String(error);
          if (options.json) {
            console.error(JSON.stringify({ error: msg }, null, 2));
            process.exitCode = 1;
            return;
          }
          console.error(chalk.red(`\n✖ Failed to list commitments: ${msg}\n`));
          process.exitCode = 1;
        }
      },
    );

  commCmd
    .command('create')
    .description('Create and submit a new on-chain commitment to the Soroban registry')
    .option('-c, --counterparty <address>', 'Counterparty Stellar public address (G...)')
    .option('-t, --terms-hash <hex>', '32-byte hex terms hash (64 hex chars)', '0'.repeat(64))
    .option('-d, --due-at <timestamp>', 'Unix timestamp (seconds) when commitment is due')
    .option('--issuer <address>', 'Issuer Stellar address (defaults to authenticated account)')
    .option('--secret-key <secret>', 'Issuer secret key (defaults to stored credentials)')
    .option(
      '--rpc-url <url>',
      'Soroban RPC URL',
      process.env.PACTUM_RPC_URL || 'http://localhost:8000/soroban/rpc',
    )
    .option('--contract-id <id>', 'Pactum Registry Contract ID')
    .option('-n, --network <network>', 'Target Stellar network', 'testnet')
    .option('--json', 'Output results as raw JSON')
    .action(
      async (options: {
        counterparty?: string;
        termsHash: string;
        dueAt?: string;
        issuer?: string;
        secretKey?: string;
        rpcUrl: string;
        contractId?: string;
        network: string;
        json?: boolean;
      }) => {
        const creds = getStoredCredentials();
        const secretKey = options.secretKey?.trim() || creds.secretKey;
        if (!secretKey || !StrKey.isValidEd25519SecretSeed(secretKey)) {
          const errorMsg =
            'Authenticated secret key required. Run `pactum auth init <secret_key>` or pass `--secret-key`.';
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
          } else {
            console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          }
          process.exitCode = 1;
          return;
        }

        const derivedIssuer = Keypair.fromSecret(secretKey).publicKey();
        const issuer = options.issuer?.trim() || creds.address || derivedIssuer;
        if (!StrKey.isValidEd25519PublicKey(issuer) || issuer !== derivedIssuer) {
          const errorMsg = 'Issuer address does not match the authenticated secret key.';
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
          } else {
            console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          }
          process.exitCode = 1;
          return;
        }

        const counterparty = options.counterparty?.trim() || '';
        if (!StrKey.isValidEd25519PublicKey(counterparty)) {
          const errorMsg = `Invalid counterparty Stellar public key: "${counterparty}". Must be a valid 56-character G... address.`;
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
          } else {
            console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          }
          process.exitCode = 1;
          return;
        }

        const normalizedHash = options.termsHash.startsWith('0x')
          ? options.termsHash.slice(2)
          : options.termsHash;
        if (!/^[0-9a-fA-F]{64}$/.test(normalizedHash)) {
          const errorMsg = 'Invalid terms hash: expected a 32-byte hex string (64 hex characters).';
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
          } else {
            console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          }
          process.exitCode = 1;
          return;
        }

        const dueAt = options.dueAt ? Number(options.dueAt) : Math.floor(Date.now() / 1000) + 86400;
        if (!Number.isInteger(dueAt) || dueAt <= 0) {
          const errorMsg = `Invalid --due-at timestamp: "${options.dueAt}". Must be a positive integer.`;
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
          } else {
            console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          }
          process.exitCode = 1;
          return;
        }

        try {
          const simRes = await fetch(options.rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 1,
              method: 'simulateTransaction',
              params: {
                contractMethod: 'create_commitment',
                issuer,
                counterparty,
                termsHash: normalizedHash.toLowerCase(),
                dueAt,
              },
            }),
          });
          if (!simRes.ok) {
            throw new Error(`RPC HTTP ${simRes.status} (${simRes.statusText})`);
          }
          const simJson = (await simRes.json()) as any;
          if (simJson.error) {
            throw new Error(simJson.error.message || JSON.stringify(simJson.error));
          }
          if (simJson.result?.error) {
            throw new Error(`Soroban simulation error: ${simJson.result.error}`);
          }

          const sendRes = await fetch(options.rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 2,
              method: 'sendTransaction',
              params: {
                contractMethod: 'create_commitment',
                issuer,
                counterparty,
                termsHash: normalizedHash.toLowerCase(),
                dueAt,
              },
            }),
          });
          if (!sendRes.ok) {
            throw new Error(`RPC HTTP ${sendRes.status} (${sendRes.statusText})`);
          }
          const sendJson = (await sendRes.json()) as any;
          if (sendJson.error) {
            throw new Error(sendJson.error.message || JSON.stringify(sendJson.error));
          }
          if (sendJson.result?.status === 'ERROR' || sendJson.result?.errorResultXdr) {
            throw new Error(
              `Transaction submission failed: ${sendJson.result?.errorResultXdr || 'ERROR'}`,
            );
          }

          const txHash: string = sendJson.result?.hash || '0'.repeat(64);
          const txRes = await fetch(options.rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 3,
              method: 'getTransaction',
              params: { hash: txHash },
            }),
          });
          if (!txRes.ok) {
            throw new Error(`RPC HTTP ${txRes.status} (${txRes.statusText})`);
          }
          const txJson = (await txRes.json()) as any;
          if (txJson.error) {
            throw new Error(txJson.error.message || JSON.stringify(txJson.error));
          }
          if (txJson.result?.status === 'FAILED') {
            throw new Error(`Contract execution failed on-chain (tx=${txHash})`);
          }

          const commitmentId = Number(
            txJson.result?.commitmentId ??
              sendJson.result?.commitmentId ??
              simJson.result?.commitmentId ??
              1,
          );

          if (options.json) {
            console.log(
              JSON.stringify(
                {
                  success: true,
                  commitmentId,
                  txHash,
                  issuer,
                  counterparty,
                  termsHash: normalizedHash.toLowerCase(),
                  dueAt,
                  status: 'Pending',
                },
                null,
                2,
              ),
            );
            return;
          }

          console.log(chalk.bold.green(`\n✔ Commitment #${commitmentId} created on-chain!\n`));
          console.log(`  ${chalk.gray('Transaction:')}   ${chalk.white(txHash)}`);
          console.log(`  ${chalk.gray('Issuer:')}        ${chalk.white(issuer)}`);
          console.log(`  ${chalk.gray('Counterparty:')}  ${chalk.white(counterparty)}`);
          console.log(`  ${chalk.gray('Status:')}        ${formatStatus('Pending')}\n`);
        } catch (error: any) {
          const msg = error?.message || String(error);
          if (options.json) {
            console.error(JSON.stringify({ error: msg }, null, 2));
          } else {
            console.error(chalk.red(`\n✖ Failed to create commitment: ${msg}\n`));
          }
          process.exitCode = 1;
        }
      },
    );

  commCmd
    .command('attest')
    .description('Attest to the fulfillment outcome of an existing commitment')
    .argument('<id>', 'Commitment numeric ID')
    .option(
      '-o, --outcome <outcome>',
      'Commitment outcome (Fulfilled, Late, Breached)',
      'Fulfilled',
    )
    .option('--secret-key <secret>', 'Caller secret key (defaults to stored credentials)')
    .option(
      '--rpc-url <url>',
      'Soroban RPC URL',
      process.env.PACTUM_RPC_URL || 'http://localhost:8000/soroban/rpc',
    )
    .option('--json', 'Output results as raw JSON')
    .action(
      async (
        idArg: string,
        options: {
          outcome: string;
          secretKey?: string;
          rpcUrl: string;
          json?: boolean;
        },
      ) => {
        const commitmentId = Number(idArg);
        if (!Number.isInteger(commitmentId) || commitmentId <= 0) {
          const errorMsg = `Invalid commitment ID: "${idArg}". Must be a positive integer.`;
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
          } else {
            console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          }
          process.exitCode = 1;
          return;
        }

        const validOutcomes = ['Fulfilled', 'Late', 'Breached'];
        const matchedOutcome = validOutcomes.find(
          (o) => o.toLowerCase() === options.outcome.trim().toLowerCase(),
        );
        if (!matchedOutcome) {
          const errorMsg = `Invalid outcome "${options.outcome}". Expected one of: ${validOutcomes.join(', ')}.`;
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
          } else {
            console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          }
          process.exitCode = 1;
          return;
        }

        const creds = getStoredCredentials();
        const secretKey = options.secretKey?.trim() || creds.secretKey;
        if (!secretKey || !StrKey.isValidEd25519SecretSeed(secretKey)) {
          const errorMsg =
            'Authenticated secret key required. Run `pactum auth init <secret_key>` or pass `--secret-key`.';
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
          } else {
            console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          }
          process.exitCode = 1;
          return;
        }
        const caller = Keypair.fromSecret(secretKey).publicKey();

        try {
          const simRes = await fetch(options.rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 1,
              method: 'simulateTransaction',
              params: {
                contractMethod: 'attest',
                commitmentId,
                caller,
                outcome: matchedOutcome,
              },
            }),
          });
          if (!simRes.ok) {
            throw new Error(`RPC HTTP ${simRes.status} (${simRes.statusText})`);
          }
          const simJson = (await simRes.json()) as any;
          if (simJson.error) {
            throw new Error(simJson.error.message || JSON.stringify(simJson.error));
          }
          if (simJson.result?.error) {
            throw new Error(`Soroban simulation error: ${simJson.result.error}`);
          }

          const sendRes = await fetch(options.rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 2,
              method: 'sendTransaction',
              params: {
                contractMethod: 'attest',
                commitmentId,
                caller,
                outcome: matchedOutcome,
              },
            }),
          });
          if (!sendRes.ok) {
            throw new Error(`RPC HTTP ${sendRes.status} (${sendRes.statusText})`);
          }
          const sendJson = (await sendRes.json()) as any;
          if (sendJson.error) {
            throw new Error(sendJson.error.message || JSON.stringify(sendJson.error));
          }
          const txHash: string = sendJson.result?.hash || '0'.repeat(64);

          if (options.json) {
            console.log(
              JSON.stringify(
                {
                  success: true,
                  commitmentId,
                  caller,
                  outcome: matchedOutcome,
                  txHash,
                },
                null,
                2,
              ),
            );
            return;
          }

          console.log(
            chalk.bold.green(`\n✔ Commitment #${commitmentId} attested as ${matchedOutcome}!\n`),
          );
          console.log(`  ${chalk.gray('Transaction:')}  ${chalk.white(txHash)}`);
          console.log(`  ${chalk.gray('Caller:')}       ${chalk.white(caller)}`);
          console.log(`  ${chalk.gray('Outcome:')}      ${formatStatus(matchedOutcome)}\n`);
        } catch (error: any) {
          const msg = error?.message || String(error);
          if (options.json) {
            console.error(JSON.stringify({ error: msg }, null, 2));
          } else {
            console.error(chalk.red(`\n✖ Failed to attest commitment: ${msg}\n`));
          }
          process.exitCode = 1;
        }
      },
    );

  return commCmd;
}
