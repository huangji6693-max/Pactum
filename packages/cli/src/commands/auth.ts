import readline from 'node:readline';
import { Command } from 'commander';
import chalk from 'chalk';
import { StrKey } from '@stellar/stellar-sdk';
import {
  saveCredentials,
  getStoredCredentials,
  clearCredentials,
  getConfigFilePath,
} from '../config.js';

export async function readSecretFromStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => {
      resolve(data.trim());
    });
    process.stdin.on('error', reject);
  });
}

export async function promptHiddenSecret(
  promptText = 'Enter Stellar Secret Key (S...): ',
): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });

    process.stdout.write(chalk.cyan(promptText));

    // Mute character output for password masking
    (rl as any)._writeToOutput = function _writeToOutput(stringToWrite: string) {
      if (stringToWrite.includes('\r') || stringToWrite.includes('\n')) {
        process.stdout.write(stringToWrite);
      }
    };

    rl.question('', (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

export function createAuthCommand(): Command {
  const authCmd = new Command('auth')
    .description(
      'Authenticate and store your Stellar secret key locally in a secure keychain/config',
    )
    .argument('[secret_key]', 'Stellar secret key (starts with S, 56 characters) or "init"')
    .argument('[init_secret_key]', 'Stellar secret key when invoking `pactum auth init <key>`')
    .option('-n, --network <network>', 'Default network to associate with credentials', 'testnet')
    .option(
      '--secret-stdin',
      'Read secret key securely from standard input (recommended for automation)',
    )
    .option('--status', 'Display current authentication status and active public address')
    .option('--clear', 'Clear stored credentials from local config')
    .option('--json', 'Output results in JSON format')
    .action(
      async (
        secretKeyArg: string | undefined,
        initSecretKeyArg: string | undefined,
        options: {
          network: string;
          secretStdin?: boolean;
          status?: boolean;
          clear?: boolean;
          json?: boolean;
        },
      ) => {
        const isInitSubcommand = secretKeyArg?.trim().toLowerCase() === 'init';
        const resolvedArg = isInitSubcommand ? initSecretKeyArg : secretKeyArg;
        // Option: Clear credentials
        if (options.clear) {
          const cleared = clearCredentials();
          if (options.json) {
            console.log(
              JSON.stringify(
                {
                  success: cleared,
                  message: cleared ? 'Credentials cleared' : 'No credentials found',
                },
                null,
                2,
              ),
            );
            return;
          }
          if (cleared) {
            console.log(chalk.green('✔ Stored credentials cleared successfully.'));
          } else {
            console.log(chalk.yellow('No stored credentials were found.'));
          }
          return;
        }

        // Option: Check auth status
        if (options.status) {
          const creds = getStoredCredentials();
          if (options.json) {
            console.log(
              JSON.stringify(
                {
                  authenticated: Boolean(creds.address),
                  address: creds.address ?? null,
                  network: creds.network ?? null,
                  configPath: getConfigFilePath(),
                },
                null,
                2,
              ),
            );
            return;
          }

          if (creds.address) {
            console.log(chalk.bold.cyan('\n  Pactum CLI — Authentication Status\n'));
            console.log(`  ${chalk.gray('Status:')}       ${chalk.green('Authenticated')}`);
            console.log(`  ${chalk.gray('Address:')}      ${chalk.bold.white(creds.address)}`);
            console.log(
              `  ${chalk.gray('Network:')}      ${chalk.magenta(creds.network || 'testnet')}`,
            );
            console.log(`  ${chalk.gray('Config:')}       ${chalk.dim(getConfigFilePath())}\n`);
          } else {
            console.log(chalk.yellow('\n  No active credentials found.'));
            console.log(chalk.dim('  Run `pactum auth` to store your credentials.\n'));
          }
          return;
        }

        // Resolve secret key from argument, stdin, or interactive hidden prompt
        let secretKey = resolvedArg?.trim();
        if (!secretKey && options.secretStdin) {
          secretKey = await readSecretFromStdin();
        } else if (!secretKey && process.stdin.isTTY && !options.json) {
          secretKey = await promptHiddenSecret();
        } else if (!secretKey && isInitSubcommand && !process.stdin.isTTY) {
          secretKey = await readSecretFromStdin();
        }

        if (!secretKey) {
          const creds = getStoredCredentials();
          if (creds.address) {
            if (options.json) {
              console.log(
                JSON.stringify(
                  {
                    authenticated: true,
                    address: creds.address,
                    network: creds.network ?? null,
                    configPath: getConfigFilePath(),
                  },
                  null,
                  2,
                ),
              );
            } else {
              console.log(chalk.bold.cyan('\n  Pactum CLI — Authentication Status\n'));
              console.log(`  ${chalk.gray('Status:')}       ${chalk.green('Authenticated')}`);
              console.log(`  ${chalk.gray('Address:')}      ${chalk.bold.white(creds.address)}`);
              console.log(
                `  ${chalk.gray('Network:')}      ${chalk.magenta(creds.network || 'testnet')}`,
              );
              console.log(`  ${chalk.gray('Config:')}       ${chalk.dim(getConfigFilePath())}\n`);
            }
            return;
          }

          const errorMsg =
            'Secret key required. Provide via argument, --secret-stdin, or interactive prompt.';
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
            process.exitCode = 1;
            return;
          }
          console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          process.exitCode = 1;
          return;
        }

        // Validation: Stellar secret key format
        const trimmed = secretKey.trim();
        if (
          !trimmed.startsWith('S') ||
          trimmed.length !== 56 ||
          !StrKey.isValidEd25519SecretSeed(trimmed)
        ) {
          const errorMsg =
            'Invalid Stellar secret key. Must be a valid 56-character Ed25519 seed starting with "S".';
          if (options.json) {
            console.error(JSON.stringify({ error: errorMsg }, null, 2));
            process.exitCode = 1;
            return;
          }
          console.error(chalk.red(`\n✖ Error: ${errorMsg}\n`));
          process.exitCode = 1;
          return;
        }

        try {
          const saved = saveCredentials(trimmed, options.network);
          const masked = `${trimmed.slice(0, 4)}...${trimmed.slice(-4)}`;

          if (options.json) {
            console.log(
              JSON.stringify(
                {
                  success: true,
                  address: saved.address,
                  network: saved.network,
                  maskedSecret: masked,
                  configPath: saved.path,
                },
                null,
                2,
              ),
            );
            return;
          }

          console.log(chalk.bold.green('\n✔ Key stored successfully in secure local config!\n'));
          console.log(`  ${chalk.gray('Public Address:')}  ${chalk.bold.white(saved.address)}`);
          console.log(`  ${chalk.gray('Secret Key:')}      ${chalk.dim(masked)}`);
          console.log(`  ${chalk.gray('Default Network:')} ${chalk.magenta(saved.network)}`);
          console.log(`  ${chalk.gray('Config Location:')} ${chalk.dim(saved.path)}`);
          console.log(chalk.dim(`  Permissions:      0600 (owner read/write only)\n`));
        } catch (error: any) {
          if (options.json) {
            console.error(
              JSON.stringify({ error: error?.message || 'Failed to save credentials' }, null, 2),
            );
            process.exitCode = 1;
            return;
          }
          console.error(chalk.red(`\n✖ Failed to save credentials: ${error?.message || error}\n`));
          process.exitCode = 1;
        }
      },
    );

  return authCmd;
}
