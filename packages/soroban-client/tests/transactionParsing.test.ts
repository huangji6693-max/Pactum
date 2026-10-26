import { afterEach, describe, expect, it, vi } from 'vitest';
import { Account, Keypair, Networks, TransactionBuilder, BASE_FEE, rpc, xdr } from '@stellar/stellar-sdk';
import {
  SorobanSimulationError,
  extractDiagnosticEventBlobs,
  hexToBytes,
  preflightSimulate,
  fetchLatestLedgerAnchor,
  fetchArbitrator,
  fetchReputationFromRpc,
  submitCreateCommitment,
  decodeSimulationError,
  decodeXdrBlob,
  isSorobanXdrError,
} from '../src/index';

describe('transaction parsing & Soroban client helpers', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  describe('hexToBytes', () => {
    it('parses a 64-character hex string with or without 0x prefix', () => {
      const hex = 'a'.repeat(64);
      const bytes = hexToBytes(hex);
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(32);
      expect(bytes[0]).toBe(0xaa);

      const prefixed = hexToBytes('0x' + hex);
      expect(prefixed).toEqual(bytes);
    });

    it('rejects hex strings that are not 64 characters long', () => {
      expect(() => hexToBytes('deadbeef')).toThrow(/expected 64 hex characters/);
    });
  });

  describe('SorobanSimulationError & XDR decoding', () => {
    it('decodes known contract error codes and populates decodedXdrError', () => {
      const err = new SorobanSimulationError(
        'Simulation failed',
        'Error(Contract, #1)',
        [],
        'create_commitment',
      );
      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(SorobanSimulationError);
      expect(err.decodedXdrError.message).toBe('Due date must be in the future.');
      expect(err.decodedXdrError.attemptedOperation?.operation).toBe('create_commitment');
    });

    it('extracts base64 diagnostic event blobs and detects XDR errors', () => {
      const scValB64 = xdr.ScVal.scvString(
        'test_event_payload_long_enough_for_regex_match',
      ).toXDR('base64');
      expect(isSorobanXdrError(scValB64)).toBe(true);
      expect(decodeXdrBlob(scValB64)).toContain('ScVal:');

      const blobs = extractDiagnosticEventBlobs({
        error: `Simulation failed: ${scValB64}`,
        events: [{ toXDR: () => scValB64 }],
      });
      expect(blobs.length).toBeGreaterThanOrEqual(1);
    });

    it('decodes simulation errors with fallback guidance', () => {
      const decoded = decodeSimulationError('HostError: budget exceeded', [], 'attest');
      expect(decoded.message).toContain('host-level error');
      expect(decoded.attemptedOperation?.operation).toBe('attest');
    });
  });

  describe('preflightSimulate & RPC queries', () => {
    it('parses fee, CPU instructions, memory bytes, and required authorizations from preflightSimulate', async () => {
      const kp = Keypair.random();
      const authEntry = new xdr.SorobanAuthorizationEntry({
        credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
        rootInvocation: new xdr.SorobanAuthorizedInvocation({
          function:
            xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
              new xdr.InvokeContractArgs({
                contractAddress: xdr.ScAddress.scAddressTypeAccount(kp.xdrPublicKey()),
                functionName: 'create_commitment',
                args: [],
              }),
            ),
          subInvocations: [],
        }),
      });

      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValue({
        id: '1',
        latestLedger: 500,
        minResourceFee: '250000',
        cost: { cpuInsns: '1250000', memBytes: '65536' },
        result: {
          auth: [authEntry],
          retval: xdr.ScVal.scvU64(xdr.Uint64.fromString('1')),
        },
        _parsed: true,
      } as unknown as rpc.Api.SimulateTransactionResponse);

      const source = new Account(kp.publicKey(), '1');
      const tx = new TransactionBuilder(source, {
        fee: BASE_FEE,
        networkPassphrase: Networks.TESTNET,
      })
        .setTimeout(30)
        .build();

      const preview = await preflightSimulate(tx, 'http://localhost:8000/soroban/rpc');
      expect(preview.success).toBe(true);
      expect(preview.cost?.feeStroops).toBe('250000');
      expect(preview.cost?.feeXlm).toBe('0.0250000');
      expect(preview.cost?.cpuInsns).toBe('1250000');
      expect(preview.cost?.memBytes).toBe('65536');
      expect(preview.requiredAuths).toContain('Source account authorization');
    });

    it('supports both options object and legacy string rpcUrl in fetchLatestLedgerAnchor, fetchArbitrator, and fetchReputationFromRpc', async () => {
      const arbKey = Keypair.random().publicKey();
      const repMap = xdr.ScVal.scvMap([
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol('fulfilled_count'),
          val: xdr.ScVal.scvU32(4),
        }),
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol('late_count'),
          val: xdr.ScVal.scvU32(1),
        }),
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol('breached_count'),
          val: xdr.ScVal.scvU32(0),
        }),
      ]);

      vi.spyOn(rpc.Server.prototype, 'getLatestLedger').mockResolvedValue({
        id: 'ledger-hash-1',
        sequence: 1024,
        protocolVersion: 21,
      } as unknown as rpc.Api.GetLatestLedgerResponse);

      let callIndex = 0;
      vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockImplementation(async () => {
        callIndex++;
        return {
          id: '1',
          latestLedger: 1024,
          minResourceFee: '100',
          result: {
            auth: [],
            retval: callIndex === 1 ? xdr.ScVal.scvString(arbKey) : repMap,
          },
          _parsed: true,
        } as unknown as rpc.Api.SimulateTransactionResponse;
      });

      const anchor = await fetchLatestLedgerAnchor('http://localhost:8000/soroban/rpc');
      expect(anchor).toEqual({ hash: 'ledger-hash-1', sequence: 1024 });

      const arb = await fetchArbitrator('http://localhost:8000/soroban/rpc');
      expect(arb).toBe(arbKey);

      const rep = await fetchReputationFromRpc(arbKey, 'http://localhost:8000/soroban/rpc');
      expect(rep).toEqual({
        address: arbKey,
        fulfilled: 4,
        late: 1,
        breached: 0,
        total: 5,
      });
    });

    it('validates parameters in submitCreateCommitment before network calls', async () => {
      const validKey = Keypair.random().publicKey();
      await expect(
        submitCreateCommitment({
          issuerAddress: 'invalid',
          counterpartyAddress: validKey,
          termsHashHex: 'a'.repeat(64),
          dueAtSeconds: Math.floor(Date.now() / 1000) + 3600,
        }),
      ).rejects.toThrow(/valid Stellar public key/);

      await expect(
        submitCreateCommitment({
          issuerAddress: validKey,
          counterpartyAddress: validKey,
          termsHashHex: 'a'.repeat(64),
          dueAtSeconds: Math.floor(Date.now() / 1000) + 3600,
        }),
      ).rejects.toThrow(/cannot be identical/);
    });
  });
});
