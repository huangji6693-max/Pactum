import { afterEach, describe, expect, it, vi } from 'vitest';
import { Account, Address, BASE_FEE, Keypair, Networks, TransactionBuilder, rpc, xdr } from '@stellar/stellar-sdk';
import {
  analyzePreflightSimulation,
  extractStorageFootprint,
  runPreflightSimulation,
  stroopsToXlm,
  SOROBAN_MAX_CPU_INSNS,
  SOROBAN_MAX_MEM_BYTES,
} from './usePreflightSimulation';

function buildLedgerKeyContractData(
  contractAddress: string,
  symbolName: string,
  durability: 'persistent' | 'temporary',
): xdr.LedgerKey {
  return xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: Address.fromString(contractAddress).toScAddress(),
      key: xdr.ScVal.scvSymbol(symbolName),
      durability:
        durability === 'temporary'
          ? xdr.ContractDataDurability.temporary()
          : xdr.ContractDataDurability.persistent(),
    }),
  );
}

describe('usePreflightSimulation & predictive gas estimation', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('converts stroops to 7-decimal XLM strings accurately', () => {
    expect(stroopsToXlm('10000000')).toBe('1.0000000');
    expect(stroopsToXlm(100)).toBe('0.0000100');
    expect(stroopsToXlm(0)).toBe('0.0000000');
  });

  it('parses CPU instructions, memory bytes, and fee breakdown from successful simulation', () => {
    const report = analyzePreflightSimulation(
      {
        minResourceFee: '250000',
        cost: {
          cpuInsns: '25000000',
          memBytes: '10485760',
        },
        results: [{ auth: [] }],
      },
      {
        baseFeeStroops: '100',
        accountBalanceStroops: '50000000',
        sourceAddress: 'GASV7ZZOPNYYFEPJ6N3GX4VINJELUQQDRX6UWWOO43F55CV6OBQUEGVK',
        counterpartyAddress: 'GCM5SKB5PS3ZCUXZ4GPLIBY42E63ILOT2EAIIT4UWGDFYOULCTLTRMMB',
        isEncrypted: true,
        hasValidationRules: true,
      },
    );

    expect(report.success).toBe(true);
    expect(report.canSubmit).toBe(true);
    expect(report.blockingReason).toBeNull();
    expect(report.resources.cpuInsns).toBe('25000000');
    expect(report.resources.memBytes).toBe('10485760');
    expect(report.resources.cpuUtilizationPct).toBe(25);
    expect(report.resources.memUtilizationPct).toBe(25);

    expect(report.fees.baseFeeStroops).toBe('100');
    expect(report.fees.resourceFeeStroops).toBe('250000');
    expect(report.fees.totalFeeStroops).toBe('250100');
    expect(report.fees.totalFeeXlm).toBe('0.0250100');
    expect(
      BigInt(report.fees.refundableFeeStroops) + BigInt(report.fees.nonRefundableFeeStroops),
    ).toBe(250000n);

    expect(report.stateChanges.length).toBeGreaterThanOrEqual(3);
    expect(report.balanceChanges).toHaveLength(1);
    expect(report.balanceChanges[0].deltaStroops).toBe('-250100');
    expect(report.balanceChanges[0].beforeBalanceXlm).toBe('5.0000000 XLM');
    expect(report.balanceChanges[0].afterBalanceXlm).toBe('4.9749900 XLM');
  });

  it('analyzes persistent vs temporary storage footprint read/write counts and deposit requirements', () => {
    const contractAddr = 'CBADTVTJ6IN332HIKZ7LWUYMYTLPZYCEBV3X2HS47VHR5UDBHQ3GAA7E';
    const pRead1 = buildLedgerKeyContractData(contractAddr, 'Admin', 'persistent');
    const pRead2 = buildLedgerKeyContractData(contractAddr, 'Arb', 'persistent');
    const tRead1 = buildLedgerKeyContractData(contractAddr, 'Nonce', 'temporary');

    const pWrite1 = buildLedgerKeyContractData(contractAddr, 'Commit', 'persistent');
    const tWrite1 = buildLedgerKeyContractData(contractAddr, 'RuleCache', 'temporary');
    const tWrite2 = buildLedgerKeyContractData(contractAddr, 'RateLim', 'temporary');

    const txDataB64 = new xdr.SorobanTransactionData({
      resources: new xdr.SorobanResources({
        footprint: new xdr.LedgerFootprint({
          readOnly: [pRead1, pRead2, tRead1],
          readWrite: [pWrite1, tWrite1, tWrite2],
        }),
        instructions: 5_000_000,
        diskReadBytes: 4096,
        writeBytes: 2048,
      }),
      resourceFee: xdr.Int64.fromString('120000'),
      ext: new xdr.SorobanTransactionDataExt(0),
    }).toXDR('base64');

    const footprint = extractStorageFootprint(
      {
        transactionData: txDataB64,
        restorePreamble: { minResourceFee: '50000' },
      },
      120_000n,
    );

    expect(footprint.persistentReads).toBe(2);
    expect(footprint.temporaryReads).toBe(1);
    expect(footprint.totalReads).toBe(3);

    expect(footprint.persistentWrites).toBe(1);
    expect(footprint.temporaryWrites).toBe(2);
    expect(footprint.totalWrites).toBe(3);

    expect(footprint.diskReadBytes).toBe(4096);
    expect(footprint.writeBytes).toBe(2048);
    expect(footprint.requiresRestore).toBe(true);
    expect(Number(footprint.storageDepositStroops)).toBeGreaterThan(0);
  });

  it('blocks submission and emits contract_revert warning when simulation fails', () => {
    const report = analyzePreflightSimulation({
      error: 'HostError: Error(Contract, #1)',
      events: [],
    });

    expect(report.success).toBe(false);
    expect(report.canSubmit).toBe(false);
    expect(report.blockingReason).toBe('contract_revert');
    expect(report.warnings.some((w) => w.code === 'contract_revert')).toBe(true);
  });

  it('blocks submission and emits insufficient_balance warning when XLM balance is below total fee', () => {
    const report = analyzePreflightSimulation(
      {
        minResourceFee: '500000',
        cost: { cpuInsns: '1000000', memBytes: '65536' },
      },
      {
        baseFeeStroops: '100',
        accountBalanceStroops: '100000', // Only 0.01 XLM, needs 0.05001 XLM
      },
    );

    expect(report.success).toBe(true);
    expect(report.canSubmit).toBe(false);
    expect(report.blockingReason).toBe('insufficient_balance');
    expect(report.warnings.some((w) => w.code === 'insufficient_balance')).toBe(true);
  });

  it('emits high CPU and memory utilization warnings when usage exceeds 80% of Soroban limits', () => {
    const report = analyzePreflightSimulation({
      minResourceFee: '900000',
      cost: {
        cpuInsns: String(Math.floor(SOROBAN_MAX_CPU_INSNS * 0.85)),
        memBytes: String(Math.floor(SOROBAN_MAX_MEM_BYTES * 0.9)),
      },
    });

    expect(report.success).toBe(true);
    expect(report.canSubmit).toBe(true);
    expect(report.warnings.some((w) => w.code === 'high_cpu_utilization')).toBe(true);
    expect(report.warnings.some((w) => w.code === 'high_memory_utilization')).toBe(true);
  });

  it('executes runPreflightSimulation against rpc.Server and checks account balance', async () => {
    const kp = Keypair.random();
    const accountEntryData = xdr.LedgerEntryData.account(
      new xdr.AccountEntry({
        accountId: kp.xdrAccountId(),
        balance: xdr.Int64.fromString('100000000'), // 10 XLM
        seqNum: xdr.Int64.fromString('1'),
        numSubEntries: 0,
        inflationDest: undefined,
        flags: 0,
        homeDomain: '',
        thresholds: Buffer.from([1, 1, 1, 1]),
        signers: [],
        ext: new xdr.AccountEntryExt(0),
      }),
    );

    vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockResolvedValueOnce({
      id: 'sim-run-1',
      latestLedger: 2000,
      minResourceFee: '45000',
      cost: { cpuInsns: '500000', memBytes: '131072' },
      result: { auth: [], retval: xdr.ScVal.scvVoid() },
    } as unknown as rpc.Api.SimulateTransactionResponse);

    vi.spyOn(rpc.Server.prototype, 'getLedgerEntries').mockResolvedValueOnce({
      entries: [{ val: accountEntryData }],
      latestLedger: 2000,
    } as unknown as rpc.Api.GetLedgerEntriesResponse);

    const tx = new TransactionBuilder(new Account(kp.publicKey(), '1'), {
      fee: BASE_FEE,
      networkPassphrase: Networks.TESTNET,
    })
      .setTimeout(30)
      .build();

    const report = await runPreflightSimulation(tx, {
      sourceAddress: kp.publicKey(),
      checkAccountBalance: true,
    });

    expect(report.success).toBe(true);
    expect(report.canSubmit).toBe(true);
    expect(report.fees.totalFeeStroops).toBe('45100');
    expect(report.balanceChanges[0].beforeBalanceXlm).toBe('10.0000000 XLM');
  });
});
