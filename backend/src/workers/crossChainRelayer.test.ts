import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  CrossChainRelayer,
  TrustScoreEntry,
  MemoryBatchStore,
  TrustScoreBatch,
} from './crossChainRelayer';
import {
  runAsynchronousDkg,
  FrostTssCoordinator,
  verifyThresholdSignature,
  modQ,
} from '../crypto/tss';

describe('CrossChainRelayer', () => {
  const dummyRegistryId = '0x1111111111111111111111111111111111111111111111111111111111111111';

  it('correctly identifies source chain reorganization', () => {
    const mockSorobanClient = {} as any;
    const mockOracleContract = {} as any;
    const mockSigner = {} as any;

    const relayer = new CrossChainRelayer(mockSorobanClient, mockOracleContract, mockSigner, {
      registryId: dummyRegistryId,
      oracleContractAddress: '0x0000000000000000000000000000000000000001',
      sourceChainId: 1001,
    });

    // Reorg: canonical ledger sequence rolled backward from 1050 to 1040
    assert.equal(relayer.detectSourceReorg(1050n, 1040n), true);

    // Monotonic progression: standard sequential advance
    assert.equal(relayer.detectSourceReorg(1050n, 1051n), false);
  });

  it('encodes batch into expected ABI wire format', () => {
    const mockSorobanClient = {} as any;
    const mockOracleContract = {} as any;
    const mockSigner = {} as any;

    const relayer = new CrossChainRelayer(mockSorobanClient, mockOracleContract, mockSigner, {
      registryId: dummyRegistryId,
      oracleContractAddress: '0x0000000000000000000000000000000000000001',
      sourceChainId: 1001,
    });

    const entry: TrustScoreEntry = {
      stellarAddress: '0x0000000000000000000000000000000000000000000000000000000000000001',
      score: 95n,
      fulfilledCount: 10,
      lateCount: 0,
      breachedCount: 0,
      sourceLedgerSeq: 5000n,
    };

    const encoded = relayer.encodeBatch({
      version: 1,
      registryId: dummyRegistryId,
      batchNonce: 1n,
      batchTimestamp: 1700000000n,
      entries: [entry],
    });

    assert.ok(encoded.startsWith('0x'));
    assert.ok(encoded.length > 64);
  });

  it('persists and retrieves batches through MemoryBatchStore across operations', async () => {
    const store = new MemoryBatchStore();
    const batch: TrustScoreBatch = {
      version: 1,
      registryId: dummyRegistryId,
      batchNonce: 42n,
      batchTimestamp: 1700000000n,
      entries: [],
    };

    await store.saveBatch(batch);
    const retrieved = await store.getBatch(42n);
    assert.deepEqual(retrieved, batch);

    await store.deleteBatch(42n);
    const deleted = await store.getBatch(42n);
    assert.equal(deleted, null);
  });

  it('relays batch with 3-of-5 FROST threshold signature while tolerating 2 offline nodes and slashing malicious share signers', async () => {
    const dkg = await runAsynchronousDkg(3, 5);
    const coordinator = new FrostTssCoordinator(dkg);

    let capturedPayload = '';
    let capturedCommitment = '';
    let capturedZ = '';

    const mockOracleContract = {
      lastBatchNonce: async () => 0n,
      receiveThresholdBatch: async (payload: string, commitmentAddress: string, z: string) => {
        capturedPayload = payload;
        capturedCommitment = commitmentAddress;
        capturedZ = z;
        return {
          hash: '0xdeadbeef00000000000000000000000000000000000000000000000000000001',
          wait: async () => ({
            status: 1,
            hash: '0xdeadbeef00000000000000000000000000000000000000000000000000000001',
          }),
        };
      },
    } as any;

    const relayer = new CrossChainRelayer({} as any, mockOracleContract, {} as any, {
      registryId: dummyRegistryId,
      oracleContractAddress: '0x0000000000000000000000000000000000000001',
      sourceChainId: 1001,
      tssCoordinator: coordinator,
    });

    const entry: TrustScoreEntry = {
      stellarAddress: '0x0000000000000000000000000000000000000000000000000000000000000007',
      score: 98n,
      fulfilledCount: 15,
      lateCount: 1,
      breachedCount: 0,
      sourceLedgerSeq: 8000n,
    };

    const result = await relayer.submitBatchWithThresholdSignature([entry], {
      offlineNodeIds: [5],
      corruptShareHooks: {
        3: (z) => modQ(z + 42n),
      },
    });

    assert.equal(
      result.txHash,
      '0xdeadbeef00000000000000000000000000000000000000000000000000000001',
    );
    assert.deepEqual(result.signature.signers, [1, 2, 4]);
    assert.equal(result.signature.slashedCulprits.length, 1);
    assert.equal(result.signature.slashedCulprits[0].culpritNodeId, 3);
    assert.equal(capturedCommitment, result.signature.commitmentAddress);
    assert.equal(capturedZ, result.signature.z);

    const expectedDigest = relayer.computeThresholdBatchDigest(1n, capturedPayload);
    assert.equal(verifyThresholdSignature(expectedDigest, result.signature), true);
  });
});
