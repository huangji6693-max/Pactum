import { Keypair } from '@stellar/stellar-sdk';
import { Buffer } from 'buffer';
import { describe, expect, it } from 'vitest';

import {
  computeBucketListRootHex,
  computeLedgerHeaderHashHex,
  evaluateCuckooInclusionProof,
  sha256Hex,
  sha256PairHex,
  verifySpvHeaderChain,
  type LedgerHeaderEntry,
} from '../../workers/validation.worker';
import {
  SpvStateManager,
  computeCommitmentLeafHash,
  type SpvSecurityWarningBanner,
} from './rpcClient';

describe('Client-Side SPV Header Verification & Cuckoo Filter WASM Integration (#301)', () => {
  it('evaluates Cuckoo Filter membership and SHA-256 Merkle inclusion proofs in < 5ms', () => {
    const populateKeys = Array.from({ length: 500 }, (_, i) => `commitment:${i + 1}`);
    const targetKey = 'commitment:250';
    const leafHash = sha256Hex(targetKey);
    const sibling0 = sha256Hex('sibling-0');
    const sibling1 = sha256Hex('sibling-1');

    const level1 = sha256PairHex(leafHash, sibling0);
    const expectedBucketRoot = sha256PairHex(sibling1, level1);

    // Pre-populate filter first, then measure pure lookup + Merkle branch evaluation
    evaluateCuckooInclusionProof({
      commitmentKey: targetKey,
      leafHash,
      merkleBranch: [],
      expectedBucketRoot: leafHash,
      populateKeys,
      resetFilter: true,
    });

    const result = evaluateCuckooInclusionProof({
      commitmentKey: targetKey,
      leafHash,
      merkleBranch: [
        { sibling: sibling0, isLeft: false },
        { sibling: sibling1, isLeft: true },
      ],
      expectedBucketRoot,
    });

    expect(result.isValid).toBe(true);
    expect(result.cuckooHit).toBe(true);
    expect(result.merkleValid).toBe(true);
    expect(result.elapsedMs).toBeLessThan(5);

    // Absent commitment is immediately rejected by Cuckoo Filter
    const missResult = evaluateCuckooInclusionProof({
      commitmentKey: 'commitment:999999',
      leafHash,
      merkleBranch: [
        { sibling: sibling0, isLeft: false },
        { sibling: sibling1, isLeft: true },
      ],
      expectedBucketRoot,
    });
    expect(missResult.isValid).toBe(false);
    expect(missResult.cuckooHit).toBe(false);
  });

  it('streams and verifies continuous Stellar ledger headers with Ed25519 validator signatures and SHA-256 bucket list hashes', () => {
    const validator = Keypair.random();
    const headers: LedgerHeaderEntry[] = [];
    let prevHash = '00'.repeat(32);

    for (let seq = 1000; seq < 1005; seq++) {
      const bucketEntries = [
        `entry-${seq}-a`,
        `entry-${seq}-b`,
        `entry-${seq}-c`,
        `entry-${seq}-d`,
      ];
      const bucketListHash = computeBucketListRootHex(bucketEntries);
      const headerBase = {
        sequence: seq,
        previousHeaderHash: prevHash,
        bucketListHash,
        headerXdrBase64: Buffer.from(`ledger-xdr-${seq}`).toString('base64'),
      };
      const headerHashHex = computeLedgerHeaderHashHex(headerBase);
      const sigHex = Buffer.from(validator.sign(Buffer.from(headerHashHex, 'hex'))).toString('hex');

      headers.push({
        ...headerBase,
        validatorPublicKey: validator.publicKey(),
        validatorSignatureHex: sigHex,
        bucketEntries,
      });
      prevHash = headerHashHex;
    }

    const validRes = verifySpvHeaderChain(headers, [validator.publicKey()]);
    expect(validRes.valid).toBe(true);
    expect(validRes.verifiedCount).toBe(5);
    expect(validRes.headHash).toBe(prevHash);

    // Tamper with a bucket list hash at index 2
    const tamperedBucketHeaders = headers.map((h, i) =>
      i === 2 ? { ...h, bucketListHash: 'ff'.repeat(32) } : h,
    );
    const badBucketRes = verifySpvHeaderChain(tamperedBucketHeaders, [validator.publicKey()]);
    expect(badBucketRes.valid).toBe(false);
    expect(badBucketRes.error).toMatch(/Bucket list SHA-256 root mismatch/);

    // Tamper with an Ed25519 validator signature at index 3
    const rogueValidator = Keypair.random();
    const forgedSigHeaders = headers.map((h, i) =>
      i === 3
        ? {
            ...h,
            validatorSignatureHex: Buffer.from(
              rogueValidator.sign(Buffer.from(computeLedgerHeaderHashHex(h), 'hex')),
            ).toString('hex'),
          }
        : h,
    );
    const badSigRes = verifySpvHeaderChain(forgedSigHeaders, [validator.publicKey()]);
    expect(badSigRes.valid).toBe(false);
    expect(badSigRes.error).toMatch(/Invalid Ed25519 validator signature/);
  });

  it('flags and blocks simulated malicious RPC responses (spoofed balances and tampered commitments) with warning banners', () => {
    const warnings: SpvSecurityWarningBanner[] = [];
    const manager = new SpvStateManager({
      onWarningBanner: (banner) => warnings.push(banner),
    });

    const honestCommitment = {
      id: 42n,
      issuer: 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7',
      counterparty: 'GBDEVU63Y6NTHJQQZIKVTC23NWLQVP3WJ2RI2OTSJTNYOIGICST6DUXR',
      terms_hash: new Uint8Array([1, 2, 3, 4]),
      due_at: 1800000000n,
      status: 0,
    };

    const sibling = sha256Hex('bucket-sibling-42');
    const cmtLeaf = computeCommitmentLeafHash(honestCommitment);
    const cmtRoot = sha256PairHex(cmtLeaf, sibling);

    manager.registerCommitmentProof(honestCommitment, [{ sibling, isLeft: false }], cmtRoot);

    const accountAddr = honestCommitment.issuer;
    const honestBalance = 500_000_000n;
    const balLeaf = sha256Hex(`${accountAddr}:${honestBalance.toString()}`);
    const balRoot = sha256PairHex(balLeaf, sibling);

    manager.registerAccountBalanceProof(
      accountAddr,
      honestBalance,
      [{ sibling, isLeft: false }],
      balRoot,
    );

    // 1. Honest commitment and balance pass SPV verification
    expect(manager.validateCommitmentResponse(42, honestCommitment)).toEqual(honestCommitment);
    expect(manager.validateAccountBalanceResponse(accountAddr, honestBalance)).toBe(honestBalance);
    expect(warnings.length).toBe(0);

    // 2. Simulated malicious RPC response: tampered commitment status/due_at
    const tamperedCommitment = {
      ...honestCommitment,
      status: 1, // RPC spoofs Fulfilled instead of Pending
    };
    expect(manager.validateCommitmentResponse(42, tamperedCommitment)).toBeNull();
    expect(warnings.length).toBe(1);
    expect(warnings[0].code).toBe('TAMPERED_COMMITMENT_PAYLOAD');
    expect(warnings[0].bannerMessage).toMatch(/WARNING: Malicious RPC response blocked/);

    // 3. Simulated malicious RPC response: spoofed account balance
    expect(manager.validateAccountBalanceResponse(accountAddr, 999_999_999_999n)).toBeNull();
    expect(warnings.length).toBe(2);
    expect(warnings[1].code).toBe('SPOOFED_ACCOUNT_BALANCE');
    expect(warnings[1].bannerMessage).toMatch(
      /WARNING: Malicious RPC response blocked — spoofed balance/,
    );

    // 4. Simulated malicious RPC response: phantom commitment absent from Cuckoo Filter
    expect(manager.validateCommitmentResponse(777, { ...honestCommitment, id: 777n })).toBeNull();
    expect(warnings.length).toBe(3);
    expect(warnings[2].code).toBe('UNINDEXED_PHANTOM_COMMITMENT');
  });
});
