/* eslint-disable */
const { expect } = require('chai');
const { ethers } = require('hardhat');
const { loadFixture, time } = require('@nomicfoundation/hardhat-network-helpers');
const crypto = require('crypto');

function sha256Buf(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

function hexToBuf(hex) {
  return Buffer.from(hex.replace(/^0x/, ''), 'hex');
}

function bufToHex(buf) {
  return '0x' + buf.toString('hex');
}

function buildCanonicalStateProof({
  contractId,
  stellarAddress,
  scoreData,
  ledgerSeq = 5050,
  merkleProofOverride,
  headerProofOverride,
}) {
  const leafBuf = Buffer.alloc(92);
  hexToBuf(contractId).copy(leafBuf, 0, 0, 32);
  hexToBuf(stellarAddress).copy(leafBuf, 32, 0, 32);
  leafBuf.writeUInt32BE(scoreData.score, 64);
  leafBuf.writeUInt32BE(scoreData.fulfilledCount, 68);
  leafBuf.writeUInt32BE(scoreData.lateCount, 72);
  leafBuf.writeUInt32BE(scoreData.breachedCount, 76);
  leafBuf.writeUInt32BE(scoreData.epoch, 80);
  leafBuf.writeBigUInt64BE(BigInt(scoreData.sourceLedgerSeq), 84);
  const leafHash = bufToHex(sha256Buf(leafBuf));

  const merkleProof = merkleProofOverride || [
    { sibling: '0x' + 'aa'.repeat(32), isRight: true },
    { sibling: '0x' + 'bb'.repeat(32), isRight: false },
  ];

  let current = hexToBuf(leafHash);
  for (const node of merkleProof) {
    const sibling = hexToBuf(node.sibling);
    current = node.isRight
      ? sha256Buf(Buffer.concat([current, sibling]))
      : sha256Buf(Buffer.concat([sibling, current]));
  }
  const stateRootHash = bufToHex(current);

  const headerProof = {
    previousLedgerHash: '0x' + '11'.repeat(32),
    txSetResultHash: '0x' + '22'.repeat(32),
    bucketListHash: stateRootHash,
    ledgerVersion: 21,
    ...(headerProofOverride || {}),
  };

  const headerBuf = Buffer.alloc(104);
  headerBuf.writeUInt32BE(ledgerSeq, 0);
  hexToBuf(headerProof.previousLedgerHash).copy(headerBuf, 4, 0, 32);
  hexToBuf(headerProof.txSetResultHash).copy(headerBuf, 36, 0, 32);
  hexToBuf(headerProof.bucketListHash).copy(headerBuf, 68, 0, 32);
  headerBuf.writeUInt32BE(headerProof.ledgerVersion, 100);
  const ledgerHeaderHash = bufToHex(sha256Buf(headerBuf));

  return {
    version: '1.0.0',
    networkPassphrase: 'Test SDF Network ; September 2015',
    ledgerSeq,
    ledgerHeaderHash,
    stateRootHash,
    contractId,
    stellarAddress,
    scoreData,
    leafHash,
    merkleProof,
    headerProof,
  };
}

const SCHEMA_VERSION = 1;
const SOURCE_CHAIN_ID = 1001; // arbitrary id standing in for "Stellar Pubnet"
const REGISTRY_ID = ethers.id('pactum-registry-contract-id');
const SOURCE_ADDRESS = ethers.zeroPadValue(ethers.toBeHex(0xfeed), 32);
const MAX_BATCH_AGE = 24 * 60 * 60; // 24h, matches the default suggested in the design doc

const BATCH_TUPLE_TYPE =
  'tuple(uint8 version, bytes32 registryId, uint64 batchNonce, uint64 batchTimestamp, ' +
  'tuple(bytes32 stellarAddress, int64 score, uint32 fulfilledCount, uint32 lateCount, uint32 breachedCount, uint64 sourceLedgerSeq)[] entries)';

function encodeBatch(batch) {
  return ethers.AbiCoder.defaultAbiCoder().encode([BATCH_TUPLE_TYPE], [batch]);
}

function stellarAddr(n) {
  return ethers.zeroPadValue(ethers.toBeHex(n), 32);
}

function makeEntry(overrides = {}) {
  return {
    stellarAddress: stellarAddr(1),
    score: 42,
    fulfilledCount: 5,
    lateCount: 1,
    breachedCount: 0,
    sourceLedgerSeq: 100,
    ...overrides,
  };
}

async function makeBatch(overrides = {}) {
  return {
    version: SCHEMA_VERSION,
    registryId: REGISTRY_ID,
    batchNonce: 1,
    batchTimestamp: await time.latest(),
    entries: [makeEntry()],
    ...overrides,
  };
}

describe('PactumTrustOracle', function () {
  async function deployFixture() {
    const [owner, other] = await ethers.getSigners();

    const Endpoint = await ethers.getContractFactory('MockMessagingEndpoint');
    const endpoint = await Endpoint.deploy();

    const Oracle = await ethers.getContractFactory('PactumTrustOracle');
    const oracle = await Oracle.deploy(
      owner.address,
      await endpoint.getAddress(),
      REGISTRY_ID,
      MAX_BATCH_AGE,
    );

    await oracle.connect(owner).setTrustedRemote(SOURCE_CHAIN_ID, SOURCE_ADDRESS);

    return { owner, other, endpoint, oracle };
  }

  async function deliver(endpoint, oracle, batch, opts = {}) {
    const payload = encodeBatch(batch);
    return endpoint.deliver(
      await oracle.getAddress(),
      opts.sourceChainId ?? SOURCE_CHAIN_ID,
      opts.sourceAddress ?? SOURCE_ADDRESS,
      payload,
    );
  }

  describe('happy path', function () {
    it('applies a valid batch and caches the trust score', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      const batch = await makeBatch();

      await expect(deliver(endpoint, oracle, batch))
        .to.emit(oracle, 'TrustScoreBatchUpdated')
        .withArgs(REGISTRY_ID, 1n, 1n);

      const stored = await oracle.getTrustScore(stellarAddr(1));
      expect(stored.score).to.equal(42n);
      expect(stored.fulfilledCount).to.equal(5n);
      expect(stored.lateCount).to.equal(1n);
      expect(stored.breachedCount).to.equal(0n);
      expect(stored.sourceLedgerSeq).to.equal(100n);
      expect(stored.updatedAt).to.be.greaterThan(0n);

      expect(await oracle.isStale(stellarAddr(1), MAX_BATCH_AGE)).to.equal(false);
    });

    it('applies multiple entries in one batch', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      const batch = await makeBatch({
        entries: [
          makeEntry({ stellarAddress: stellarAddr(1), score: 10 }),
          makeEntry({ stellarAddress: stellarAddr(2), score: -5 }),
          makeEntry({ stellarAddress: stellarAddr(3), score: 0 }),
        ],
      });

      await deliver(endpoint, oracle, batch);

      expect((await oracle.getTrustScore(stellarAddr(1))).score).to.equal(10n);
      expect((await oracle.getTrustScore(stellarAddr(2))).score).to.equal(-5n);
      expect((await oracle.getTrustScore(stellarAddr(3))).score).to.equal(0n);
    });

    it('only emits per-entry events when emitDetailedEvents is enabled', async function () {
      const { owner, endpoint, oracle } = await loadFixture(deployFixture);
      const batch = await makeBatch();

      await expect(deliver(endpoint, oracle, batch)).to.not.emit(oracle, 'TrustScoreUpdated');

      await oracle.connect(owner).setEmitDetailedEvents(true);
      const batch2 = await makeBatch({
        batchNonce: 2,
        entries: [makeEntry({ sourceLedgerSeq: 101 })],
      });
      await expect(deliver(endpoint, oracle, batch2))
        .to.emit(oracle, 'TrustScoreUpdated')
        .withArgs(stellarAddr(1), 42n, 101n);
    });
  });

  describe('layer 1: transport authenticity', function () {
    it('rejects calls that do not come from the configured messaging endpoint', async function () {
      const { other, oracle } = await loadFixture(deployFixture);
      const batch = await makeBatch();
      const payload = encodeBatch(batch);

      await expect(oracle.connect(other).receiveMessage(SOURCE_CHAIN_ID, SOURCE_ADDRESS, payload))
        .to.be.revertedWithCustomError(oracle, 'NotMessagingEndpoint')
        .withArgs(other.address);
    });

    it('rejects an unregistered source chain id', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      const batch = await makeBatch();

      await expect(
        deliver(endpoint, oracle, batch, { sourceChainId: 9999 }),
      ).to.be.revertedWithCustomError(oracle, 'UntrustedRemote');
    });

    it("rejects a source address that doesn't match the trusted remote", async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      const batch = await makeBatch();
      const forgedSource = stellarAddr(666);

      await expect(
        deliver(endpoint, oracle, batch, { sourceAddress: forgedSource }),
      ).to.be.revertedWithCustomError(oracle, 'UntrustedRemote');
    });
  });

  describe('layer 2: application-level integrity', function () {
    it('rejects an unsupported schema version', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      const batch = await makeBatch({ version: 2 });

      await expect(deliver(endpoint, oracle, batch))
        .to.be.revertedWithCustomError(oracle, 'UnsupportedVersion')
        .withArgs(2);
    });

    it('rejects a batch declaring an unknown registry id', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      const foreignRegistry = ethers.id('some-other-registry');
      const batch = await makeBatch({ registryId: foreignRegistry });

      await expect(deliver(endpoint, oracle, batch))
        .to.be.revertedWithCustomError(oracle, 'UnknownRegistry')
        .withArgs(foreignRegistry);
    });

    it('rejects a batch larger than MAX_BATCH_SIZE', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      const max = await oracle.MAX_BATCH_SIZE();
      const tooMany = Number(max) + 1;
      const entries = Array.from({ length: tooMany }, (_, i) =>
        makeEntry({ stellarAddress: stellarAddr(i + 1), sourceLedgerSeq: i + 1 }),
      );
      const batch = await makeBatch({ entries });

      await expect(deliver(endpoint, oracle, batch)).to.be.revertedWithCustomError(
        oracle,
        'BatchTooLarge',
      );
    });

    it('rejects a replayed batch (same nonce)', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      const batch = await makeBatch();
      await deliver(endpoint, oracle, batch);

      await expect(deliver(endpoint, oracle, batch)).to.be.revertedWithCustomError(
        oracle,
        'NonceNotIncreasing',
      );
    });

    it('rejects a batch with a lower nonce than the last applied one', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      await deliver(endpoint, oracle, await makeBatch({ batchNonce: 5 }));

      await expect(
        deliver(endpoint, oracle, await makeBatch({ batchNonce: 3 })),
      ).to.be.revertedWithCustomError(oracle, 'NonceNotIncreasing');
    });

    it('rejects a batch older than maxBatchAge', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      const staleTimestamp = (await time.latest()) - MAX_BATCH_AGE - 3600;
      const batch = await makeBatch({ batchTimestamp: staleTimestamp });

      await expect(deliver(endpoint, oracle, batch)).to.be.revertedWithCustomError(
        oracle,
        'BatchTooStale',
      );
    });

    it('accepts a batch that is old but still within the staleness window', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      // A few seconds of headroom below the boundary, since submitting the transaction
      // itself advances block.timestamp by at least one second.
      const nearBoundaryTimestamp = (await time.latest()) - (MAX_BATCH_AGE - 5);
      const batch = await makeBatch({ batchTimestamp: nearBoundaryTimestamp });

      await expect(deliver(endpoint, oracle, batch)).to.not.be.reverted;
    });

    it('rejects an out-of-order sourceLedgerSeq for the same address across batches', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      await deliver(
        endpoint,
        oracle,
        await makeBatch({ batchNonce: 1, entries: [makeEntry({ sourceLedgerSeq: 100 })] }),
      );

      await expect(
        deliver(
          endpoint,
          oracle,
          await makeBatch({ batchNonce: 2, entries: [makeEntry({ sourceLedgerSeq: 50 })] }),
        ),
      ).to.be.revertedWithCustomError(oracle, 'LedgerSeqNotIncreasing');
    });

    it("does not let an older batch's ledger seq clobber a newer one already applied, even for a different address in the same later batch", async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      await deliver(
        endpoint,
        oracle,
        await makeBatch({
          batchNonce: 1,
          entries: [makeEntry({ stellarAddress: stellarAddr(1), sourceLedgerSeq: 100 })],
        }),
      );

      // batch 2 has a valid (higher) nonce, and correctly advances address 2, but tries to
      // regress address 1 - only address 1's entry must be rejected.
      await expect(
        deliver(
          endpoint,
          oracle,
          await makeBatch({
            batchNonce: 2,
            entries: [
              makeEntry({ stellarAddress: stellarAddr(1), sourceLedgerSeq: 99 }),
              makeEntry({ stellarAddress: stellarAddr(2), sourceLedgerSeq: 1 }),
            ],
          }),
        ),
      ).to.be.revertedWithCustomError(oracle, 'LedgerSeqNotIncreasing');

      // and because the whole call reverted, address 2 must not have been applied either.
      expect((await oracle.getTrustScore(stellarAddr(2))).updatedAt).to.equal(0n);
    });
  });

  describe('staleness reads', function () {
    it('treats an address with no history as stale', async function () {
      const { oracle } = await loadFixture(deployFixture);
      expect(await oracle.isStale(stellarAddr(1), MAX_BATCH_AGE)).to.equal(true);
    });

    it('becomes stale once maxAge has elapsed since the last update', async function () {
      const { endpoint, oracle } = await loadFixture(deployFixture);
      await deliver(endpoint, oracle, await makeBatch());

      expect(await oracle.isStale(stellarAddr(1), 1000)).to.equal(false);
      await time.increase(1001);
      expect(await oracle.isStale(stellarAddr(1), 1000)).to.equal(true);
    });
  });

  describe('owner configuration', function () {
    it('restricts configuration setters to the owner', async function () {
      const { other, oracle } = await loadFixture(deployFixture);

      await expect(oracle.connect(other).setMessagingEndpoint(other.address)).to.be.reverted;
      await expect(oracle.connect(other).setTrustedRemote(1, stellarAddr(1))).to.be.reverted;
      await expect(oracle.connect(other).setRegistryId(stellarAddr(1))).to.be.reverted;
      await expect(oracle.connect(other).setMaxBatchAge(1)).to.be.reverted;
      await expect(oracle.connect(other).setEmitDetailedEvents(true)).to.be.reverted;
    });

    it('lets the owner rotate the messaging endpoint and registry id', async function () {
      const { owner, oracle } = await loadFixture(deployFixture);
      const newEndpoint = ethers.Wallet.createRandom().address;
      const newRegistry = ethers.id('new-registry');

      await expect(oracle.connect(owner).setMessagingEndpoint(newEndpoint))
        .to.emit(oracle, 'MessagingEndpointUpdated')
        .withArgs(newEndpoint);
      expect(await oracle.messagingEndpoint()).to.equal(newEndpoint);

      await expect(oracle.connect(owner).setRegistryId(newRegistry))
        .to.emit(oracle, 'RegistryIdUpdated')
        .withArgs(newRegistry);
      expect(await oracle.registryId()).to.equal(newRegistry);
    });
  });

  describe('optimistic challenge window & cross-chain fraud proof disproval (Issue #307)', function () {
    it('locks optimistic score updates during challenge window and finalizes with bond refund after expiry', async function () {
      const { owner, other, oracle } = await loadFixture(deployFixture);
      const [, , relayer] = await ethers.getSigners();

      await oracle.connect(owner).setChallengeWindow(3600);
      const relayerBond = ethers.parseEther('0.2');
      const entry = makeEntry({
        stellarAddress: stellarAddr(77),
        score: 85,
        fulfilledCount: 12,
        lateCount: 1,
        breachedCount: 0,
        sourceLedgerSeq: 500,
      });

      const tx = await oracle.connect(relayer).proposeOptimisticUpdate(entry, {
        value: relayerBond,
      });
      await expect(tx).to.emit(oracle, 'OptimisticUpdateProposed');

      // Score is NOT yet applied while the challenge window is active
      const pendingScore = await oracle.getTrustScore(stellarAddr(77));
      expect(pendingScore.updatedAt).to.equal(0n);

      // Finalizing before the 3600s challenge window expires must revert
      await expect(oracle.connect(other).finalizeOptimisticUpdate(1)).to.be.revertedWithCustomError(
        oracle,
        'ChallengePeriodActive',
      );

      // Advance time past the challenge window and finalize
      await time.increase(3601);

      const relayerBalanceBefore = await ethers.provider.getBalance(relayer.address);
      await expect(oracle.connect(other).finalizeOptimisticUpdate(1))
        .to.emit(oracle, 'OptimisticUpdateFinalized')
        .withArgs(1n, stellarAddr(77), relayer.address, 85n, relayerBond);

      const relayerBalanceAfter = await ethers.provider.getBalance(relayer.address);
      expect(relayerBalanceAfter - relayerBalanceBefore).to.equal(relayerBond);

      const finalizedScore = await oracle.getTrustScore(stellarAddr(77));
      expect(finalizedScore.score).to.equal(85n);
      expect(finalizedScore.fulfilledCount).to.equal(12n);
      expect(finalizedScore.sourceLedgerSeq).to.equal(500n);
      expect(finalizedScore.updatedAt).to.be.greaterThan(0n);
    });

    it('slashes dishonest relayer and pays bond to challenger upon valid contradictory Stellar Merkle proof', async function () {
      const { owner, oracle } = await loadFixture(deployFixture);
      const [, , dishonestRelayer, challenger] = await ethers.getSigners();

      const ZeroTrust = await ethers.getContractFactory('PactumZeroTrustOracle');
      const zeroTrust = await ZeroTrust.deploy(owner.address, REGISTRY_ID);
      await oracle.connect(owner).setZeroTrustOracle(await zeroTrust.getAddress());

      // Dishonest relayer proposes an inflated score of 95 (fulfilledCount = 20, breachedCount = 0) at sourceLedgerSeq 1000
      const relayerBond = ethers.parseEther('0.5');
      const fraudulentEntry = makeEntry({
        stellarAddress: stellarAddr(88),
        score: 95,
        fulfilledCount: 20,
        lateCount: 0,
        breachedCount: 0,
        sourceLedgerSeq: 1000,
      });

      await oracle.connect(dishonestRelayer).proposeOptimisticUpdate(fraudulentEntry, {
        value: relayerBond,
      });

      // Canonical Stellar ledger header at sequence 1050 proves the true score at sourceLedgerSeq 1000 is 30 (with 4 breaches)
      const canonicalProof = buildCanonicalStateProof({
        contractId: REGISTRY_ID,
        stellarAddress: stellarAddr(88),
        ledgerSeq: 1050,
        scoreData: {
          score: 30,
          fulfilledCount: 5,
          lateCount: 2,
          breachedCount: 4,
          epoch: 1,
          sourceLedgerSeq: 1000,
        },
      });
      await zeroTrust
        .connect(owner)
        .setTrustedLedgerHeader(canonicalProof.ledgerSeq, canonicalProof.ledgerHeaderHash);

      const challengerBond = ethers.parseEther('0.05');
      const expectedTotalReward = relayerBond + challengerBond;

      await expect(
        oracle.connect(challenger).challengeOptimisticUpdate(1, canonicalProof, {
          value: challengerBond,
        }),
      )
        .to.changeEtherBalances(
          [oracle, challenger],
          [-relayerBond, relayerBond],
        );

      const proposal = await oracle.getOptimisticProposal(1);
      expect(proposal.status).to.equal(3n); // ProposalStatus.Slashed
      expect(proposal.relayerBond).to.equal(0n);
      expect(await oracle.activeProposalByAddress(stellarAddr(88))).to.equal(0n);

      // Fraudulent score was never applied
      const storedScore = await oracle.getTrustScore(stellarAddr(88));
      expect(storedScore.updatedAt).to.equal(0n);

      // Finalizing a slashed proposal is rejected
      await time.increase(MAX_BATCH_AGE + 10);
      await expect(
        oracle.connect(dishonestRelayer).finalizeOptimisticUpdate(1),
      ).to.be.revertedWithCustomError(oracle, 'ProposalNotPending');
      expect(expectedTotalReward).to.equal(ethers.parseEther('0.55'));
    });

    it('rejects invalid challenges (non-contradictory proof, tampered Merkle path, untrusted header, or insufficient bond)', async function () {
      const { owner, oracle } = await loadFixture(deployFixture);
      const [, , HonestRelayer, attacker] = await ethers.getSigners();

      const relayerBond = ethers.parseEther('0.1');
      const challengerBond = ethers.parseEther('0.05');

      // 1. Rejects optimistic proposal with insufficient relayer bond
      await expect(
        oracle.connect(HonestRelayer).proposeOptimisticUpdate(makeEntry(), {
          value: ethers.parseEther('0.01'),
        }),
      ).to.be.revertedWithCustomError(oracle, 'InsufficientRelayerBond');

      // Honest relayer proposes an accurate score = 75 at sourceLedgerSeq = 2000
      const honestEntry = makeEntry({
        stellarAddress: stellarAddr(99),
        score: 75,
        fulfilledCount: 10,
        lateCount: 1,
        breachedCount: 0,
        sourceLedgerSeq: 2000,
      });
      await oracle.connect(HonestRelayer).proposeOptimisticUpdate(honestEntry, {
        value: relayerBond,
      });

      const matchingProof = buildCanonicalStateProof({
        contractId: REGISTRY_ID,
        stellarAddress: stellarAddr(99),
        ledgerSeq: 2010,
        scoreData: {
          score: 75,
          fulfilledCount: 10,
          lateCount: 1,
          breachedCount: 0,
          epoch: 1,
          sourceLedgerSeq: 2000,
        },
      });

      // 2. Rejects challenge when ledger header is untrusted
      await expect(
        oracle.connect(attacker).challengeOptimisticUpdate(1, matchingProof, {
          value: challengerBond,
        }),
      ).to.be.revertedWithCustomError(oracle, 'UntrustedCanonicalHeader');

      // Register the trusted header directly on PactumTrustOracle
      await oracle
        .connect(owner)
        .setTrustedLedgerHeader(matchingProof.ledgerSeq, matchingProof.ledgerHeaderHash);

      // 3. Rejects challenge with insufficient challenger bond
      await expect(
        oracle.connect(attacker).challengeOptimisticUpdate(1, matchingProof, {
          value: ethers.parseEther('0.01'),
        }),
      ).to.be.revertedWithCustomError(oracle, 'InsufficientChallengerBond');

      // 4. Rejects challenge when canonical proof matches the proposed update (no contradiction!)
      await expect(
        oracle.connect(attacker).challengeOptimisticUpdate(1, matchingProof, {
          value: challengerBond,
        }),
      ).to.be.revertedWithCustomError(oracle, 'NoContradictionProven');

      // 5. Rejects challenge with tampered Merkle sibling
      const tamperedProof = {
        ...matchingProof,
        scoreData: { ...matchingProof.scoreData, score: 10 },
      };
      await expect(
        oracle.connect(attacker).challengeOptimisticUpdate(1, tamperedProof, {
          value: challengerBond,
        }),
      ).to.be.reverted;
    });
  });
});
