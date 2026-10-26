/* eslint-disable */
const { expect } = require('chai');
const { ethers } = require('hardhat');
const { loadFixture, time } = require('@nomicfoundation/hardhat-network-helpers');

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

  describe('FROST / TSS threshold signature relay (#299)', function () {
    const SECP256K1_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
    const SECP256K1_Q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
    const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
    const G = { x: GX, y: GY };

    function modP(n) {
      const r = n % SECP256K1_P;
      return r < 0n ? r + SECP256K1_P : r;
    }
    function modQ(n) {
      const r = n % SECP256K1_Q;
      return r < 0n ? r + SECP256K1_Q : r;
    }
    function modInv(a, m) {
      let t = 0n,
        newT = 1n,
        r = m,
        newR = ((a % m) + m) % m;
      while (newR !== 0n) {
        const q = r / newR;
        [t, newT] = [newT, t - q * newT];
        [r, newR] = [newR, r - q * newR];
      }
      return t < 0n ? t + m : t;
    }
    function pointDouble(p) {
      if (p.inf || p.y === 0n) return { x: 0n, y: 0n, inf: true };
      const s = modP(3n * p.x * p.x * modInv(2n * p.y, SECP256K1_P));
      const x3 = modP(s * s - 2n * p.x);
      const y3 = modP(s * (p.x - x3) - p.y);
      return { x: x3, y: y3 };
    }
    function pointAdd(p1, p2) {
      if (p1.inf) return p2;
      if (p2.inf) return p1;
      if (p1.x === p2.x) {
        return modP(p1.y + p2.y) === 0n ? { x: 0n, y: 0n, inf: true } : pointDouble(p1);
      }
      const s = modP((p2.y - p1.y) * modInv(p2.x - p1.x, SECP256K1_P));
      const x3 = modP(s * s - p1.x - p2.x);
      const y3 = modP(s * (p1.x - x3) - p1.y);
      return { x: x3, y: y3 };
    }
    function pointMul(p, scalar) {
      let k = modQ(scalar);
      let res = { x: 0n, y: 0n, inf: true };
      let add = p;
      while (k > 0n) {
        if ((k & 1n) === 1n) res = pointAdd(res, add);
        add = pointDouble(add);
        k >>= 1n;
      }
      return res;
    }
    function pointToEthAddress(p) {
      const uncompressed = p.x.toString(16).padStart(64, '0') + p.y.toString(16).padStart(64, '0');
      const digest = ethers.keccak256('0x' + uncompressed);
      return ethers.getAddress('0x' + digest.slice(26));
    }
    function lagrangeCoeff(i, subset) {
      const bi = BigInt(i);
      let num = 1n,
        den = 1n;
      for (const j of subset) {
        if (j === i) continue;
        const bj = BigInt(j);
        num = modQ(num * bj);
        den = modQ(den * modQ(bj - bi));
      }
      return modQ(num * modInv(den, SECP256K1_Q));
    }

    it('verifies a 3-of-5 FROST threshold signature on-chain and applies the bridged batch', async function () {
      const { owner, other, oracle } = await loadFixture(deployFixture);

      // 5-node Feldman/Pedersen DKG (threshold t = 3, nodes 1..5)
      const nodePolys = [
        [101n, 202n, 303n],
        [404n, 505n, 606n],
        [707n, 808n, 909n],
        [111n, 222n, 333n],
        [444n, 555n, 666n],
      ];
      const evalPoly = (coeffs, x) =>
        modQ(coeffs[0] + modQ(coeffs[1] * x) + modQ(coeffs[2] * modQ(x * x)));

      const secretShares = new Map();
      for (let j = 1; j <= 5; j++) {
        let s = 0n;
        for (let i = 0; i < 5; i++) {
          s = modQ(s + evalPoly(nodePolys[i], BigInt(j)));
        }
        secretShares.set(j, s);
      }

      let groupSecret = 0n;
      for (let i = 0; i < 5; i++) {
        groupSecret = modQ(groupSecret + nodePolys[i][0]);
      }
      const groupPub = pointMul(G, groupSecret);
      const groupPubKeyX = '0x' + groupPub.x.toString(16).padStart(64, '0');
      const groupPubKeyParity = (groupPub.y & 1n) === 0n ? 27 : 28;

      await expect(oracle.connect(owner).setTssGroupPublicKey(groupPubKeyX, groupPubKeyParity))
        .to.emit(oracle, 'TssGroupPublicKeyUpdated')
        .withArgs(groupPubKeyX, groupPubKeyParity);

      const batch = await makeBatch({
        batchNonce: 1,
        entries: [makeEntry({ stellarAddress: stellarAddr(9), score: 850, sourceLedgerSeq: 77 })],
      });
      const payload = encodeBatch(batch);
      const messageHash = ethers.solidityPackedKeccak256(
        ['bytes32', 'uint64', 'bytes32'],
        [REGISTRY_ID, batch.batchNonce, ethers.keccak256(payload)],
      );

      // 3-of-5 signing with nodes [1, 3, 4] (nodes 2 and 5 offline)
      const signers = [1, 3, 4];
      const nonces = {
        1: { d: 12345n, e: 67890n, rho: 11n },
        3: { d: 23456n, e: 78901n, rho: 13n },
        4: { d: 34567n, e: 89012n, rho: 17n },
      };

      let groupR = { x: 0n, y: 0n, inf: true };
      for (const id of signers) {
        const kI = modQ(nonces[id].d + modQ(nonces[id].e * nonces[id].rho));
        groupR = pointAdd(groupR, pointMul(G, kI));
      }
      const commitmentAddress = pointToEthAddress(groupR);

      const challengeDigest = ethers.solidityPackedKeccak256(
        ['address', 'uint8', 'bytes32', 'bytes32'],
        [commitmentAddress, groupPubKeyParity, groupPubKeyX, messageHash],
      );
      const c = modQ(BigInt(challengeDigest));

      let zAgg = 0n;
      for (const id of signers) {
        const lam = lagrangeCoeff(id, signers);
        const kI = modQ(nonces[id].d + modQ(nonces[id].e * nonces[id].rho));
        const zI = modQ(kI + modQ(modQ(lam * secretShares.get(id)) * c));
        zAgg = modQ(zAgg + zI);
      }

      expect(await oracle.verifyThresholdSignature(messageHash, commitmentAddress, zAgg)).to.equal(
        true,
      );

      await expect(oracle.connect(other).receiveThresholdBatch(payload, commitmentAddress, zAgg))
        .to.emit(oracle, 'ThresholdBatchRelayed')
        .withArgs(REGISTRY_ID, 1n, commitmentAddress, zAgg);

      const stored = await oracle.getTrustScore(stellarAddr(9));
      expect(stored.score).to.equal(850n);
      expect(stored.sourceLedgerSeq).to.equal(77n);
    });

    it('reverts with InvalidThresholdSignature when signature share or payload is tampered', async function () {
      const { owner, oracle } = await loadFixture(deployFixture);
      const pub = pointMul(G, 999n);
      const pubX = '0x' + pub.x.toString(16).padStart(64, '0');
      const parity = (pub.y & 1n) === 0n ? 27 : 28;
      await oracle.connect(owner).setTssGroupPublicKey(pubX, parity);

      const batch = await makeBatch({ batchNonce: 1 });
      const payload = encodeBatch(batch);
      const fakeR = pointToEthAddress(pointMul(G, 555n));

      await expect(
        oracle.receiveThresholdBatch(payload, fakeR, 123456n),
      ).to.be.revertedWithCustomError(oracle, 'InvalidThresholdSignature');
    });
  });
});
