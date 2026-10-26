import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  Account,
  Contract,
  Keypair,
  Networks,
  TransactionBuilder,
  xdr,
} from '@stellar/stellar-sdk';
import { decodePartialTransactionEnvelope } from '../lib/xdrDecode';
import {
  appendSignatureToEnvelope,
  buildMultiSigShareUrl,
  decodeShareableMultiSigPayload,
  encodeShareableMultiSigPayload,
  submitMultiSigEnvelopeIfReady,
} from '../lib/sorobanTxHelpers';
import { createMultiSigCoordinator } from './useMultiSig';
import { MultiSigCoordinatorModal } from '../components/MultiSigCoordinatorModal';

const mockSignTransaction = vi.fn();
const mockSendTransaction = vi.fn();
const mockGetTransaction = vi.fn();

vi.mock('@stellar/freighter-api', () => ({
  signTransaction: (...args: unknown[]) => mockSignTransaction(...args),
}));

vi.mock('../lib/sorobanRpcPool', () => ({
  SorobanRpcPool: class {
    sendTransaction(...args: unknown[]) {
      return mockSendTransaction(...args);
    }
    getTransaction(...args: unknown[]) {
      return mockGetTransaction(...args);
    }
  },
  resolveSorobanRpcUrls: () => ['https://soroban-testnet.stellar.org'],
}));

function buildSampleSorobanTx(sourcePublicKey: string) {
  const sourceAccount = new Account(sourcePublicKey, '100');
  const contract = new Contract('CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC');
  const op = contract.call(
    'resolve_dispute',
    xdr.ScVal.scvU64(xdr.Uint64.fromString('42')),
    xdr.ScVal.scvSymbol('success'),
  );
  return new TransactionBuilder(sourceAccount, {
    fee: '1000',
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(op)
    .setTimeout(300)
    .build();
}

describe('Multi-Signature Partial XDR Coordinator (#300)', () => {
  const signer1 = Keypair.random();
  const signer2 = Keypair.random();
  const signer3 = Keypair.random();

  const knownSigners = [
    { key: signer1.publicKey(), weight: 10, label: 'Treasury Signer A' },
    { key: signer2.publicKey(), weight: 10, label: 'Treasury Signer B' },
    { key: signer3.publicKey(), weight: 10, label: 'Treasury Signer C' },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    mockSendTransaction.mockResolvedValue({
      status: 'PENDING',
      hash: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
    });
    mockGetTransaction.mockResolvedValue({
      status: 'SUCCESS',
    });
  });

  it('decodes a partially-signed XDR envelope, verifies signer weights, and decodes Soroban contract arguments', () => {
    const tx = buildSampleSorobanTx(signer1.publicKey());
    tx.sign(signer1);

    const decoded = decodePartialTransactionEnvelope(tx.toXDR(), {
      networkPassphrase: Networks.TESTNET,
      knownSigners,
      requiredThreshold: 20,
    });

    expect(decoded.collectedWeight).toBe(10);
    expect(decoded.requiredThreshold).toBe(20);
    expect(decoded.remainingWeight).toBe(10);
    expect(decoded.thresholdMet).toBe(false);
    expect(decoded.thresholdLabel).toBe('Weight 10/20 reached');

    // First signer is marked signed, second and third are pending
    expect(decoded.signers[0].signed).toBe(true);
    expect(decoded.signers[1].signed).toBe(false);
    expect(decoded.signers[2].signed).toBe(false);

    // Operation parameters decoded accurately
    expect(decoded.operations).toHaveLength(1);
    expect(decoded.operations[0].functionName).toBe('resolve_dispute');
    expect(decoded.operations[0].args).toEqual({
      commitmentId: '42',
      outcome: 'success',
    });
  });

  it('encodes and decodes shareable multi-sig coordination URLs and merges co-signer signatures without duplication', async () => {
    const tx1 = buildSampleSorobanTx(signer1.publicKey());
    tx1.sign(signer1);

    const shareUrl = buildMultiSigShareUrl(
      {
        version: 1,
        envelopeXdr: tx1.toXDR(),
        networkPassphrase: Networks.TESTNET,
        requiredThreshold: 20,
        knownSigners,
        description: 'DAO Treasury High-Value Settlement #42',
        createdAt: 1710000000000,
      },
      'https://pactum.app/commitments',
    );

    expect(shareUrl).toContain('https://pactum.app/commitments?multisig=msig1.');
    const restoredBundle = decodeShareableMultiSigPayload(shareUrl);
    expect(restoredBundle.description).toBe('DAO Treasury High-Value Settlement #42');
    expect(restoredBundle.requiredThreshold).toBe(20);

    // Co-signer 2 signs a copy of the envelope
    const tx2 = TransactionBuilder.fromXDR(restoredBundle.envelopeXdr, Networks.TESTNET);
    tx2.sign(signer2);

    // Merge signatures and verify deduplication
    const mergedXdr = appendSignatureToEnvelope(
      restoredBundle.envelopeXdr,
      tx2.toXDR(),
      Networks.TESTNET,
    );
    const mergedTwiceXdr = appendSignatureToEnvelope(mergedXdr, tx2.toXDR(), Networks.TESTNET);

    const decodedAfterSecond = decodePartialTransactionEnvelope(mergedTwiceXdr, {
      networkPassphrase: Networks.TESTNET,
      knownSigners,
      requiredThreshold: 20,
    });

    expect(decodedAfterSecond.collectedSignatures).toHaveLength(2);
    expect(decodedAfterSecond.collectedWeight).toBe(20);
    expect(decodedAfterSecond.thresholdMet).toBe(true);
    expect(decodedAfterSecond.thresholdLabel).toBe('Weight 20/20 reached');

    // Submit once threshold is met
    const submission = await submitMultiSigEnvelopeIfReady(mergedTwiceXdr, {
      knownSigners,
      requiredThreshold: 20,
      networkPassphrase: Networks.TESTNET,
      pollConfirmation: false,
    });

    expect(submission.submitted).toBe(true);
    expect(submission.hash).toBe(
      'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
    );
    expect(mockSendTransaction).toHaveBeenCalledTimes(1);
  });

  it('coordinates 2-of-3 signing and auto-submits as soon as threshold weight is reached', async () => {
    const unsignedTx = buildSampleSorobanTx(signer1.publicKey());

    const coordinator = createMultiSigCoordinator({
      autoSubmit: true,
      pollConfirmation: false,
      baseUrl: 'https://pactum.app/dashboard',
    });

    coordinator.initializeEnvelope({
      envelopeXdr: unsignedTx.toXDR(),
      knownSigners,
      requiredThreshold: 20,
      networkPassphrase: Networks.TESTNET,
      description: 'Escrow Release #42',
    });

    expect(coordinator.decoded?.thresholdLabel).toBe('Weight 0/20 reached');

    // Signer 1 signs via Freighter wallet
    const txSignedBy1 = TransactionBuilder.fromXDR(unsignedTx.toXDR(), Networks.TESTNET);
    txSignedBy1.sign(signer1);
    mockSignTransaction.mockResolvedValueOnce({ signedTxXdr: txSignedBy1.toXDR() });

    await coordinator.signWithWallet(signer1.publicKey(), 'freighter');

    expect(coordinator.decoded?.thresholdLabel).toBe('Weight 10/20 reached');
    expect(coordinator.submittedHash).toBeNull();

    // Signer 2 signs externally and appends signature -> triggers auto-submission
    const txSignedBy2 = TransactionBuilder.fromXDR(
      coordinator.bundle!.envelopeXdr,
      Networks.TESTNET,
    );
    txSignedBy2.sign(signer2);

    await coordinator.appendExternalSignature(txSignedBy2.toXDR());

    expect(coordinator.decoded?.thresholdLabel).toBe('Weight 20/20 reached');
    expect(coordinator.decoded?.thresholdMet).toBe(true);
    expect(coordinator.submittedHash).toBe(
      'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
    );
    expect(coordinator.exportXdrDownload()?.filename).toMatch(
      /^pactum-multisig-[0-9a-f]{10}\.xdr$/,
    );
  });

  it('renders MultiSigCoordinatorModal with signer statuses, decoded operations, and shareable link details', () => {
    const tx1 = buildSampleSorobanTx(signer1.publicKey());
    tx1.sign(signer1);

    const token = encodeShareableMultiSigPayload({
      version: 1,
      envelopeXdr: tx1.toXDR(),
      networkPassphrase: Networks.TESTNET,
      requiredThreshold: 20,
      knownSigners,
      description: 'Multi-Sig Resolution Proposal',
      createdAt: 1710000000000,
    });

    const coordinator = createMultiSigCoordinator({
      autoSubmit: true,
      pollConfirmation: false,
      baseUrl: 'https://pactum.app/commitments',
    });
    coordinator.importFromSharePayload(token);

    const html = renderToStaticMarkup(
      <MultiSigCoordinatorModal
        isOpen={true}
        onClose={() => {}}
        multiSig={coordinator}
        activeWalletAddress={signer2.publicKey()}
        activeWalletProvider="freighter"
      />,
    );

    expect(html).toContain('Weight 10/20 reached');
    expect(html).toContain('10 more weight required');
    expect(html).toContain('Invoke resolve_dispute(commitmentId=42, outcome=success)');
    expect(html).toContain('Treasury Signer A');
    expect(html).toContain('Treasury Signer B');
    expect(html).toContain('stellar+multisig:msig1.');
  });
});
