import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { Account, Keypair, nativeToScVal } from '@stellar/stellar-sdk';
import {
  SLASH_PERCENT,
  UNBONDING_PERIOD_SECONDS,
  calculateSlashedBalance,
  fetchAttestorStakeInfo,
  formatUnbondingCountdown,
  submitCastDisputeVote,
  submitCreateCommitment,
  submitFinalizeUnstake,
  submitRequestUnstake,
  submitStakeAttestor,
} from '../lib/soroban';
import { AttestorStakingModal } from './AttestorStakingModal';

const mockSignTransaction = vi.fn();
const mockSimulateTransaction = vi.fn();
const mockPrepareTransaction = vi.fn();
const mockSendTransaction = vi.fn();
const mockGetTransaction = vi.fn();
const mockGetAccount = vi.fn();

vi.mock('@stellar/freighter-api', () => ({
  signTransaction: (...args: unknown[]) => mockSignTransaction(...args),
}));

vi.mock('../lib/sorobanRpcPool', () => ({
  SorobanRpcPool: class {
    simulateTransaction(...args: unknown[]) {
      return mockSimulateTransaction(...args);
    }
    prepareTransaction(...args: unknown[]) {
      return mockPrepareTransaction(...args);
    }
    sendTransaction(...args: unknown[]) {
      return mockSendTransaction(...args);
    }
    getTransaction(...args: unknown[]) {
      return mockGetTransaction(...args);
    }
    getAccount(...args: unknown[]) {
      return mockGetAccount(...args);
    }
  },
}));

describe('Attestor Staking, Unbonding, Dispute Resolution & Slashing (#296)', () => {
  const attestorKp = Keypair.random();
  const counterpartyKp = Keypair.random();
  const panelMember2 = Keypair.random();
  const panelMember3 = Keypair.random();

  beforeEach(() => {
    vi.clearAllMocks();
    mockGetAccount.mockImplementation((addr: string) => Promise.resolve(new Account(addr, '100')));
    mockPrepareTransaction.mockImplementation((tx: unknown) => Promise.resolve(tx));
    mockSignTransaction.mockImplementation((xdrStr: string) =>
      Promise.resolve({ signedTxXdr: xdrStr }),
    );
    mockSendTransaction.mockResolvedValue({
      status: 'PENDING',
      hash: 'f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f00',
    });
    mockGetTransaction.mockResolvedValue({
      status: 'SUCCESS',
    });
  });

  it('computes 14-day unbonding countdowns and withdrawal eligibility accurately', () => {
    const now = 1_710_000_000;
    const noneCountdown = formatUnbondingCountdown(null, now);
    expect(noneCountdown.canFinalize).toBe(false);
    expect(noneCountdown.label).toBe('No active unbonding request');

    const freshCountdown = formatUnbondingCountdown(now + UNBONDING_PERIOD_SECONDS, now);
    expect(freshCountdown.canFinalize).toBe(false);
    expect(freshCountdown.remainingSeconds).toBe(1_209_600);
    expect(freshCountdown.label).toBe('14d 0h 0m remaining');

    const halfwayCountdown = formatUnbondingCountdown(now + 7 * 86_400 + 3_600, now);
    expect(halfwayCountdown.canFinalize).toBe(false);
    expect(halfwayCountdown.label).toBe('7d 1h 0m remaining');
    expect(halfwayCountdown.progressPercent).toBeGreaterThanOrEqual(49);

    const elapsedCountdown = formatUnbondingCountdown(now - 10, now);
    expect(elapsedCountdown.canFinalize).toBe(true);
    expect(elapsedCountdown.progressPercent).toBe(100);
    expect(elapsedCountdown.label).toBe('Unbonding complete — Ready to withdraw');
  });

  it('computes 10% dissent slashing penalty and remaining stake balance accurately', () => {
    const initialStake = 500_0000000n; // 500 XLM in stroops
    const { slashedCut, remainingStake } = calculateSlashedBalance(initialStake, SLASH_PERCENT);
    expect(slashedCut).toBe(50_0000000n); // 50 XLM slashed
    expect(remainingStake).toBe(450_0000000n); // 450 XLM remaining
  });

  it('queries get_stake_info and executes stake_attestor, request_unstake, finalize_unstake, and cast_dispute_vote', async () => {
    const now = 1_710_000_000;
    mockSimulateTransaction.mockResolvedValueOnce({
      result: {
        retval: nativeToScVal({
          staked: 750_0000000n,
          unbonding_until: now + 86_400 * 3,
          locked: false,
        }),
      },
    });

    const info = await fetchAttestorStakeInfo(attestorKp.publicKey(), { nowSeconds: now });
    expect(info.staked).toBe(750_0000000n);
    expect(info.locked).toBe(false);
    expect(info.canFinalizeUnstake).toBe(false);
    expect(info.remainingUnbondingSeconds).toBe(86_400 * 3);

    const stakeRes = await submitStakeAttestor({
      attestorAddress: attestorKp.publicKey(),
      amountStroops: 250_0000000n,
    });
    expect(stakeRes.status).toBe('SUCCESS');

    const unstakeRes = await submitRequestUnstake({
      attestorAddress: attestorKp.publicKey(),
    });
    expect(unstakeRes.status).toBe('SUCCESS');
    expect(unstakeRes.unbondingUntil).toBeGreaterThan(Math.floor(Date.now() / 1000));

    const finalizeRes = await submitFinalizeUnstake({
      attestorAddress: attestorKp.publicKey(),
    });
    expect(finalizeRes.status).toBe('SUCCESS');

    const voteRes = await submitCastDisputeVote({
      attestorAddress: attestorKp.publicKey(),
      commitmentId: 108,
      outcome: 'Fulfilled',
    });
    expect(voteRes.status).toBe('SUCCESS');
    expect(mockSendTransaction).toHaveBeenCalledTimes(4);
  });

  it('encodes M-of-N attestor panel and quorum threshold in submitCreateCommitment and validates threshold bounds', async () => {
    const panel = [attestorKp.publicKey(), panelMember2.publicKey(), panelMember3.publicKey()];

    // Threshold exceeding panel size must throw
    await expect(
      submitCreateCommitment({
        issuerAddress: attestorKp.publicKey(),
        counterpartyAddress: counterpartyKp.publicKey(),
        termsHashHex: 'a'.repeat(64),
        dueAtSeconds: Math.floor(Date.now() / 1000) + 86_400,
        attestors: panel,
        voteThreshold: 4,
      }),
    ).rejects.toThrow('Vote threshold (4) cannot exceed attestor panel size (3)');

    // Valid 2-of-3 panel succeeds
    mockSimulateTransaction.mockResolvedValueOnce({
      result: {
        retval: nativeToScVal(attestorKp.publicKey(), { type: 'address' }),
      },
    });
    mockPrepareTransaction.mockImplementationOnce(async () => {
      const tx = new (await import('@stellar/stellar-sdk')).TransactionBuilder(
        new Account(attestorKp.publicKey(), '100'),
        {
          fee: '1000',
          networkPassphrase: (await import('@stellar/stellar-sdk')).Networks.TESTNET,
        },
      )
        .addOperation(
          (await import('@stellar/stellar-sdk')).Operation.manageData({
            name: 'test',
            value: '1',
          }),
        )
        .setTimeout(30)
        .build();
      return tx;
    });

    const created = await submitCreateCommitment({
      issuerAddress: attestorKp.publicKey(),
      counterpartyAddress: counterpartyKp.publicKey(),
      termsHashHex: 'b'.repeat(64),
      dueAtSeconds: Math.floor(Date.now() / 1000) + 86_400,
      attestors: panel,
      voteThreshold: 2,
    });
    expect(created.status).toBe('SUCCESS');
  });

  it('renders AttestorStakingModal with staked balance, 14-day unbonding countdown, slashing exposure, and dispute voting panel', () => {
    const now = 1_710_000_000;
    const html = renderToStaticMarkup(
      <AttestorStakingModal
        isOpen={true}
        onClose={() => {}}
        attestorAddress={attestorKp.publicKey()}
        nowSeconds={now}
        initialStakeInfo={{
          attestor: attestorKp.publicKey(),
          staked: 500_0000000n,
          unbondingUntil: now + UNBONDING_PERIOD_SECONDS,
          locked: true,
          canFinalizeUnstake: false,
          remainingUnbondingSeconds: UNBONDING_PERIOD_SECONDS,
        }}
      />,
    );

    expect(html).toContain('500 XLM');
    expect(html).toContain('Locked in Active Dispute Panel');
    expect(html).toContain('-50 XLM');
    expect(html).toContain('Post-slash balance: 450 XLM');
    expect(html).toContain('14d 0h 0m remaining');
    expect(html).toContain('Commitment #108');
    expect(html).toContain('Quorum: 1/2 Votes (Panel of 3)');
  });
});
