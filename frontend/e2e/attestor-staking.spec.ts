import { test, expect } from '@playwright/test';

test.describe('Attestor Staking, Unbonding, M-of-N Panel & Dispute Resolution (#296)', () => {
  test('opens Attestor Staking modal from Reputation Dashboard, stakes collateral, starts 14-day unbonding, and casts dispute verdict', async ({
    page,
  }) => {
    await page.goto('/');

    const openBtn = page.getByTestId('open-attestor-staking-btn');
    await expect(openBtn).toBeVisible();
    await openBtn.click();

    const modal = page.getByTestId('attestor-staking-modal');
    await expect(modal).toBeVisible();
    await expect(page.getByTestId('attestor-staked-balance')).toContainText('500 XLM');

    // Deposit +250 XLM
    await page.getByTestId('stake-deposit-input').fill('250');
    await page.getByTestId('stake-deposit-btn').click();
    await expect(page.getByTestId('attestor-staked-balance')).toContainText('750 XLM');

    // Trigger 14-day unbonding request
    await page.getByTestId('request-unstake-btn').click();
    await expect(page.getByTestId('unbonding-countdown-label')).toContainText(
      '14d 0h 0m remaining',
    );

    // Cast dissenting vote on Commitment #108 to verify 10% slashing banner & balance update
    await page.getByTestId('vote-breached-btn-108').click();
    await expect(page.getByTestId('slashing-penalty-banner')).toContainText(
      '10% collateral slashed',
    );
    await expect(page.getByTestId('attestor-staked-balance')).toContainText('675 XLM');
  });
});
