import { Router, Request, Response, NextFunction } from 'express';
import { z, ZodError } from 'zod';
import { ReputationCache } from '../cache/reputationCache';
import { CertificateService } from '../services/CertificateService';
import { queryTimescale } from '../db/timescale';
import { SorobanClient } from '../soroban/client';
import {
  BulletproofRangeError,
  BulletproofRangeProof,
  BulletproofVerificationError,
  deserializeBulletproof,
  PEDERSEN_P,
  verifyBulletproofBatchStrict,
  verifyBulletproofStrict,
  verifyRangeProof,
} from '../crypto/bulletproof';

const STELLAR_ADDRESS = /^G[A-Z2-7]{55}$/;
const DEFAULT_HISTORY_DAYS = 30;
const MAX_HISTORY_DAYS = 365;

/**
 * Middleware that verifies Bulletproof range proofs (single or batch) on
 * encrypted private feedback submission routes before persisting outcomes.
 */
export const verifyFeedbackRangeProofMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  try {
    const body = req.body ?? {};
    const pkN = body.pkN ? BigInt('0x' + String(body.pkN).replace(/^0x/, '')) : PEDERSEN_P;

    if (Array.isArray(body.bulletproofs) && body.bulletproofs.length > 0) {
      const decoded: BulletproofRangeProof[] = body.bulletproofs.map((item: unknown) => {
        if (typeof item === 'string') {
          return deserializeBulletproof(Buffer.from(item.replace(/^0x/, ''), 'hex'));
        }
        return item as BulletproofRangeProof;
      });
      verifyBulletproofBatchStrict(decoded, pkN);
      next();
      return;
    }

    if (body.bulletproof !== undefined) {
      const proof: BulletproofRangeProof =
        typeof body.bulletproof === 'string'
          ? deserializeBulletproof(Buffer.from(body.bulletproof.replace(/^0x/, ''), 'hex'))
          : (body.bulletproof as BulletproofRangeProof);
      verifyBulletproofStrict(proof, pkN);
      next();
      return;
    }

    if (body.proof !== undefined) {
      const p = body.proof;
      const rangeProof = {
        commitment: BigInt('0x' + String(p.commitment).replace(/^0x/, '')),
        witnessA: BigInt('0x' + String(p.witnessA).replace(/^0x/, '')),
        witnessB: BigInt('0x' + String(p.witnessB).replace(/^0x/, '')),
      };
      if (!verifyRangeProof(rangeProof, pkN)) {
        throw new BulletproofVerificationError(
          'TAMPERED_WITNESS',
          'Schnorr range proof verification failed',
        );
      }
      next();
      return;
    }

    res.status(400).json({
      error: 'Bad Request',
      code: 'MISSING_RANGE_PROOF',
      message: 'A valid range proof (bulletproof, bulletproofs, or proof) is required',
    });
  } catch (error) {
    if (error instanceof BulletproofRangeError || error instanceof BulletproofVerificationError) {
      res.status(400).json({
        error: 'Range Proof Verification Failed',
        code: error.code,
        message: error.message,
      });
      return;
    }
    res.status(400).json({
      error: 'Invalid Range Proof Payload',
      message: error instanceof Error ? error.message : String(error),
    });
  }
};

// Zod schema for validating the export certificate request
const exportCertificateSchema = z.object({
  did: z.string().min(1, 'DID is required'),
  trustScore: z.number().min(0).max(100, 'Trust score must be between 0 and 100'),
});

const validateExportRequest = (req: Request, res: Response, next: NextFunction): void => {
  try {
    const validatedData = exportCertificateSchema.parse(req.body);
    req.body = validatedData;
    next();
  } catch (error) {
    if (error instanceof ZodError) {
      const formattedErrors = error.errors.map((err) => ({
        field: err.path.join('.'),
        message: err.message,
      }));

      res.status(400).json({
        error: 'Bad Request',
        details: formattedErrors,
      });
      return;
    }
    next(error);
  }
};

export function createReputationRouter(
  cache: ReputationCache,
  sorobanClient?: SorobanClient,
): Router {
  const router = Router();

  // POST /feedback - Verifies single or batch Bulletproof range proofs for encrypted feedback
  router.post(
    '/feedback',
    verifyFeedbackRangeProofMiddleware,
    async (req: Request, res: Response) => {
      const count = Array.isArray(req.body?.bulletproofs) ? req.body.bulletproofs.length : 1;
      res.status(200).json({
        verified: true,
        verifiedCount: count,
        message: 'Encrypted feedback range proof verified',
      });
    },
  );

  // POST /export/certificate - Exports a Reputation Certificate (VC)
  router.post(
    '/export/certificate',
    validateExportRequest,
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { did, trustScore } = req.body;

        // Generate the Verifiable Credential using our KMS-backed service
        const token = await CertificateService.generateReputationCertificate(did, trustScore);

        res.status(200).json({
          message: 'Certificate generated successfully',
          certificate: token,
        });
      } catch (error) {
        console.error('Error generating certificate:', error);
        res.status(500).json({
          error: 'Internal Server Error',
        });
      }
    },
  );

  /**
   * GET /reputation/:address/trust-score
   *
   * Returns the on-chain Soroban trust score for a Stellar address.
   * Handles the three distinct states:
   *
   * 200 { score: number }
   *     The entry is live and readable.  Score is 0–100 (50 = neutral baseline).
   *
   * 503 { archived: true, address: string, message: string, restore_hint: string }
   *     The trust-history entry for this address has been archived by Soroban state
   *     expiration.  The indexer's TTL monitor will restore it proactively, or the
   *     caller can submit a RestoreFootprint + restore_reputation(address) transaction.
   *
   * 404 { error: "Soroban client not configured" }
   *     The backend was started without SOROBAN_RPC_URL / ORACLE_PRIVATE_KEY / etc.
   *     (development mode with no live Soroban connection).
   *
   * 400 { error: "Invalid Stellar account address" }
   *     The address parameter is not a valid Stellar G… address.
   *
   * 500 { error: string }
   *     Unexpected error querying the Soroban RPC.
   */
  router.get('/:address/trust-score', async (req: Request, res: Response) => {
    const rawAddress = req.params.address;
    const address = (Array.isArray(rawAddress) ? rawAddress[0] : rawAddress).toUpperCase();

    if (!STELLAR_ADDRESS.test(address)) {
      res.status(400).json({ error: 'Invalid Stellar account address' });
      return;
    }

    if (!sorobanClient) {
      res.status(404).json({
        error: 'Soroban client not configured',
        hint: 'Set SOROBAN_RPC_URL, SOROBAN_CONTRACT_ID, ORACLE_PRIVATE_KEY, and SOROBAN_NETWORK_PASSPHRASE to enable on-chain trust score queries.',
      });
      return;
    }

    try {
      const scoreResult = await sorobanClient.getTrustScore(address);

      // null means the entry is archived (Option<u32> returned None from the contract).
      if (scoreResult === null) {
        res.status(503).json({
          archived: true,
          address,
          message:
            'The trust-score entry for this address has been archived by Soroban state ' +
            'expiration.  The TTL monitor will restore it automatically on its next run.  ' +
            'To restore immediately, submit a RestoreFootprint + restore_reputation transaction.',
          restore_hint:
            'Wait for the next TTL monitor cycle, or submit a RestoreFootprint + restore_reputation(address) transaction on-chain.',
        });
        return;
      }

      res.status(200).json({ address, score: scoreResult });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[reputation] Failed to fetch trust score for ${address}:`, message);
      res.status(500).json({ error: 'Failed to query trust score', details: message });
    }
  });

  router.get('/:address', async (req: Request, res: Response) => {
    const rawAddress = req.params.address;
    const address = (Array.isArray(rawAddress) ? rawAddress[0] : rawAddress).toUpperCase();
    if (!STELLAR_ADDRESS.test(address)) {
      res.status(400).json({ error: 'Invalid Stellar account address' });
      return;
    }

    try {
      const result = await cache.get(address);
      res.setHeader('X-Cache', result.hit ? 'HIT' : 'MISS');
      if (!result.value) {
        res.status(404).json({ error: 'Reputation not found', address });
        return;
      }
      res.status(200).json(result.value);
    } catch (error) {
      console.error('Failed to fetch reputation', error);
      res.status(503).json({ error: 'Reputation service unavailable' });
    }
  });

  // GET /:address/history - Daily reputation snapshots for an address
  router.get('/:address/history', async (req: Request, res: Response) => {
    const { address } = req.params;
    const requested = parseInt(String(req.query.days ?? DEFAULT_HISTORY_DAYS), 10);
    const days = Number.isNaN(requested)
      ? DEFAULT_HISTORY_DAYS
      : Math.min(Math.max(requested, 1), MAX_HISTORY_DAYS);

    try {
      // Snapshots are only written on days an address was active, so each day in
      // the window carries the most recent snapshot at or before it forward.
      const result = await queryTimescale(
        `SELECT
           to_char(bucket, 'YYYY-MM-DD') AS date,
           COALESCE(fulfilled_count, 0) AS fulfilled,
           COALESCE(late_count, 0) AS late,
           COALESCE(breached_count, 0) AS breached
         FROM reputation_snapshots_daily
         WHERE address = $2
           AND bucket >= CURRENT_DATE - $1::interval
         ORDER BY bucket ASC`,
        [`${days - 1} days`, address],
      );
      res.json(result.rows);
    } catch (error) {
      console.error('Failed to fetch reputation history', error);
      res.status(500).json({ error: 'Database query failed' });
    }
  });

  return router;
}
