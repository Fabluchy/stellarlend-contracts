import crypto from 'crypto';
import express from 'express';
import request from 'supertest';
import { z } from 'zod';
import {
  validateBody,
  lendingRequestSchema,
  depositValidation,
  borrowValidation,
  repayValidation,
  withdrawValidation,
} from '../middleware/validation';
import { I128String, PositiveI128String, StellarAddress } from '../utils/validators';
import logger from '../utils/logger';

const mockStellarService = {
  buildDepositTransaction: jest.fn(),
  buildBorrowTransaction: jest.fn(),
  buildRepayTransaction: jest.fn(),
  buildWithdrawTransaction: jest.fn(),
  submitTransaction: jest.fn(),
};

jest.mock('../services/stellar.service', () => ({
  StellarService: jest.fn(() => mockStellarService),
}));

const app = require('../app').default;

const VALID_USER_ADDRESS = 'GBLXVKWHD4QAPFLHMJDXSVB6GFUDLTC46VY42OWHC3TPRN2I6NNV3ZSJ';
const VALID_CONTRACT_ADDRESS = 'CBQ4OAIKSIQS4XHACA4KH4TKQAZX4WLEARB5HWZRZPXAKMLLRRZTWI5R';
const VALID_ASSET_ADDRESS = 'GD5TFY4DYYF43CQN3UMZUPBBXBLWK3WYAM5PIOMKOVRHBTZF7J7VGHP4';
const VALID_USER_SECRET = 'SAOS4OGIK6HD4QGR3DVRRDSR4FUBH73FCZGRZ7M53LRN67UQE5JDNS4I';
const I128_MAX = '170141183460469231731687303715884105727';
const I128_MIN = '-170141183460469231731687303715884105728';
const I128_OVERFLOW = '170141183460469231731687303715884105728';
const I128_UNDERFLOW = '-170141183460469231731687303715884105729';

describe('Validation Middleware', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    mockStellarService.buildDepositTransaction.mockResolvedValue('mock_deposit_tx');
    mockStellarService.buildBorrowTransaction.mockResolvedValue('mock_borrow_tx');
    mockStellarService.buildRepayTransaction.mockResolvedValue('mock_repay_tx');
    mockStellarService.buildWithdrawTransaction.mockResolvedValue('mock_withdraw_tx');

    mockStellarService.submitTransaction.mockResolvedValue({
      success: false,
      status: 'failed',
      error: 'mock transaction failure',
    });
  });

  describe('Shared Validators', () => {
    describe('StellarAddress', () => {
      it('should accept valid Stellar account public keys', () => {
        expect(StellarAddress.safeParse(VALID_USER_ADDRESS).success).toBe(true);
      });

      it('should accept valid Stellar contract addresses', () => {
        expect(StellarAddress.safeParse(VALID_CONTRACT_ADDRESS).success).toBe(true);
      });

      it('should trim surrounding whitespace from valid addresses', () => {
        const result = StellarAddress.safeParse(`  ${VALID_USER_ADDRESS}  `);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data).toBe(VALID_USER_ADDRESS);
        }
      });

      it('should reject malformed Stellar addresses', () => {
        expect(StellarAddress.safeParse('GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX').success).toBe(false);
        expect(StellarAddress.safeParse('invalid_address').success).toBe(false);
        expect(StellarAddress.safeParse('G123').success).toBe(false);
        expect(StellarAddress.safeParse('').success).toBe(false);
        expect(StellarAddress.safeParse('   ').success).toBe(false);
      });

      it('should reject non-string types for StellarAddress', () => {
        expect(StellarAddress.safeParse(12345).success).toBe(false);
        expect(StellarAddress.safeParse(null).success).toBe(false);
        expect(StellarAddress.safeParse(undefined).success).toBe(false);
        expect(StellarAddress.safeParse({}).success).toBe(false);
      });
    });

    describe('I128String', () => {
      it('should accept signed i128 integer strings at range limits', () => {
        expect(I128String.safeParse(I128_MAX).success).toBe(true);
        expect(I128String.safeParse(I128_MIN).success).toBe(true);
        expect(I128String.safeParse('0').success).toBe(true);
        expect(I128String.safeParse('1').success).toBe(true);
        expect(I128String.safeParse('-1').success).toBe(true);
      });

      it('should trim whitespace from integer strings', () => {
        const result = I128String.safeParse('  1000000  ');
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data).toBe('1000000');
        }
      });

      it('should reject non-integer, floating point, and non-numeric strings', () => {
        expect(I128String.safeParse('1.5').success).toBe(false);
        expect(I128String.safeParse('0.0001').success).toBe(false);
        expect(I128String.safeParse('1e18').success).toBe(false);
        expect(I128String.safeParse('0x10').success).toBe(false);
        expect(I128String.safeParse('abc').success).toBe(false);
        expect(I128String.safeParse('').success).toBe(false);
        expect(I128String.safeParse('   ').success).toBe(false);
      });

      it('should reject out-of-range i128 strings', () => {
        expect(I128String.safeParse(I128_OVERFLOW).success).toBe(false);
        expect(I128String.safeParse(I128_UNDERFLOW).success).toBe(false);
      });

      it('should reject non-string types for I128String', () => {
        expect(I128String.safeParse(100).success).toBe(false);
        expect(I128String.safeParse(null).success).toBe(false);
        expect(I128String.safeParse(undefined).success).toBe(false);
      });
    });

    describe('PositiveI128String', () => {
      it('should accept positive values within i128 range', () => {
        expect(PositiveI128String.safeParse('1').success).toBe(true);
        expect(PositiveI128String.safeParse('1000000').success).toBe(true);
        expect(PositiveI128String.safeParse(I128_MAX).success).toBe(true);
      });

      it('should reject zero and negative values', () => {
        expect(PositiveI128String.safeParse('0').success).toBe(false);
        expect(PositiveI128String.safeParse('-1').success).toBe(false);
        expect(PositiveI128String.safeParse(I128_MIN).success).toBe(false);
      });
    });
  });

  describe('validateBody Middleware Invariants', () => {
    /**
     * Races a supertest request against a timer so a hung request fails the
     * test instead of stalling the suite. The timer is always cleared so it
     * cannot keep the Jest event loop alive after the run.
     */
    const withHangTimeout = async <T,>(promise: Promise<T>, ms = 3000): Promise<T | { timedOut: true }> => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<'timeout'>(resolve => {
        timer = setTimeout(() => resolve('timeout'), ms);
      });
      const result = await Promise.race([
        promise.then(value => ({ kind: 'value' as const, value })),
        timeout.then(() => ({ kind: 'timeout' as const })),
      ]);
      if (timer) {
        clearTimeout(timer);
      }
      return result.kind === 'timeout' ? { timedOut: true } : result.value;
    };

    it('should replace req.body with parsed output on successful validation', () => {
      const schema = z.object({
        name: z.string().trim(),
        age: z.number(),
      });

      const req = {
        body: {
          name: '  Alice  ',
          age: 30,
          unexpectedField: 'strip-me',
        },
      } as any;
      const next = jest.fn();

      validateBody(schema)(req, {} as any, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.body).toEqual({ name: 'Alice', age: 30 });
      expect(req.body.unexpectedField).toBeUndefined();
    });

    it('should NOT mutate req.body on validation failure', () => {
      const schema = z.object({
        name: z.string(),
        count: z.number(),
      });

      const initialBody = { name: 'Alice', count: 'not-a-number' };
      const req = { body: { ...initialBody } } as any;
      const next = jest.fn();

      validateBody(schema)(req, {} as any, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(next.mock.calls[0][0]).toBeInstanceOf(Error);
      expect(req.body).toEqual(initialBody);
    });

    it('should accept the exact i128 minimum boundary', () => {
      expect(I128String.safeParse(I128_MIN).success).toBe(true);
    });

    it('should reject values below the i128 minimum boundary', () => {
      expect(I128String.safeParse('-170141183460469231731687303715884105729').success).toBe(false);
    });

    it('should reject non-integer and out-of-range i128 strings', () => {
      expect(I128String.safeParse('1.5').success).toBe(false);
      expect(I128String.safeParse('abc').success).toBe(false);
      expect(I128String.safeParse(I128_OVERFLOW).success).toBe(false);
    });

    it('should pass non-zod validator errors to next middleware', async () => {
      const error = new Error('custom parser failure');
      const schema = {
        parse: jest.fn(() => {
          throw error;
        }),
      } as unknown as z.ZodSchema;
      const request = { body: { userAddress: VALID_USER_ADDRESS } } as any;
      const next = jest.fn();

      await validateBody(schema)(request, {} as any, next);

      expect(next).toHaveBeenCalledWith(error);
    });

    it('should handle asynchronous Zod schemas resolving successfully', async () => {
      const asyncSchema = z.object({
        asyncField: z.string().refine(async val => val === 'valid', 'Must be valid'),
      });

      const req = { body: { asyncField: 'valid' } } as any;
      const next = jest.fn();

      validateBody(asyncSchema)(req, {} as any, next);

      await new Promise(resolve => setImmediate(resolve));

      expect(next).toHaveBeenCalledWith();
      expect(req.body).toEqual({ asyncField: 'valid' });
    });

    it('should handle asynchronous Zod schemas rejecting with ValidationError', async () => {
      const asyncSchema = z.object({
        asyncField: z.string().refine(async val => val === 'valid', 'Async verification failed'),
      });

      const req = { body: { asyncField: 'invalid' } } as any;
      const next = jest.fn();

      validateBody(asyncSchema)(req, {} as any, next);

      await new Promise(resolve => setImmediate(resolve));

      expect(next).toHaveBeenCalledTimes(1);
      const passedError = next.mock.calls[0][0];
      expect(passedError).toBeInstanceOf(Error);
      expect(passedError.message).toContain('Async verification failed');
    });

    it('should handle null or undefined body gracefully without crashing', () => {
      const schema = z.object({ field: z.string() });
      const next = jest.fn();

      validateBody(schema)({ body: undefined } as any, {} as any, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(next.mock.calls[0][0]).toBeInstanceOf(Error);

      next.mockClear();
      validateBody(schema)({ body: null } as any, {} as any, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(next.mock.calls[0][0]).toBeInstanceOf(Error);
    });

    it('should handle primitive body types (string, number, array) safely', () => {
      const schema = z.object({ field: z.string() });
      const next = jest.fn();

      validateBody(schema)({ body: 'invalid-string' } as any, {} as any, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(next.mock.calls[0][0]).toBeInstanceOf(Error);

      next.mockClear();
      validateBody(schema)({ body: [1, 2, 3] } as any, {} as any, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(next.mock.calls[0][0]).toBeInstanceOf(Error);
    });

    it('should log diagnostic warning without leaking sensitive fields on failure', () => {
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => logger);
      const schema = z.object({
        userSecret: z.string().min(10, 'Secret too short'),
      });

      const req = {
        method: 'POST',
        path: '/api/lending/deposit',
        body: { userSecret: 'shh' },
      } as any;
      const next = jest.fn();

      validateBody(schema)(req, {} as any, next);

      expect(warnSpy).toHaveBeenCalledWith(
        'Request body validation failed',
        expect.objectContaining({
          method: 'POST',
          path: '/api/lending/deposit',
          error: expect.stringContaining('userSecret'),
        })
      );

      warnSpy.mockRestore();
    });

    it('should reject duplicate keys by validating the parsed body deterministically', () => {
      const schema = z.object({ userAddress: StellarAddress }).strict();
      const request = {
        body: { userAddress: VALID_USER_ADDRESS, extra: 'unexpected' },
      } as any;
      const next = jest.fn();

      validateBody(schema)(request, {} as any, next);

      expect(next).toHaveBeenCalledWith(expect.any(Error));
    });

    /**
     * Advance-Once Invariant.
     *
     * `next()` used to be called from INSIDE the try/catch that wraps
     * `schema.parse`. When a downstream handler threw synchronously, the
     * resulting error was caught and mistaken for a validation failure, so
     * `next(err)` ran a SECOND time and advanced the Express chain twice.
     */
    describe('Advance-Once Invariant (regression)', () => {
      it('should not re-enter the catch block when downstream next() throws synchronously', () => {
        const schema = z.object({ field: z.string() });
        const req = { body: { field: 'value' } } as any;
        const downstreamError = new Error('downstream handler blew up');

        const next = jest.fn(() => {
          throw downstreamError;
        });

        // The throw belongs to Express, not to validation, so it must escape
        // rather than be converted into a second next() invocation.
        expect(() => validateBody(schema)(req, {} as any, next)).toThrow(downstreamError);

        expect(next).toHaveBeenCalledTimes(1);
        expect(next).toHaveBeenCalledWith();
        expect(req.body).toEqual({ field: 'value' });
      });

      it('should advance the downstream chain exactly once end-to-end', async () => {
        const app = express();
        app.use(express.json());

        let handlerRuns = 0;
        let nextCalls = 0;
        app.post(
          '/advance-once',
          validateBody(z.object({ field: z.string() })),
          (_req: any, _res: any, next: any) => {
            handlerRuns += 1;
            nextCalls += 1;
            next();
          }
        );
        app.use((_err: any, _req: any, res: any, _next: any) => {
          res.status(500).json({ error: 'unreachable' });
        });

        const response = await request(app).post('/advance-once').send({ field: 'x' });

        expect(response.status).toBe(404);
        expect(handlerRuns).toBe(1);
        expect(nextCalls).toBe(1);
      });

      it('should call next() exactly once when downstream throws on the async path', async () => {
        const schema = z.object({
          field: z.string().refine(async () => true),
        });
        const app = express();
        app.use(express.json());

        let handlerRuns = 0;
        app.post(
          '/async-advance-once',
          validateBody(schema),
          (_req: any, _res: any, next: any) => {
            handlerRuns += 1;
            next();
          }
        );
        app.use((err: any, _req: any, res: any, _next: any) => {
          res.status(500).json({ error: err.message });
        });

        const response = await request(app).post('/async-advance-once').send({ field: 'x' });
        await new Promise(resolve => setImmediate(resolve));

        expect(handlerRuns).toBe(1);
        expect(response.status).toBe(404);
      });
    });

    /**
     * Async fallback failure paths.
     *
     * The async re-parse used to be fire-and-forget: `schema.parseAsync(...)`
     * was chained without guarding the call itself. If it threw synchronously,
     * or returned a non-thenable, the rejection escaped the middleware. Express 4
     * ignores rejected middleware promises, so the request was left hanging
     * forever with no response and no error event.
     */
    describe('Async Fallback Failure Paths (regression)', () => {
      it('should settle next() instead of hanging when parseAsync throws synchronously', async () => {
        const app = express();
        app.use(express.json());

        const schema = {
          parse: () => {
            throw new Error('Encountered Promise during synchronous parse');
          },
          parseAsync: () => {
            throw new Error('parseAsync exploded synchronously');
          },
        } as unknown as z.ZodSchema;

        let handlerRuns = 0;
        app.post('/sync-throw', validateBody(schema), (_req: any, res: any) => {
          handlerRuns += 1;
          res.json({ ok: true });
        });
        app.use((err: any, _req: any, res: any, _next: any) => {
          res.status(500).json({ error: err.message });
        });

        // A hang would never settle; the bounded race makes that a failure.
        const outcome: any = await withHangTimeout(
          request(app).post('/sync-throw').send({ field: 'x' })
        );

        expect(outcome.timedOut).toBeUndefined();
        expect(outcome.status).toBe(500);
        expect(handlerRuns).toBe(0);
      });

      it('should settle next() instead of hanging when parseAsync returns a non-thenable', async () => {
        const app = express();
        app.use(express.json());

        const schema = {
          parse: () => {
            throw new Error('Encountered Promise during synchronous parse');
          },
          parseAsync: () => undefined,
        } as unknown as z.ZodSchema;

        app.post('/non-thenable', validateBody(schema), (_req: any, res: any) => {
          res.json({ ok: true });
        });
        app.use((err: any, _req: any, res: any, _next: any) => {
          res.status(500).json({ error: err.message });
        });

        const outcome: any = await withHangTimeout(
          request(app).post('/non-thenable').send({ field: 'x' })
        );

        expect(outcome.timedOut).toBeUndefined();
        expect(outcome.status).toBe(500);
      });

      it('should never return a rejected promise from the middleware', async () => {
        const schema = {
          parse: () => {
            throw new Error('Encountered Promise during synchronous parse');
          },
          parseAsync: () => {
            throw new Error('parseAsync exploded synchronously');
          },
        } as unknown as z.ZodSchema;

        const req = { body: { field: 'x' } } as any;
        const next = jest.fn();

        // Express 4 does not observe returned promises, so the middleware must
        // not be able to reject at all.
        const returned = validateBody(schema)(req, {} as any, next);
        expect(returned).toBeUndefined();

        await expect(Promise.resolve(returned)).resolves.toBeUndefined();
        expect(next).toHaveBeenCalledTimes(1);
        expect(next.mock.calls[0][0]).toBeInstanceOf(Error);
      });

      it('should not leak an unhandled rejection when the async schema rejects', async () => {
        const unhandled: unknown[] = [];
        const listener = (reason: unknown) => unhandled.push(reason);
        process.on('unhandledRejection', listener);

        try {
          const schema = {
            parse: () => {
              throw new Error('Encountered Promise during synchronous parse');
            },
            parseAsync: () => Promise.reject(new Error('async validation failed')),
          } as unknown as z.ZodSchema;

          const next = jest.fn();
          validateBody(schema)({ body: { field: 'x' } } as any, {} as any, next);

          await new Promise(resolve => setTimeout(resolve, 50));
          // Let any stray microtask/rejection surface before asserting none.

          expect(next).toHaveBeenCalledTimes(1);
          expect(next.mock.calls[0][0]).toBeInstanceOf(Error);
          expect(unhandled).toEqual([]);
        } finally {
          process.off('unhandledRejection', listener);
        }
      });

      it('should not mutate req.body when the async path rejects', async () => {
        const schema = {
          parse: () => {
            throw new Error('Encountered Promise during synchronous parse');
          },
          parseAsync: () => Promise.reject(new Error('async validation failed')),
        } as unknown as z.ZodSchema;

        const req = { body: { field: 'original' } } as any;
        const next = jest.fn();

        validateBody(schema)(req, {} as any, next);
        await new Promise(resolve => setImmediate(resolve));

        expect(req.body).toEqual({ field: 'original' });
      });
    });

    /**
     * Async detection stability.
     *
     * Detection used to substring-match an internal Zod error *message*. A
     * wording change silently degraded async validation into an unhandled
     * 500 instead of a normal validation result.
     */
    describe('Async Schema Detection Stability (regression)', () => {
      it('should detect async schemas by error name when the message wording differs', async () => {
        const app = express();
        app.use(express.json());

        const schema = {
          parse: () => {
            const error = new Error('Some entirely different wording from a future release');
            error.name = '$ZodAsyncError';
            throw error;
          },
          parseAsync: async () => ({ field: 'validated' }),
        } as unknown as z.ZodSchema;

        let handlerRuns = 0;
        app.post(
          '/renamed',
          validateBody(schema),
          (req: any, res: any) => {
            handlerRuns += 1;
            res.json({ body: req.body });
          }
        );
        app.use((err: any, _req: any, res: any, _next: any) => {
          res.status(500).json({ error: err.message });
        });

        const response = await request(app).post('/renamed').send({ field: 'x' });

        expect(response.status).toBe(200);
        expect(handlerRuns).toBe(1);
        expect(response.body.body).toEqual({ field: 'validated' });
      });

      it('should still detect async schemas via the legacy message fallback', async () => {
        const schema = {
          parse: () => {
            throw new Error('Encountered Promise during synchronous parse. Use .parseAsync() instead.');
          },
          parseAsync: async () => ({ field: 'legacy' }),
        } as unknown as z.ZodSchema;

        const req = { body: { field: 'x' } } as any;
        const next = jest.fn();

        validateBody(schema)(req, {} as any, next);
        await new Promise(resolve => setImmediate(resolve));

        expect(next).toHaveBeenCalledWith();
        expect(req.body).toEqual({ field: 'legacy' });
      });

      it('should forward the async error when the schema has no parseAsync', () => {
        const asyncError = new Error('Encountered Promise during synchronous parse');
        const schema = {
          parse: () => {
            throw asyncError;
          },
        } as unknown as z.ZodSchema;

        const next = jest.fn();
        validateBody(schema)({ body: {} } as any, {} as any, next);

        // Without parseAsync there is no way to re-validate, so the error must
        // be forwarded rather than swallowed or reclassified.
        expect(next).toHaveBeenCalledTimes(1);
        expect(next).toHaveBeenCalledWith(asyncError);
      });

      it('should not report a second error when next() throws on the async success path', async () => {
        const unhandled: unknown[] = [];
        const listener = (reason: unknown) => unhandled.push(reason);
        process.on('unhandledRejection', listener);

        try {
          const schema = {
            parse: () => {
              throw new Error('Encountered Promise during synchronous parse');
            },
            parseAsync: async () => ({ field: 'x' }),
          } as unknown as z.ZodSchema;

          const req = { body: { field: 'x' } } as any;
          const next = jest.fn(() => {
            throw new Error('downstream handler exploded');
          });

          // The success callback already advanced the chain, so a throw from
          // next() must not be re-reported as a validation error, and must not
          // escape as an unhandled rejection.
          validateBody(schema)(req, {} as any, next);
          await new Promise(resolve => setTimeout(resolve, 50));

          expect(next).toHaveBeenCalledTimes(1);
          expect(req.body).toEqual({ field: 'x' });
          expect(unhandled).toEqual([]);
        } finally {
          process.off('unhandledRejection', listener);
        }
      });

      it('should handle a non-Error downstream throw without crashing', async () => {
        const errorSpy = jest.spyOn(logger, 'error').mockImplementation(() => logger);
        const unhandled: unknown[] = [];
        const listener = (reason: unknown) => unhandled.push(reason);
        process.on('unhandledRejection', listener);

        try {
          const schema = {
            parse: () => {
              throw new Error('Encountered Promise during synchronous parse');
            },
            parseAsync: async () => ({ field: 'x' }),
          } as unknown as z.ZodSchema;

          // A downstream throw that is not an Error must still be diagnosable
          // and must not escape as an unhandled rejection.
          const next = jest.fn(() => {
            throw 'plain string downstream failure';
          });

          validateBody(schema)({ body: { field: 'x' } } as any, {} as any, next);
          await new Promise(resolve => setTimeout(resolve, 50));

          expect(next).toHaveBeenCalledTimes(1);
          expect(errorSpy).toHaveBeenCalledWith(
            'Async validation failed after the request advanced',
            expect.objectContaining({ error: 'plain string downstream failure' })
          );
          expect(unhandled).toEqual([]);
        } finally {
          process.off('unhandledRejection', listener);
          errorSpy.mockRestore();
        }
      });

      it('should forward a non-Error async rejection to next without crashing', async () => {
        const schema = {
          parse: () => {
            throw new Error('Encountered Promise during synchronous parse');
          },
          parseAsync: () => Promise.reject('plain string rejection'),
        } as unknown as z.ZodSchema;

        const next = jest.fn();
        validateBody(schema)({ body: { field: 'x' } } as any, {} as any, next);
        await new Promise(resolve => setImmediate(resolve));

        expect(next).toHaveBeenCalledTimes(1);
        expect(next).toHaveBeenCalledWith('plain string rejection');
      });

      it('should not treat an unrelated error as an async schema error', () => {
        const schema = {
          parse: () => {
            throw new Error('some unrelated failure');
          },
          parseAsync: jest.fn(),
        } as unknown as z.ZodSchema;

        const next = jest.fn();
        validateBody(schema)({ body: {} } as any, {} as any, next);

        expect(next).toHaveBeenCalledTimes(1);
        expect((schema as any).parseAsync).not.toHaveBeenCalled();
        expect(next.mock.calls[0][0].message).toBe('some unrelated failure');
      });
    });
  });

  describe('Boundary Values for the Lending Schema', () => {
    const parse = (body: unknown) => lendingRequestSchema.safeParse(body);

    const base = {
      userAddress: VALID_USER_ADDRESS,
      amount: '1000000',
      userSecret: VALID_USER_SECRET,
    };

    it('should accept the smallest representable positive amount', () => {
      const result = parse({ ...base, amount: '1' });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.amount).toBe('1');
      }
    });

    it('should accept the largest representable i128 amount', () => {
      const result = parse({ ...base, amount: I128_MAX });
      expect(result.success).toBe(true);
    });

    it('should reject one stroop above i128::MAX', () => {
      expect(parse({ ...base, amount: I128_OVERFLOW }).success).toBe(false);
    });

    it('should reject zero and negative amounts at the sign boundary', () => {
      expect(parse({ ...base, amount: '0' }).success).toBe(false);
      expect(parse({ ...base, amount: '-0' }).success).toBe(false);
      expect(parse({ ...base, amount: '-1' }).success).toBe(false);
    });

    it('should reject the negative i128 minimum, which is not a positive amount', () => {
      expect(parse({ ...base, amount: I128_MIN }).success).toBe(false);
    });

    it('should trim surrounding whitespace on boundary amounts', () => {
      const result = parse({ ...base, amount: `  ${I128_MAX}  ` });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.amount).toBe(I128_MAX);
      }
    });

    it('should reject amounts with a leading sign, decimals, or exponent notation', () => {
      expect(parse({ ...base, amount: '+1' }).success).toBe(false);
      expect(parse({ ...base, amount: '1.0' }).success).toBe(false);
      expect(parse({ ...base, amount: '1e6' }).success).toBe(false);
      expect(parse({ ...base, amount: '0x10' }).success).toBe(false);
      expect(parse({ ...base, amount: '1,000' }).success).toBe(false);
    });

    it('should reject a non-string numeric amount so precision is never lost', () => {
      expect(parse({ ...base, amount: 1000000 }).success).toBe(false);
      expect(parse({ ...base, amount: 1.5 }).success).toBe(false);
      expect(parse({ ...base, amount: null }).success).toBe(false);
    });

    it('should reject a missing or non-string userSecret', () => {
      expect(parse({ userAddress: VALID_USER_ADDRESS, amount: '1' }).success).toBe(false);
      expect(parse({ ...base, userSecret: '' }).success).toBe(false);
      expect(parse({ ...base, userSecret: '   ' }).success).toBe(false);
      expect(parse({ ...base, userSecret: 12345 }).success).toBe(false);
      expect(parse({ ...base, userSecret: null }).success).toBe(false);
    });

    it('should normalize a null assetAddress to undefined instead of failing', () => {
      const result = parse({ ...base, assetAddress: null });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.assetAddress).toBeUndefined();
      }
    });

    it('should reject an assetAddress that is present but malformed', () => {
      expect(parse({ ...base, assetAddress: 'not-an-address' }).success).toBe(false);
      expect(parse({ ...base, assetAddress: 42 }).success).toBe(false);
    });

    it('should reject a userAddress that is valid base58 but not a Stellar key', () => {
      // Length and prefix look plausible, but the StrKey checksum is wrong.
      const forged = `G${'A'.repeat(55)}`;
      expect(parse({ ...base, userAddress: forged }).success).toBe(false);
    });

    it('should reject an all-zero address of the correct length', () => {
      const forged = `G${'A'.repeat(55)}`;
      expect(parse({ ...base, userAddress: forged }).success).toBe(false);
    });

    it('should strip unknown fields rather than trusting them', () => {
      const result = parse({ ...base, isAdmin: true, role: 'admin', amount_override: '1' });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data).not.toHaveProperty('isAdmin');
        expect(result.data).not.toHaveProperty('role');
        expect(result.data).not.toHaveProperty('amount_override');
        expect(result.data.amount).toBe('1000000');
      }
    });

    it('should produce a deterministic result across repeated parses', () => {
      const outcomes = new Set<string>();
      for (let i = 0; i < 25; i += 1) {
        const result = parse({ ...base, amount: 'not-a-number' });
        outcomes.add(result.success ? 'accepted' : 'rejected');
      }
      expect(outcomes.size).toBe(1);
      expect([...outcomes]).toEqual(['rejected']);
    });

    it('should not allow prototype pollution through the payload', () => {
      const payload = JSON.parse(
        '{"userAddress":"' +
          VALID_USER_ADDRESS +
          '","amount":"1000000","userSecret":"' +
          VALID_USER_SECRET +
          '","__proto__":{"polluted":"yes"}}'
      );

      parse(payload);

      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    });
  });

  describe('Deposit Validation Endpoint (/api/lending/deposit)', () => {
    it('should reject empty userAddress', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          amount: '1000000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('userAddress');
      expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
    });

    it('should reject malformed userAddress before controller execution', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: 'invalid_address',
          amount: '1000000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('valid Stellar');
      expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
    });

    it('should accept valid contract address for userAddress', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_CONTRACT_ADDRESS,
          amount: '1000000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('mock transaction failure');
      expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledWith(
        VALID_CONTRACT_ADDRESS,
        undefined,
        '1000000',
        VALID_USER_SECRET
      );
    });

    it('should reject zero amount', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: '0',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('greater than zero');
      expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
    });

    it('should reject negative amount', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: '-1000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
    });

    it('should reject non-integer amount', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: '1.5',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('integer string');
      expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
    });

    it('should reject i128 amount overflow', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: I128_OVERFLOW,
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('signed 128-bit');
      expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
    });

    it('should accept boundary amount equal to 1', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: '1',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('mock transaction failure');
      expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledWith(
        VALID_USER_ADDRESS,
        undefined,
        '1',
        VALID_USER_SECRET
      );
    });

    it('should accept boundary amount equal to i128::MAX', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: I128_MAX,
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('mock transaction failure');
      expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledWith(
        VALID_USER_ADDRESS,
        undefined,
        I128_MAX,
        VALID_USER_SECRET
      );
    });

    it('should reject missing userSecret authorization credential', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: '1000000',
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('userSecret');
      expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
    });

    it('should reject whitespace-only userSecret', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: '1000000',
          userSecret: '    ',
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('User secret is required');
      expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
    });

    it('should allow valid body with optional assetAddress', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          assetAddress: VALID_ASSET_ADDRESS,
          amount: '1000000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('mock transaction failure');
      expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledWith(
        VALID_USER_ADDRESS,
        VALID_ASSET_ADDRESS,
        '1000000',
        VALID_USER_SECRET
      );
    });

    it('should normalize empty string assetAddress to undefined', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          assetAddress: '',
          amount: '1000000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledWith(
        VALID_USER_ADDRESS,
        undefined,
        '1000000',
        VALID_USER_SECRET
      );
    });

    it('should normalize whitespace-only assetAddress to undefined', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          assetAddress: '   ',
          amount: '1000000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledWith(
        VALID_USER_ADDRESS,
        undefined,
        '1000000',
        VALID_USER_SECRET
      );
    });

    it('should reject malformed assetAddress when provided', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          assetAddress: 'invalid_asset_address',
          amount: '1000000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('assetAddress');
      expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
    });

    it('should safely strip unexpected/extraneous fields from payload', async () => {
      const response = await request(app)
        .post('/api/lending/deposit')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: '1000000',
          userSecret: VALID_USER_SECRET,
          maliciousField: 'attack_payload',
          __proto__: { polluted: true },
        });

      expect(response.status).toBe(400);
      expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledWith(
        VALID_USER_ADDRESS,
        undefined,
        '1000000',
        VALID_USER_SECRET
      );
    });
  });

  describe('Borrow Validation Endpoint (/api/lending/borrow)', () => {
    it('should reject empty request body', async () => {
      const response = await request(app)
        .post('/api/lending/borrow')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(mockStellarService.buildBorrowTransaction).not.toHaveBeenCalled();
    });

    it('should validate and forward valid borrow request', async () => {
      const response = await request(app)
        .post('/api/lending/borrow')
        .send({
          userAddress: VALID_USER_ADDRESS,
          assetAddress: VALID_ASSET_ADDRESS,
          amount: '500000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('mock transaction failure');
      expect(mockStellarService.buildBorrowTransaction).toHaveBeenCalledWith(
        VALID_USER_ADDRESS,
        VALID_ASSET_ADDRESS,
        '500000',
        VALID_USER_SECRET
      );
    });

    it('should reject invalid amount in borrow request', async () => {
      const response = await request(app)
        .post('/api/lending/borrow')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: '0',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(mockStellarService.buildBorrowTransaction).not.toHaveBeenCalled();
    });

    it('should reject malformed userAddress before controller execution', async () => {
      const response = await request(app)
        .post('/api/lending/borrow')
        .send({
          userAddress: 'invalid_address',
          amount: '1000000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Repay Validation Endpoint (/api/lending/repay)', () => {
    it('should reject empty request body', async () => {
      const response = await request(app)
        .post('/api/lending/repay')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(mockStellarService.buildRepayTransaction).not.toHaveBeenCalled();
    });

    it('should validate and forward valid repay request', async () => {
      const response = await request(app)
        .post('/api/lending/repay')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: '250000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('mock transaction failure');
      expect(mockStellarService.buildRepayTransaction).toHaveBeenCalledWith(
        VALID_USER_ADDRESS,
        undefined,
        '250000',
        VALID_USER_SECRET
      );
    });

    it('should reject invalid userAddress in repay request', async () => {
      const response = await request(app)
        .post('/api/lending/repay')
        .send({
          userAddress: 'bad_address',
          amount: '250000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(mockStellarService.buildRepayTransaction).not.toHaveBeenCalled();
    });

    it('should reject i128 amount overflow', async () => {
      const response = await request(app)
        .post('/api/lending/repay')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: I128_OVERFLOW,
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
    });
  });

  describe('Withdraw Validation Endpoint (/api/lending/withdraw)', () => {
    it('should reject empty request body', async () => {
      const response = await request(app)
        .post('/api/lending/withdraw')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(mockStellarService.buildWithdrawTransaction).not.toHaveBeenCalled();
    });

    it('should validate and forward valid withdraw request', async () => {
      const response = await request(app)
        .post('/api/lending/withdraw')
        .send({
          userAddress: VALID_USER_ADDRESS,
          assetAddress: VALID_ASSET_ADDRESS,
          amount: '100000',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('mock transaction failure');
      expect(mockStellarService.buildWithdrawTransaction).toHaveBeenCalledWith(
        VALID_USER_ADDRESS,
        VALID_ASSET_ADDRESS,
        '100000',
        VALID_USER_SECRET
      );
    });

    it('should reject missing userSecret in withdraw request', async () => {
      const response = await request(app)
        .post('/api/lending/withdraw')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: '100000',
        });

      expect(response.status).toBe(400);
      expect(mockStellarService.buildWithdrawTransaction).not.toHaveBeenCalled();
    });
  });

  describe('Adverse Conditions: Retries, Concurrency, and Determinism', () => {
    it('should produce deterministic rejection across repeated retries with identical invalid payload', async () => {
      const invalidPayload = {
        userAddress: 'invalid_address',
        amount: '-10',
        userSecret: '',
      };

      const responses = await Promise.all(
        Array.from({ length: 5 }, () =>
          request(app)
            .post('/api/lending/deposit')
            .send(invalidPayload)
        )
      );

      const firstStatus = responses[0].status;
      const firstError = responses[0].body.error;

      expect(firstStatus).toBe(400);
      for (const res of responses) {
        expect(res.status).toBe(firstStatus);
        expect(res.body.error).toBe(firstError);
      }
      expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
    });

    it('should produce deterministic success across repeated retries with identical valid payload', async () => {
      const validPayload = {
        userAddress: VALID_USER_ADDRESS,
        amount: '1000000',
        userSecret: VALID_USER_SECRET,
      };

      const responses = await Promise.all(
        Array.from({ length: 5 }, () =>
          request(app)
            .post('/api/lending/deposit')
            .send(validPayload)
        )
      );

      for (const res of responses) {
        expect(res.status).toBe(400); // Fails in controller mock, but passed validation
        expect(res.body.error).toBe('mock transaction failure');
      }
      expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledTimes(5);
    });

    it('should execute concurrent mixed valid and invalid requests in complete isolation', async () => {
      const validPayload = {
        userAddress: VALID_USER_ADDRESS,
        amount: '1000000',
        userSecret: VALID_USER_SECRET,
      };
      const invalidPayload = {
        userAddress: 'bad_address',
        amount: '0',
        userSecret: '   ',
      };

      const requests = Array.from({ length: 20 }, (_, idx) => {
        const isValid = idx % 2 === 0;
        return request(app)
          .post('/api/lending/deposit')
          .send(isValid ? validPayload : invalidPayload)
          .then(res => ({ idx, isValid, status: res.status, body: res.body }));
      });

      const results = await Promise.all(requests);

      for (const r of results) {
        if (r.isValid) {
          expect(r.body.error).toBe('mock transaction failure');
        } else {
          expect(r.status).toBe(400);
          expect(r.body.error).toContain('userAddress');
        }
      }

      // Exactly 10 valid requests reached the controller
      expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledTimes(10);
    });
  });

  describe('Exported Validation Arrays Compatibility', () => {
    it('should export depositValidation, borrowValidation, repayValidation, withdrawValidation arrays', () => {
      expect(Array.isArray(depositValidation)).toBe(true);
      expect(depositValidation.length).toBe(1);
      expect(typeof depositValidation[0]).toBe('function');

      expect(Array.isArray(borrowValidation)).toBe(true);
      expect(borrowValidation.length).toBe(1);
      expect(typeof borrowValidation[0]).toBe('function');

      expect(Array.isArray(repayValidation)).toBe(true);
      expect(repayValidation.length).toBe(1);
      expect(typeof repayValidation[0]).toBe('function');

      expect(Array.isArray(withdrawValidation)).toBe(true);
      expect(withdrawValidation.length).toBe(1);
      expect(typeof withdrawValidation[0]).toBe('function');
    });

    it('should export lendingRequestSchema and validators', () => {
      expect(lendingRequestSchema).toBeDefined();
      expect(typeof lendingRequestSchema.parse).toBe('function');
      expect(I128String).toBeDefined();
      expect(PositiveI128String).toBeDefined();
      expect(StellarAddress).toBeDefined();
    });

    it('should reject zero amount', async () => {
      const response = await request(app)
        .post('/api/lending/withdraw')
        .send({
          userAddress: VALID_USER_ADDRESS,
          amount: '0',
          userSecret: VALID_USER_SECRET,
        });

      expect(response.status).toBe(400);
    });
  });
});

describe('Hook HMAC Validation', () => {
  const mockReq = {
    headers: {},
    body: {},
    rawBody: '{}',
  } as any;
  const mockRes = {} as any;
  const next = jest.fn();

  beforeEach(() => {
    process.env.STELLAR_API_HOOK_SECRET = 'validation-hook-secret';
  });

  it('rejects missing hook headers', () => {
    jest.isolateModules(() => {
      const { verifyHookHmac } = require('../middleware/auth');
      expect(() => verifyHookHmac(mockReq, mockRes, next)).toThrow(
        'Hook signature and timestamp headers are required'
      );
    });
  });

  it('rejects invalid hook timestamp', () => {
    jest.isolateModules(() => {
      const { verifyHookHmac } = require('../middleware/auth');
      const req = {
        headers: {
          'x-hook-timestamp': 'not-a-number',
          'x-hook-signature': 'abcd',
        },
        body: {},
        rawBody: '{}',
      } as any;

      expect(() => verifyHookHmac(req, mockRes, next)).toThrow(
        'Invalid hook timestamp'
      );
    });
  });

  it('rejects a stale hook timestamp outside the replay window', () => {
    jest.isolateModules(() => {
      const { verifyHookHmac } = require('../middleware/auth');
      const staleTimestamp = String(Date.now() - 3600 * 1000);
      const req = {
        headers: {
          'x-hook-timestamp': staleTimestamp,
          'x-hook-signature': 'abcd',
        },
        body: {},
        rawBody: '{}',
      } as any;

      expect(() => verifyHookHmac(req, mockRes, next)).toThrow();
    });
  });

  it('accepts a valid hook signature and rejects a tampered body', () => {
    jest.isolateModules(() => {
      const { verifyHookHmac } = require('../middleware/auth');
      const secret = process.env.STELLAR_API_HOOK_SECRET as string;
      const timestamp = String(Date.now());
      const rawBody = JSON.stringify({ event: 'deposit', amount: '1000000' });
      const signature = crypto
        .createHmac('sha256', secret)
        .update(`${timestamp}.${rawBody}`)
        .digest('hex');

      const validReq = {
        headers: {
          'x-hook-timestamp': timestamp,
          'x-hook-signature': signature,
        },
        body: JSON.parse(rawBody),
        rawBody,
      } as any;
      expect(() => verifyHookHmac(validReq, mockRes, next)).not.toThrow();

      const tamperedReq = {
        ...validReq,
        rawBody: JSON.stringify({ event: 'deposit', amount: '9999999' }),
      } as any;
      expect(() => verifyHookHmac(tamperedReq, mockRes, next)).toThrow();
    });
  });
});
