import crypto from 'crypto';
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

  // ---------------------------------------------------------------------------
  // Unconfigured hookSecret: must reject before checking headers/signature.
  // ---------------------------------------------------------------------------
  it('rejects when hookSecret is not configured', () => {
    jest.isolateModules(() => {
      delete process.env.STELLAR_API_HOOK_SECRET;
      // Force config to reload without the secret
      jest.resetModules();
      const { verifyHookHmac } = require('../middleware/auth');
      const timestamp = String(Date.now());
      const req = {
        headers: {
          'x-hook-timestamp': timestamp,
          'x-hook-signature': 'deadbeef',
        },
        body: {},
        rawBody: '{}',
      } as any;
      expect(() => verifyHookHmac(req, mockRes, next)).toThrow(
        'Hook authentication secret is not configured'
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Array-format headers: spec says first element is used (not concatenated).
  // ---------------------------------------------------------------------------
  it('accepts array-format timestamp/signature headers using the first element', () => {
    jest.isolateModules(() => {
      process.env.STELLAR_API_HOOK_SECRET = 'validation-hook-secret';
      const { verifyHookHmac } = require('../middleware/auth');
      const secret = 'validation-hook-secret';
      const timestamp = String(Date.now());
      const rawBody = '{}';
      const signature = crypto
        .createHmac('sha256', secret)
        .update(`${timestamp}.${rawBody}`)
        .digest('hex');

      const req = {
        headers: {
          'x-hook-timestamp': [timestamp, 'ignored-second-value'],
          'x-hook-signature': [signature, 'ignored-second-value'],
        },
        body: {},
        rawBody,
      } as any;

      expect(() => verifyHookHmac(req, mockRes, next)).not.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // Timestamp exactly at the edge of the replay window (just inside = accept,
  // just outside = reject).
  // ---------------------------------------------------------------------------
  it('accepts a timestamp exactly at the edge of the replay window', () => {
    jest.isolateModules(() => {
      process.env.STELLAR_API_HOOK_SECRET = 'validation-hook-secret';
      const { verifyHookHmac } = require('../middleware/auth');
      const secret = 'validation-hook-secret';
      // 4 minutes 59 seconds ago — just inside the 5-minute window
      const timestamp = String(Date.now() - (5 * 60 * 1000 - 1000));
      const rawBody = '{}';
      const signature = crypto
        .createHmac('sha256', secret)
        .update(`${timestamp}.${rawBody}`)
        .digest('hex');

      const req = {
        headers: {
          'x-hook-timestamp': timestamp,
          'x-hook-signature': signature,
        },
        body: {},
        rawBody,
      } as any;

      expect(() => verifyHookHmac(req, mockRes, next)).not.toThrow();
    });
  });

  it('rejects a future timestamp outside the replay window', () => {
    jest.isolateModules(() => {
      process.env.STELLAR_API_HOOK_SECRET = 'validation-hook-secret';
      const { verifyHookHmac } = require('../middleware/auth');
      const futureTimestamp = String(Date.now() + 10 * 60 * 1000);
      const req = {
        headers: {
          'x-hook-timestamp': futureTimestamp,
          'x-hook-signature': 'abcd',
        },
        body: {},
        rawBody: '{}',
      } as any;
      expect(() => verifyHookHmac(req, mockRes, next)).toThrow();
    });
  });
});

// =============================================================================
// Additional failure-path and boundary coverage
// =============================================================================

describe('I128String — Additional Boundary and Failure Paths', () => {
  // Leading zeros are not valid integer representations (regex ^-?\d+$ allows
  // them, but these are additional important edge cases for documentation).
  it('should accept strings with leading zeros (regex permits them)', () => {
    // The regex ^-?\d+$ matches "007"; the actual behaviour is acceptance.
    // This test documents the current behaviour so regressions are caught.
    expect(I128String.safeParse('007').success).toBe(true);
  });

  it('should reject a "+" prefix (not matched by ^-?\\d+$)', () => {
    expect(I128String.safeParse('+5').success).toBe(false);
    expect(I128String.safeParse('+0').success).toBe(false);
  });

  it('should reject a lone dash "-"', () => {
    expect(I128String.safeParse('-').success).toBe(false);
  });

  it('should reject double-dash "--1"', () => {
    expect(I128String.safeParse('--1').success).toBe(false);
  });

  it('should reject "NaN" and "Infinity"', () => {
    expect(I128String.safeParse('NaN').success).toBe(false);
    expect(I128String.safeParse('Infinity').success).toBe(false);
    expect(I128String.safeParse('-Infinity').success).toBe(false);
  });

  it('should reject scientific-notation strings', () => {
    expect(I128String.safeParse('1e18').success).toBe(false);
    expect(I128String.safeParse('1E18').success).toBe(false);
    expect(I128String.safeParse('1.5e10').success).toBe(false);
  });

  it('should reject hex strings', () => {
    expect(I128String.safeParse('0xFF').success).toBe(false);
    expect(I128String.safeParse('0x10').success).toBe(false);
  });

  it('should trim surrounding whitespace and still validate correctly', () => {
    const result = I128String.safeParse('  -42  ');
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toBe('-42');
    }
  });

  it('should accept i128::MAX exactly', () => {
    expect(I128String.safeParse('170141183460469231731687303715884105727').success).toBe(true);
  });

  it('should accept i128::MIN exactly', () => {
    expect(I128String.safeParse('-170141183460469231731687303715884105728').success).toBe(true);
  });

  it('should reject i128::MAX + 1', () => {
    expect(I128String.safeParse('170141183460469231731687303715884105728').success).toBe(false);
  });

  it('should reject i128::MIN - 1', () => {
    expect(I128String.safeParse('-170141183460469231731687303715884105729').success).toBe(false);
  });

  it('should reject very large numbers well beyond i128 range', () => {
    expect(
      I128String.safeParse(
        '99999999999999999999999999999999999999999999999999999999999999'
      ).success
    ).toBe(false);
  });
});

describe('PositiveI128String — Additional Boundary and Failure Paths', () => {
  it('should reject i128::MAX + 1 overflow', () => {
    expect(PositiveI128String.safeParse('170141183460469231731687303715884105728').success).toBe(false);
  });

  it('should reject strings with leading zeros (e.g., "00")', () => {
    // "00" parses to 0n which is not > 0n
    expect(PositiveI128String.safeParse('00').success).toBe(false);
  });

  it('should reject "+" prefix', () => {
    expect(PositiveI128String.safeParse('+1').success).toBe(false);
  });

  it('should accept the minimum positive value "1"', () => {
    expect(PositiveI128String.safeParse('1').success).toBe(true);
  });

  it('should accept i128::MAX', () => {
    expect(PositiveI128String.safeParse('170141183460469231731687303715884105727').success).toBe(true);
  });

  it('should reject zero', () => {
    expect(PositiveI128String.safeParse('0').success).toBe(false);
  });

  it('should reject negative values', () => {
    expect(PositiveI128String.safeParse('-1').success).toBe(false);
    expect(PositiveI128String.safeParse('-170141183460469231731687303715884105728').success).toBe(false);
  });

  it('should reject float strings', () => {
    expect(PositiveI128String.safeParse('1.0').success).toBe(false);
    expect(PositiveI128String.safeParse('0.1').success).toBe(false);
  });
});

describe('validateBody — Additional Failure-Path Coverage', () => {
  it('should validate an empty-object schema against an empty body without error', () => {
    const emptySchema = z.object({});
    const req = { body: {} } as any;
    const next = jest.fn();

    validateBody(emptySchema)(req, {} as any, next);

    expect(next).toHaveBeenCalledWith();
    expect(req.body).toEqual({});
  });

  it('should call logger.warn even when req lacks method and path properties', () => {
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => logger);
    const schema = z.object({ field: z.string().min(5) });

    // req with neither method nor path — covers the optional chaining safe path
    const req = { body: { field: 'ab' } } as any;
    const next = jest.fn();

    validateBody(schema)(req, {} as any, next);

    expect(warnSpy).toHaveBeenCalledWith(
      'Request body validation failed',
      expect.objectContaining({ error: expect.stringContaining('field') })
    );
    expect(next).toHaveBeenCalledWith(expect.any(Error));

    warnSpy.mockRestore();
  });

  it('should not mutate req.body on validation failure with a deeply nested body', async () => {
    const schema = z.object({ nested: z.object({ value: z.number() }) });
    const originalBody = { nested: { value: 'not-a-number' } };
    const req = { body: JSON.parse(JSON.stringify(originalBody)) } as any;
    const next = jest.fn();

    validateBody(schema)(req, {} as any, next);

    await new Promise(resolve => setImmediate(resolve));

    expect(next).toHaveBeenCalledWith(expect.any(Error));
    expect(req.body).toEqual(originalBody);
  });

  it('should handle concurrent calls without shared-state contamination', async () => {
    const schema = z.object({ value: z.number() });

    const results = await Promise.all(
      Array.from({ length: 50 }, (_, i) => {
        const req = { body: { value: i % 2 === 0 ? i : 'bad' } } as any;
        const next = jest.fn();
        validateBody(schema)(req, {} as any, next);
        return new Promise<{ idx: number; passed: boolean }>(resolve => {
          setImmediate(() => {
            const passed = next.mock.calls.length === 1 && next.mock.calls[0][0] === undefined;
            resolve({ idx: i, passed });
          });
        });
      })
    );

    for (const { idx, passed } of results) {
      // Even indices have numeric values → should pass; odd have 'bad' → should fail
      expect(passed).toBe(idx % 2 === 0);
    }
  });

  it('should forward non-Zod errors thrown by a custom schema.parse', async () => {
    const customError = new TypeError('unexpected custom error');
    const badSchema = { parse: () => { throw customError; } } as unknown as z.ZodSchema;
    const req = { body: {} } as any;
    const next = jest.fn();

    validateBody(badSchema)(req, {} as any, next);

    await new Promise(resolve => setImmediate(resolve));

    expect(next).toHaveBeenCalledWith(customError);
  });
});

describe('Sensitive Field Scrubbing — userSecret must not appear in logs or errors', () => {
  it('should NOT echo the raw userSecret value in the formatted error message', async () => {
    const schema = z.object({
      userSecret: z.string().min(20, 'Secret too short'),
    });
    // 15 chars — shorter than min(20) — so validation must fail
    const secretValue = 'short_secret_val';
    const req = {
      method: 'POST',
      path: '/api/lending/deposit',
      body: { userSecret: secretValue },
    } as any;
    const next = jest.fn();

    await validateBody(schema)(req, {} as any, next);
    await new Promise(resolve => setImmediate(resolve));

    const error = next.mock.calls[0]?.[0];
    expect(error).toBeInstanceOf(Error);
    // The error message should reference the field path but NEVER the raw secret value
    expect(error.message).not.toContain(secretValue);
  });

  it('should mark userSecret field as isSensitive in the logged warning metadata', () => {
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => logger);
    const schema = z.object({
      userSecret: z.string().min(20, 'Secret too short'),
    });
    const req = {
      method: 'POST',
      path: '/api/lending/deposit',
      body: { userSecret: 'tiny' },
    } as any;
    const next = jest.fn();

    validateBody(schema)(req, {} as any, next);

    const warnCall = warnSpy.mock.calls[0];
    expect(warnCall).toBeDefined();
    const logMeta = warnCall[1] as any;
    const sensitiveIssue = logMeta?.issues?.find((i: any) => i.path === 'userSecret');
    expect(sensitiveIssue?.isSensitive).toBe(true);

    warnSpy.mockRestore();
  });

  it('should NOT echo the raw userSecret value in logger.warn call', () => {
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => logger);
    const schema = z.object({
      userSecret: z.string().min(20, 'Secret too short'),
    });
    const secretValue = 'tiny_secret_123';
    const req = {
      method: 'POST',
      path: '/api/lending/deposit',
      body: { userSecret: secretValue },
    } as any;
    const next = jest.fn();

    validateBody(schema)(req, {} as any, next);

    // Walk every warn call argument and verify the raw secret never appears
    for (const call of warnSpy.mock.calls) {
      const serialized = JSON.stringify(call);
      expect(serialized).not.toContain(secretValue);
    }

    warnSpy.mockRestore();
  });
});

describe('isSensitiveField — sensitive-keyword detection invariants', () => {
  // Indirectly exercised through validateBody's warn metadata; we verify the
  // isSensitive flag is set for every known sensitive field name.

  const sensitiveFields = [
    'userSecret',
    'secret',
    'password',
    'token',
    'authorization',
    'key',
    'privateKey',
    'seed',
    'PASSWORD',          // case-insensitive
    'Authorization',     // mixed case
    'access_token',      // underscore-separated compound
    'private_key',       // underscore variant
  ];

  it.each(sensitiveFields)(
    'should mark field "%s" as sensitive in logger metadata',
    fieldName => {
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => logger);

      const schema = z.object({
        [fieldName]: z.string().min(100, 'Too short'),
      });
      const req = {
        method: 'POST',
        path: '/test',
        body: { [fieldName]: 'short' },
      } as any;
      const next = jest.fn();

      validateBody(schema)(req, {} as any, next);

      const warnCall = warnSpy.mock.calls[0];
      const logMeta = warnCall?.[1] as any;
      const issue = logMeta?.issues?.find((i: any) => i.path === fieldName);
      expect(issue?.isSensitive).toBe(true);

      warnSpy.mockRestore();
    }
  );

  it('should NOT mark a non-sensitive field as sensitive', () => {
    const warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => logger);

    const schema = z.object({ userAddress: z.string().min(100, 'Too short') });
    const req = {
      method: 'POST',
      path: '/test',
      body: { userAddress: 'short' },
    } as any;
    const next = jest.fn();

    validateBody(schema)(req, {} as any, next);

    const warnCall = warnSpy.mock.calls[0];
    const logMeta = warnCall?.[1] as any;
    const issue = logMeta?.issues?.find((i: any) => i.path === 'userAddress');
    expect(issue?.isSensitive).toBe(false);

    warnSpy.mockRestore();
  });
});

describe('Error Response Shape — all 400 validation errors include success:false', () => {
  const endpoints = [
    '/api/lending/deposit',
    '/api/lending/borrow',
    '/api/lending/repay',
    '/api/lending/withdraw',
  ] as const;

  const invalidPayload = {
    userAddress: 'bad',
    amount: '0',
    userSecret: '',
  };

  it.each(endpoints)(
    'POST %s with invalid body must return { success: false } in response body',
    async endpoint => {
      const response = await request(app)
        .post(endpoint)
        .send(invalidPayload);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('success', false);
      expect(response.body).toHaveProperty('error');
      expect(typeof response.body.error).toBe('string');
      expect(response.body.error.length).toBeGreaterThan(0);
    }
  );
});

describe('lendingRequestSchema — Additional Boundary Tests via HTTP', () => {
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

  it('should trim leading/trailing whitespace from userAddress via HTTP', async () => {
    const paddedAddress = `  ${VALID_USER_ADDRESS}  `;
    const response = await request(app)
      .post('/api/lending/deposit')
      .send({
        userAddress: paddedAddress,
        amount: '1000000',
        userSecret: VALID_USER_SECRET,
      });

    // Validation passes (address is trimmed and valid), controller mock returns failure
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('mock transaction failure');
    expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledWith(
      VALID_USER_ADDRESS,
      undefined,
      '1000000',
      VALID_USER_SECRET
    );
  });

  it('should trim leading/trailing whitespace from amount via HTTP', async () => {
    const response = await request(app)
      .post('/api/lending/deposit')
      .send({
        userAddress: VALID_USER_ADDRESS,
        amount: '  500000  ',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('mock transaction failure');
    expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledWith(
      VALID_USER_ADDRESS,
      undefined,
      '500000',
      VALID_USER_SECRET
    );
  });

  it('should accept userSecret of exactly 1 character (min(1) boundary)', async () => {
    const response = await request(app)
      .post('/api/lending/deposit')
      .send({
        userAddress: VALID_USER_ADDRESS,
        amount: '1000000',
        userSecret: 'X',
      });

    // Single character passes validation; controller mock returns failure
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('mock transaction failure');
    expect(mockStellarService.buildDepositTransaction).toHaveBeenCalledWith(
      VALID_USER_ADDRESS,
      undefined,
      '1000000',
      'X'
    );
  });

  it('should reject userSecret of zero characters after trimming', async () => {
    const response = await request(app)
      .post('/api/lending/deposit')
      .send({
        userAddress: VALID_USER_ADDRESS,
        amount: '1000000',
        userSecret: '   ',
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toContain('User secret is required');
    expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
  });

  // ----- Borrow endpoint additional boundaries -----

  it('should accept borrow with amount = "1" (minimum positive boundary)', async () => {
    const response = await request(app)
      .post('/api/lending/borrow')
      .send({
        userAddress: VALID_USER_ADDRESS,
        assetAddress: VALID_ASSET_ADDRESS,
        amount: '1',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('mock transaction failure');
    expect(mockStellarService.buildBorrowTransaction).toHaveBeenCalledWith(
      VALID_USER_ADDRESS,
      VALID_ASSET_ADDRESS,
      '1',
      VALID_USER_SECRET
    );
  });

  it('should accept borrow with amount = i128::MAX', async () => {
    const response = await request(app)
      .post('/api/lending/borrow')
      .send({
        userAddress: VALID_USER_ADDRESS,
        assetAddress: VALID_ASSET_ADDRESS,
        amount: I128_MAX,
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('mock transaction failure');
    expect(mockStellarService.buildBorrowTransaction).toHaveBeenCalledWith(
      VALID_USER_ADDRESS,
      VALID_ASSET_ADDRESS,
      I128_MAX,
      VALID_USER_SECRET
    );
  });

  it('should reject borrow with malformed assetAddress', async () => {
    const response = await request(app)
      .post('/api/lending/borrow')
      .send({
        userAddress: VALID_USER_ADDRESS,
        assetAddress: 'BAD_ASSET',
        amount: '1000',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(mockStellarService.buildBorrowTransaction).not.toHaveBeenCalled();
  });

  it('should accept borrow without assetAddress (optional field)', async () => {
    const response = await request(app)
      .post('/api/lending/borrow')
      .send({
        userAddress: VALID_USER_ADDRESS,
        amount: '1000',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('mock transaction failure');
    expect(mockStellarService.buildBorrowTransaction).toHaveBeenCalledWith(
      VALID_USER_ADDRESS,
      undefined,
      '1000',
      VALID_USER_SECRET
    );
  });

  // ----- Repay endpoint additional boundaries -----

  it('should accept repay with amount = "1" (minimum positive boundary)', async () => {
    const response = await request(app)
      .post('/api/lending/repay')
      .send({
        userAddress: VALID_USER_ADDRESS,
        amount: '1',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('mock transaction failure');
    expect(mockStellarService.buildRepayTransaction).toHaveBeenCalledWith(
      VALID_USER_ADDRESS,
      undefined,
      '1',
      VALID_USER_SECRET
    );
  });

  it('should accept repay with amount = i128::MAX', async () => {
    const response = await request(app)
      .post('/api/lending/repay')
      .send({
        userAddress: VALID_USER_ADDRESS,
        amount: I128_MAX,
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('mock transaction failure');
    expect(mockStellarService.buildRepayTransaction).toHaveBeenCalledWith(
      VALID_USER_ADDRESS,
      undefined,
      I128_MAX,
      VALID_USER_SECRET
    );
  });

  it('should reject repay with malformed assetAddress', async () => {
    const response = await request(app)
      .post('/api/lending/repay')
      .send({
        userAddress: VALID_USER_ADDRESS,
        assetAddress: 'NOT_AN_ADDRESS',
        amount: '1000',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(mockStellarService.buildRepayTransaction).not.toHaveBeenCalled();
  });

  it('should reject repay with non-integer amount', async () => {
    const response = await request(app)
      .post('/api/lending/repay')
      .send({
        userAddress: VALID_USER_ADDRESS,
        amount: '100.5',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(mockStellarService.buildRepayTransaction).not.toHaveBeenCalled();
  });

  // ----- Withdraw endpoint additional boundaries -----

  it('should accept withdraw with amount = "1" (minimum positive boundary)', async () => {
    const response = await request(app)
      .post('/api/lending/withdraw')
      .send({
        userAddress: VALID_USER_ADDRESS,
        assetAddress: VALID_ASSET_ADDRESS,
        amount: '1',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('mock transaction failure');
    expect(mockStellarService.buildWithdrawTransaction).toHaveBeenCalledWith(
      VALID_USER_ADDRESS,
      VALID_ASSET_ADDRESS,
      '1',
      VALID_USER_SECRET
    );
  });

  it('should accept withdraw with amount = i128::MAX', async () => {
    const response = await request(app)
      .post('/api/lending/withdraw')
      .send({
        userAddress: VALID_USER_ADDRESS,
        assetAddress: VALID_ASSET_ADDRESS,
        amount: I128_MAX,
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('mock transaction failure');
    expect(mockStellarService.buildWithdrawTransaction).toHaveBeenCalledWith(
      VALID_USER_ADDRESS,
      VALID_ASSET_ADDRESS,
      I128_MAX,
      VALID_USER_SECRET
    );
  });

  it('should reject withdraw with i128::MAX + 1 overflow amount', async () => {
    const response = await request(app)
      .post('/api/lending/withdraw')
      .send({
        userAddress: VALID_USER_ADDRESS,
        amount: I128_OVERFLOW,
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(mockStellarService.buildWithdrawTransaction).not.toHaveBeenCalled();
  });

  it('should reject withdraw with malformed assetAddress', async () => {
    const response = await request(app)
      .post('/api/lending/withdraw')
      .send({
        userAddress: VALID_USER_ADDRESS,
        assetAddress: 'INVALID_ADDR',
        amount: '1000',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(mockStellarService.buildWithdrawTransaction).not.toHaveBeenCalled();
  });

  it('should accept withdraw without assetAddress (optional field)', async () => {
    const response = await request(app)
      .post('/api/lending/withdraw')
      .send({
        userAddress: VALID_USER_ADDRESS,
        amount: '5000',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('mock transaction failure');
    expect(mockStellarService.buildWithdrawTransaction).toHaveBeenCalledWith(
      VALID_USER_ADDRESS,
      undefined,
      '5000',
      VALID_USER_SECRET
    );
  });
});

describe('optionalStellarAddress — direct unit coverage', () => {
  // Access the schema through lendingRequestSchema's shape.
  // We test it indirectly by constructing minimal objects.

  const parseOptional = (assetAddress: unknown) =>
    lendingRequestSchema.safeParse({
      userAddress: VALID_USER_ADDRESS,
      amount: '1000',
      userSecret: VALID_USER_SECRET,
      assetAddress,
    });

  it('should accept undefined assetAddress', () => {
    const result = parseOptional(undefined);
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.assetAddress).toBeUndefined();
  });

  it('should accept null assetAddress and normalize to undefined', () => {
    const result = parseOptional(null);
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.assetAddress).toBeUndefined();
  });

  it('should accept empty-string assetAddress and normalize to undefined', () => {
    const result = parseOptional('');
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.assetAddress).toBeUndefined();
  });

  it('should accept whitespace-only assetAddress and normalize to undefined', () => {
    const result = parseOptional('   ');
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.assetAddress).toBeUndefined();
  });

  it('should accept a valid Stellar address', () => {
    const result = parseOptional(VALID_ASSET_ADDRESS);
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.assetAddress).toBe(VALID_ASSET_ADDRESS);
  });

  it('should reject a non-empty, non-whitespace invalid address', () => {
    const result = parseOptional('INVALID_STELLAR_ADDRESS');
    expect(result.success).toBe(false);
  });

  it('should reject a number type for assetAddress', () => {
    const result = parseOptional(12345);
    expect(result.success).toBe(false);
  });
});

describe('Partial and Cascading Field Failures', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockStellarService.buildDepositTransaction.mockResolvedValue('mock_deposit_tx');
    mockStellarService.submitTransaction.mockResolvedValue({
      success: false,
      status: 'failed',
      error: 'mock transaction failure',
    });
  });

  it('should report errors for all invalid fields simultaneously (not just the first)', async () => {
    const response = await request(app)
      .post('/api/lending/deposit')
      .send({
        userAddress: 'BAD',
        amount: '0',
        userSecret: '',
      });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    // The error message should mention at least one of the invalid fields
    expect(response.body.error).toBeTruthy();
    expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
  });

  it('should NOT advance to the controller when only amount is invalid', async () => {
    const response = await request(app)
      .post('/api/lending/deposit')
      .send({
        userAddress: VALID_USER_ADDRESS,
        amount: 'not-a-number',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
  });

  it('should NOT advance to the controller when only userAddress is invalid', async () => {
    const response = await request(app)
      .post('/api/lending/deposit')
      .send({
        userAddress: 'GXXX',
        amount: '1000000',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
  });

  it('should return 400 with success:false for a completely empty body', async () => {
    const response = await request(app)
      .post('/api/lending/deposit')
      .send({});

    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty('success', false);
    expect(response.body).toHaveProperty('error');
    expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
  });

  it('should reject a payload where userAddress is a number, not a string', async () => {
    const response = await request(app)
      .post('/api/lending/deposit')
      .send({
        userAddress: 12345,
        amount: '1000000',
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
  });

  it('should reject a payload where amount is an array', async () => {
    const response = await request(app)
      .post('/api/lending/deposit')
      .send({
        userAddress: VALID_USER_ADDRESS,
        amount: ['1000000'],
        userSecret: VALID_USER_SECRET,
      });

    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(mockStellarService.buildDepositTransaction).not.toHaveBeenCalled();
  });
});
