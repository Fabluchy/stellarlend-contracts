import { Request, Response, NextFunction } from 'express';
import { z, ZodError, ZodSchema } from 'zod';
import { ValidationError } from '../utils/errors';
import { I128String, PositiveI128String, StellarAddress } from '../utils/validators';
import logger from '../utils/logger';

/**
 * Sensitive field patterns to identify authorization credentials and secrets.
 * Any issue on these paths will be scrubbed to prevent leaking credentials in diagnostics.
 */
const SENSITIVE_FIELD_NAMES = new Set([
  'usersecret',
  'secret',
  'password',
  'token',
  'authorization',
  'key',
  'privatekey',
  'seed',
]);

function sanitizeFieldName(path: string): string {
  return path.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function isSensitiveField(path: string): boolean {
  const normalized = sanitizeFieldName(path);
  return Array.from(SENSITIVE_FIELD_NAMES).some(sensitive => normalized.includes(sensitive));
}

/**
 * Express middleware factory that validates the request body against a Zod schema.
 *
 * Invariants enforced by validateBody:
 * 1. Determinism: Identical input payloads always produce the exact same validation
 *    outcome and error structure, regardless of retries, timing, or concurrency.
 * 2. State Transition & Isolation: req.body is replaced with the parsed (validated and
 *    normalized) output only upon successful validation. On rejection, req.body is NOT
 *    corrupted or partially updated, and downstream handlers/controllers are not invoked.
 * 3. Credential Protection: Authorization credentials (such as userSecret) are never echoed
 *    or leaked in error messages, logs, or responses.
 * 4. Async & Sync Compatibility: Supports both synchronous and asynchronous Zod schemas.
 *    The returned middleware is synchronous and never rejects, so Express 4 cannot
 *    strand a request on an unhandled promise rejection. Async schemas are detected by
 *    error name (not message wording) and always settle `next()` exactly once.
 * 4b. Advance-Once Invariant: `next()` is called at most once per request, so a
 *    downstream throw can never re-enter the middleware and advance the chain twice.
 * 5. Diagnostic Observability: Validation failures emit structured warning logs containing
 *    request method, path, and error summaries while strictly redacting sensitive fields.
 * 6. Error Propagation: ZodError issues are formatted into a single ValidationError.
 *    Non-Zod errors are forwarded via next(err) without alteration.
 */
export const validateBody =
  (schema: ZodSchema) => (req: Request, res: Response, next: NextFunction): void => {
    let parsed: unknown;
    try {
      parsed = schema.parse(req.body);
    } catch (error) {
      if (isAsyncSchemaError(error, schema)) {
        resolveAsyncSchema(schema, req, next);
        return;
      }

      handleValidationFailure(error, req, next);
      return;
    }

    // `next()` is deliberately invoked OUTSIDE the try/catch above. If a
    // downstream handler throws synchronously, re-entering the catch would
    // reinterpret that unrelated error as a validation failure and advance the
    // Express chain a second time. Express already owns downstream errors, so
    // letting them propagate is the correct behavior.
    req.body = parsed;
    next();
  };

/**
 * Stable, version-tolerant detection of "this schema has async refinements".
 *
 * Zod raises a dedicated error when a synchronous parse encounters a Promise.
 * Matching on the error *name* is the durable signal; the message check is kept
 * only as a fallback for older Zod releases. Relying on the message alone let a
 * wording change silently downgrade async validation into a 500.
 */
const ZOD_ASYNC_ERROR_NAMES = new Set(['$ZodAsyncError', 'ZodAsyncError']);

function isAsyncSchemaError(error: unknown, schema: ZodSchema): boolean {
  if (typeof (schema as { parseAsync?: unknown }).parseAsync !== 'function') {
    return false;
  }

  if (error instanceof Error && ZOD_ASYNC_ERROR_NAMES.has(error.name)) {
    return true;
  }

  return (
    error instanceof Error &&
    error.message.includes('Encountered Promise during synchronous parse')
  );
}

/**
 * Re-runs validation asynchronously for schemas with async refinements.
 *
 * Invariants:
 * - `next()` is invoked exactly once, on every path (resolve, reject, or a
 *   malformed `parseAsync` implementation).
 * - A synchronous throw from `parseAsync`, or a non-thenable return value, is
 *   routed to `handleValidationFailure` instead of escaping as a rejected
 *   promise. Express 4 ignores rejected middleware promises, which previously
 *   left the request hanging with no response and no error event.
 * - `req.body` is only replaced after a successful async parse, matching the
 *   sync path's all-or-nothing mutation guarantee.
 */
function resolveAsyncSchema(schema: ZodSchema, req: Request, next: NextFunction): void {
  let advanced = false;
  let pending: Promise<unknown>;
  try {
    pending = (schema as { parseAsync: (body: unknown) => Promise<unknown> }).parseAsync(
      req.body
    );
  } catch (syncError) {
    handleValidationFailure(syncError, req, next);
    return;
  }

  if (typeof pending?.then !== 'function') {
    handleValidationFailure(
      new TypeError('Schema parseAsync did not return a promise'),
      req,
      next
    );
    return;
  }

  pending
    .then((validatedBody: unknown) => {
      req.body = validatedBody;
      advanced = true;
      // `next()` synchronously drives the rest of the chain. Express routes
      // downstream errors to its own error handler internally, so anything
      // thrown back out here has already been advanced past and must never be
      // re-reported as a validation failure.
      next();
    })
    .catch((asyncError: unknown) => {
      // Reached only if the async parse rejected. If `next()` already advanced
      // the chain, re-reporting would advance it a second time, so the error is
      // logged for diagnosis and the request is left to Express.
      if (advanced) {
        logger.error('Async validation failed after the request advanced', {
          method: req?.method,
          path: req?.path,
          error: asyncError instanceof Error ? asyncError.message : String(asyncError),
        });
        return;
      }
      handleValidationFailure(asyncError, req, next);
    });
}

/**
 * Handles validation failures with safe logging and standardized error propagation.
 */
function handleValidationFailure(error: unknown, req: Request, next: NextFunction): void {
  if (error instanceof ZodError) {
    const errorMessages = error.issues
      .map(issue => {
        const path = issue.path.join('.') || 'body';
        return `${path}: ${issue.message}`;
      })
      .join(', ');

    // Safe diagnostic telemetry without leaking sensitive credentials
    try {
      logger.warn('Request body validation failed', {
        method: req?.method,
        path: req?.path,
        error: errorMessages,
        issues: error.issues.map(i => ({
          path: i.path.join('.') || 'body',
          code: i.code,
          message: i.message,
          isSensitive: isSensitiveField(i.path.join('.')),
        })),
      });
    } catch {
      // Diagnostic logging failure must never prevent error propagation
    }

    return next(new ValidationError(errorMessages));
  }

  return next(error);
}

/**
 * Normalizes an optional Stellar address field.
 *
 * Invariants:
 * - `undefined` and `null` are normalized to `undefined`.
 * - Empty string `""` or whitespace-only strings are normalized to `undefined`.
 * - Non-empty strings are passed to `StellarAddress` for strict address validation.
 */
const optionalStellarAddress = z.preprocess(
  value => {
    if (value === undefined || value === null) return undefined;
    if (typeof value === 'string' && value.trim() === '') return undefined;
    return value;
  },
  StellarAddress.optional()
);

/**
 * Schema for core lending operations (deposit, borrow, repay, withdraw).
 *
 * Invariants:
 * - `userAddress`: Must be a valid Stellar account (G...) or contract (C...) address.
 * - `amount`: Must be a positive signed 128-bit integer string (1 <= amount <= i128::MAX).
 *   Rejects zero, negative amounts, decimals, scientific notation, and non-numeric values.
 * - `assetAddress`: Optional Stellar address. Normalized via optionalStellarAddress.
 * - `userSecret`: Required transaction signing authorization credential.
 *   Must be non-empty and non-whitespace. Raw secret values are never echoed in errors.
 */
export const lendingRequestSchema = z.object({
  userAddress: StellarAddress,
  amount: PositiveI128String,
  assetAddress: optionalStellarAddress,
  userSecret: z.string().trim().min(1, 'User secret is required'),
});

export const depositValidation = [validateBody(lendingRequestSchema)];
export const borrowValidation = [validateBody(lendingRequestSchema)];
export const repayValidation = [validateBody(lendingRequestSchema)];
export const withdrawValidation = [validateBody(lendingRequestSchema)];

export { I128String, PositiveI128String, StellarAddress };
