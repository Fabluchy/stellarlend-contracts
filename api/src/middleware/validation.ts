import { Request, Response, NextFunction } from 'express';
import { z, ZodError, ZodSchema } from 'zod';
import { ValidationError } from '../utils/errors';
import { I128String, PositiveI128String, StellarAddress } from '../utils/validators';
import logger from '../utils/logger';

/**
 * Body validation middleware.
 *
 * Invariants enforced by validateBody:
 * 1. Determinism: Identical input payloads always produce the exact same validation
 *    outcome and error structure, regardless of retries, timing, or concurrency.
 * 2. State Transition & Isolation: req.body is replaced with the parsed (validated and
 *    normalized) output only upon successful validation. On rejection, req.body is NOT
 *    corrupted or partially updated, and downstream handlers/controllers are not invoked.
 * 3. Credential Protection: Authorization credentials (such as userSecret) are never echoed
 *    or leaked in error messages, logs, or responses.
 * 4. Async & Sync Compatibility: Supports both synchronous and asynchronous Zod schemas,
 *    handling promises cleanly without unhandled rejections or race conditions.
 * 5. Diagnostic Observability: Validation failures emit structured warning logs containing
 *    request method, path, and error summaries while strictly redacting sensitive fields.
 * 6. Error Propagation: ZodError issues are formatted into a single ValidationError.
 *    Non-Zod errors are forwarded via next(err) without alteration.
 * 7. Termination: `next` is invoked exactly once for every invocation of the middleware,
 *    on every path — success, synchronous rejection, asynchronous rejection, and when the
 *    schema adapter itself misbehaves. This guarantee is what stops a request from hanging
 *    (invariant 8 below); a middleware that never calls `next` leaves the socket open.
 * 8. No Escaping Failures: Every failure is funnelled through `next`, so nothing is
 *    discarded as an unhandled rejection. Express 4 ignores the promise returned by an
 *    async middleware, so a throw on that promise is silently lost.
 */
export const validateBody =
  (schema: ZodSchema) => async (req: Request, res: Response, next: NextFunction) => {
    let parsed: unknown;
    try {
      parsed = schema.parse(req.body);
 * Invariants:
 *  - The request body is replaced with the parsed, normalized value only after a successful parse.
 *  - On failure the body is left untouched and a deterministic ValidationError is forwarded
 *    to the error handler via `next(`.
 *  - Non-Zod errors are propagated unchanged so they are not mislabeled as validation failures.
 *  - Error messages include the field path but never echo the received value, so secrets are not leaked.
 */
export const validateBody =
  (schema: ZodSchema) => (req: Request, _res: Response, next: NextFunction) => {
    try {
      const parsed = schema.parse(req.body);
      // Only mutate the body after a successful parse to avoid leaving partially
      // normalized state on failure.
      req.body = parsed;
      return next();
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.includes('Encountered Promise during synchronous parse') &&
        typeof (schema as any).parseAsync === 'function'
      ) {
        await handleAsyncParse(schema, req, next);
        return;
      }

      handleValidationFailure(error, req, next);
      return;
    }

    // Deliberately outside the try/catch. If a downstream handler throws, Express must
    // receive that error directly; catching it here would report a downstream failure
    // as a validation failure and invoke `next` a second time.
    req.body = parsed;
    next();
  };

/**
 * Runs an asynchronous schema and routes its outcome to `next` exactly once.
 *
 * Failure modes this guards against, all of which previously escaped the middleware
 * and left the request hanging forever:
 * - `parseAsync` throws synchronously instead of returning a rejected promise.
 * - `parseAsync` returns a non-thenable value, so `.then(...)` itself throws.
 * - `parseAsync` rejects with a non-ZodError (forwarded verbatim, not masked).
 *
 * A downstream handler that itself throws is *not* treated as a validation failure:
 * `next` is invoked outside the promise chain's rejection path, so Express remains the
 * single owner of post-validation error handling.
 */
async function handleAsyncParse(
  schema: ZodSchema,
  req: Request,
  next: NextFunction,
): Promise<void> {
  let pending: unknown;
  try {
    pending = (schema as any).parseAsync(req.body);
  } catch (syncError) {
    handleValidationFailure(syncError, req, next);
    return;
  }

  // A schema adapter that returns a non-thenable would make the original `.then(...)`
  // throw a TypeError outside the rejection path, leaving the request hanging.
  if (typeof (pending as any)?.then !== 'function') {
    handleValidationFailure(
      new Error('Schema parseAsync did not return a promise'),
      req,
      next,
    );
    return;
  }

  try {
    const validatedBody = await (pending as Promise<unknown>);
    req.body = validatedBody;
  } catch (asyncError) {
    handleValidationFailure(asyncError, req, next);
    return;
  }

  // Deliberately outside the try/catch: if a downstream handler throws, Express must
  // receive that error directly rather than it being re-reported as a validation failure.
  next();
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
export const optionalStellarAddress = z.preprocess(
  value => (value === '' ? undefined : value),
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
