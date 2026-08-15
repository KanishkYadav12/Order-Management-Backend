import { ValidationError } from "../utils/errorHandler.js";

/**
 * Request validation.
 *
 * `joi` was a dependency and `utils/validator.js` held a single schema
 * followed by the comment "should we use it ?" — nothing imported it, and no
 * endpoint validated its input. This replaces that with Zod schemas applied
 * per route.
 *
 * Validated values are written back onto the request, so handlers receive
 * coerced and stripped data: unknown keys are removed, which also closes mass
 * assignment (a client sending `{ isApproved: true }` to a profile update
 * cannot reach the model).
 *
 * @param {{body?: import('zod').ZodType, query?: import('zod').ZodType, params?: import('zod').ZodType}} schemas
 */
export const validate = (schemas) => (req, res, next) => {
  const issues = [];

  for (const source of ["params", "query", "body"]) {
    const schema = schemas[source];
    if (!schema) continue;

    const result = schema.safeParse(req[source]);

    if (!result.success) {
      for (const issue of result.error.issues) {
        issues.push({
          field: [source, ...issue.path].join("."),
          path: issue.path.join(".") || source,
          message: issue.message,
          code: issue.code,
        });
      }
      continue;
    }

    // `req.query` and `req.params` are getter-backed on some Express versions,
    // so assign properties rather than replacing the object.
    if (source === "body") {
      req.body = result.data;
    } else {
      Object.keys(req[source]).forEach((key) => delete req[source][key]);
      Object.assign(req[source], result.data);
    }
  }

  if (issues.length > 0) {
    return next(
      new ValidationError(
        issues.length === 1
          ? issues[0].message
          : `${issues.length} fields need attention.`,
        issues
      )
    );
  }

  next();
};

export default validate;
