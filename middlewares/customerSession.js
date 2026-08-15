import jwt from "jsonwebtoken";
import { verifyCustomerSession } from "../utils/generateToken.js";
import { ClientError } from "../utils/errorHandler.js";

const HEADER = "x-customer-session";

const readToken = (req) => {
  const header = req.headers[HEADER];
  if (typeof header === "string" && header.trim()) return header.trim();

  // Allow the token in the body too, for the QR client's initial POST where
  // setting a custom header is awkward.
  if (typeof req.body?.customerSession === "string") {
    return req.body.customerSession.trim();
  }
  return null;
};

/**
 * Requires a valid per-table customer session.
 *
 * Attaches `req.customerSession = { sessionId, tableId, hotelId, customerId }`.
 *
 * When the route has a `:tableId` parameter, the session must match it — this
 * is what stops a diner at table 4 from ordering on, or reading, table 9.
 */
export const requireCustomerSession = (req, res, next) => {
  const token = readToken(req);

  if (!token) {
    return next(
      new ClientError(
        "Scan the QR code at your table to start ordering.",
        401,
        "NO_CUSTOMER_SESSION"
      )
    );
  }

  let payload;
  try {
    payload = verifyCustomerSession(token);
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return next(
        new ClientError(
          "Your table session has expired. Please scan the QR code again.",
          401,
          "CUSTOMER_SESSION_EXPIRED"
        )
      );
    }
    return next(
      new ClientError(
        "That table session is not valid.",
        401,
        "INVALID_CUSTOMER_SESSION"
      )
    );
  }

  const routeTableId = req.params?.tableId;
  if (routeTableId && routeTableId !== payload.tableId) {
    return next(
      new ClientError(
        "This session belongs to a different table.",
        403,
        "TABLE_SESSION_MISMATCH"
      )
    );
  }

  req.customerSession = payload;
  next();
};

/**
 * Attaches the session when present but does not require it — for endpoints
 * that serve both signed-in staff and anonymous diners.
 */
export const optionalCustomerSession = (req, res, next) => {
  const token = readToken(req);
  if (!token) return next();
  try {
    req.customerSession = verifyCustomerSession(token);
  } catch {
    // An invalid optional session is simply absent.
  }
  next();
};

export default requireCustomerSession;
